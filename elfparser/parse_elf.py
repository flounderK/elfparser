#!/usr/bin/env python3

from . import elfstructs
from . import elfenums
from . import elfmacros
from . import constexpr
from ctypes import c_ubyte, sizeof, addressof, cast, POINTER, create_string_buffer, string_at
from types import SimpleNamespace
from collections import defaultdict, namedtuple
import _ctypes
import _io
import io


def pull_stringtable(elf_array, shdr):
    return [i.decode() for i in bytes(elf_array[shdr.sh_offset:shdr.sh_offset+shdr.sh_size]).split(b'\x00') if i != b'']


def string_at_offset(stringtable, offset=0, cast_to_str=True):
    address = None
    if isinstance(stringtable, int):
        # stringtable is the address of the stringtable
        address = stringtable
    elif issubclass(stringtable.__class__, _ctypes.Array):
        address = addressof(stringtable)
    else:
        raise Exception("Unsupported")

    s = string_at(address+offset)

    if cast_to_str is True:
        s = s.decode()

    return s


class ElfParser:
    def __init__(self, file, lazy_load=True):
        if isinstance(file, (io.TextIOWrapper)) or issubclass(file.__class__, (_io._TextIOBase)):
            self.file = file.name
            self._fd = file
            self.__original_offset = self._fd.tell()
        elif isinstance(file, str):
            self.file = file
            self._fd = open(file, "rb")
            self.__original_offset = 0
        else:
            raise NotImplementedError("file must be a filepath or ")
        self.sections = []
        self.segments = []
        self.symbols = {}
        self.dyn_symbols = {}
        self.symbol_entries = []
        self.dynamic_entries = []
        self.relocation_entries = []
        self.program_headers = []
        self.needed_libraries = []
        self.dynamic_flags = 0
        self.relocation_enum = None
        self.address = 0
        self.got = None
        self.got_plt = None
        self._load_entries = []

        # alternate strategy for casting from bytes
        # ehdr = ((Elf32_Ehdr*1).from_buffer(bytearray(f.read(sizeof(Elf32_Ehdr)))))[0]

        self._lazy_load = lazy_load
        if self._lazy_load is False:
            e = self._fd.read()
            self.__elf_array = (c_ubyte*len(e)).from_buffer(bytearray(e))
        else:
            self.__elf_array = None

        self._parse_ident()
        self._apply_elf_structures()
        self._constexpr = constexpr.ELF32_CONSTEXPR if self.bits == 32 else constexpr.ELF64_CONSTEXPR
        self._parse_ehdr()
        self.relocation_enum = self._get_relocation_enum_for_machine()
        self._parse_shdrs()
        self._parse_symbol_entries()
        self._parse_phdrs()
        self._parse_dyn_entries()
        self._parse_rela_entries()

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        for k in self.symbols.keys():
            self.symbols[k] = self.symbols[k] - self._address + value

        self._address = value

    def _get_c_array_at_offset(self, offset, size, reset_pos=True):
        memory_class = (c_ubyte*size)
        if self._lazy_load is True:
            orig_pos = self._fd.tell()
            self._fd.seek(self.__original_offset + offset)
            buffer = memory_class.from_buffer(bytearray(self._fd.read(size)))
            if reset_pos is True:
                self._fd.seek(orig_pos)
        else:
            buffer = memory_class.from_buffer(self.__elf_array, offset)

        return buffer

    def _parse_ident(self):
        ident_buf = self._get_c_array_at_offset(self.__original_offset, sizeof(elfstructs.Elf_Ident))
        # ident_buf_class = c_ubyte*sizeof(elfstructs.Elf_Ident)
        # ident_buf = ident_buf_class.from_buffer(bytearray(self._fd.read(sizeof(elfstructs.Elf_Ident))))
        ident = cast(ident_buf, POINTER(elfstructs.Elf_Ident)).contents
        # confirm elf magic
        if bytes(ident.ei_elfmag) != elfmacros.ELFMAG:
            raise Exception("Elf magic not present")

        self.elfclass = elfenums.ELFCLASS(ident.ei_class)
        if self.elfclass == elfenums.ELFCLASS.ELFCLASS32:
            self.bits = 32
        elif self.elfclass == elfenums.ELFCLASS.ELFCLASS64:
            self.bits = 64
        else:
            raise Exception("Invalid ELFCLASS")
        self._endianness_flag = elfenums.ELFDATA(ident.ei_data)
        if self._endianness_flag == elfenums.ELFDATA.ELFDATA2LSB:
            self.endianness = "little"
        elif self._endianness_flag == elfenums.ELFDATA.ELFDATA2MSB:
            self.endianness = "big"
        else:
            raise Exception("Invalid ELFDATA")
        self.osabi = elfenums.ELFOSABI(ident.ei_osabi)

    def _apply_elf_structures(self):
        # get appropriate elf structures for the bitness and endianness found
        elf_structures = elfstructs.get_elf_structures(self.bits, self.endianness)
        prefix = "_"
        for k, v in elf_structures.items():
            # store the basic elf structure classes
            setattr(self, prefix + k, v)
            # create buffers/backings for every basic elf class
            memory_class = c_ubyte*sizeof(v)
            setattr(self, prefix + k + '_memory_class', memory_class)

    def _parse_ehdr(self):
        """Parse ElfXX_Ehdr"""
        ehdr_buf = self._get_c_array_at_offset(self.__original_offset, sizeof(self._ElfW_Ehdr_memory_class))
        ehdr = self._ehdr = cast(ehdr_buf, POINTER(self._ElfW_Ehdr)).contents
        self.e_type = elfenums.ET(ehdr.e_type)
        self.e_machine = elfenums.EM(ehdr.e_machine)

        # setup section header array
        shdr_array_memory_class = self._ElfW_Shdr*ehdr.e_shnum
        # get backing of the whole section header array
        shdr_array_buffer = self._get_c_array_at_offset(ehdr.e_shoff, ehdr.e_shentsize*ehdr.e_shnum)
        self._shdr_array = cast(shdr_array_buffer, POINTER(shdr_array_memory_class)).contents

        # string table for section header names
        shstrshdr = self._shdr_array[ehdr.e_shstrndx]
        self._shstrtab = self._get_c_array_at_offset(shstrshdr.sh_offset, shstrshdr.sh_size)

        # setup progam header array / segment array
        phdr_array_memory_class = self._ElfW_Phdr*ehdr.e_phnum
        phdr_array_buffer = self._get_c_array_at_offset(ehdr.e_phoff, ehdr.e_phentsize*ehdr.e_phnum)
        self._phdr_array = cast(phdr_array_buffer, POINTER(phdr_array_memory_class)).contents

    def _parse_shdrs(self):
        # maybe check for  weird occurrances here, like having 7 string tables
        # TODO: make a subclass of namedtuple that only prints certain fields in the repr
        section_tuple = namedtuple('Section', ['name', 'type'] + list(dict(self._ElfW_Shdr._fields_).keys()))
        for shdr in self._shdr_array:
            section_type = elfenums.SHT(shdr.sh_type)
            section_name = string_at_offset(self._shstrtab, shdr.sh_name)
            if section_type == elfenums.SHT.SHT_STRTAB and section_name == '.strtab':
                self._string_table = self._get_c_array_at_offset(shdr.sh_offset,
                                                                  shdr.sh_size)
            elif section_type == elfenums.SHT.SHT_STRTAB and section_name == '.dynstr':
                self._dynamic_string_table = self._get_c_array_at_offset(shdr.sh_offset,
                                                                          shdr.sh_size)
            elif section_type == elfenums.SHT.SHT_DYNSYM and section_name == '.dynsym':
                dyn_sym_array_memory_class = self._ElfW_Sym * (shdr.sh_size // sizeof(self._ElfW_Sym))
                dyn_sym_array_buffer = self._get_c_array_at_offset(shdr.sh_offset,
                                                                    shdr.sh_size)

                self._dyn_sym_array = cast(dyn_sym_array_buffer, POINTER(dyn_sym_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_SYMTAB and section_name == '.symtab':
                sym_array_memory_class = self._ElfW_Sym * (shdr.sh_size // sizeof(self._ElfW_Sym))
                sym_array_buffer = self._get_c_array_at_offset(shdr.sh_offset,
                                                                shdr.sh_size)
                self._sym_array = cast(sym_array_buffer, POINTER(sym_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_DYNAMIC and section_name == '.dynamic':
                dyn_array_memory_class = self._ElfW_Dyn * (shdr.sh_size // sizeof(self._ElfW_Dyn))
                dyn_array_buffer = self._get_c_array_at_offset(shdr.sh_offset,
                                                                shdr.sh_size)
                self._dyn_array = cast(dyn_array_buffer, POINTER(dyn_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_RELA:
                rela_array_memory_class = self._ElfW_Rela * (shdr.sh_size // sizeof(self._ElfW_Rela))
                rela_array_buffer = self._get_c_array_at_offset(shdr.sh_offset,
                                                                 shdr.sh_size)
                self._rela_array = cast(rela_array_buffer, POINTER(rela_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_REL:
                rel_array_memory_class = self._ElfW_Rel * (shdr.sh_size // sizeof(self._ElfW_Rel))
                rel_array_buffer = self._get_c_array_at_offset(shdr.sh_offset,
                                                                shdr.sh_size)
                self._rel_array = cast(rel_array_buffer, POINTER(rel_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_PROGBITS and section_name == '.got':
                self.got = self._get_c_array_at_offset(shdr.sh_offset,
                                                        shdr.sh_size)
            elif section_type == elfenums.SHT.SHT_PROGBITS and section_name == '.got.plt':
                self.got_plt = self._get_c_array_at_offset(shdr.sh_offset,
                                                        shdr.sh_size)

            section_dict = dict(shdr)
            section_dict['name'] = section_name
            section_dict['type'] = section_type

            # self.sections.append(elfstructs.Shdr(**section_dict))
            self.sections.append(section_tuple(**section_dict))

    def _parse_symbol_entries(self):
        extra_fields = ['name', 'type', 'binding', 'visibility']
        sym_tuple = namedtuple('Symbol', extra_fields + list(dict(self._ElfW_Sym._fields_).keys()))
        for sym in self._sym_array:
            symbol_name = string_at_offset(self._string_table, sym.st_name)
            info_raw = sym.st_info
            # decode sym type and binding
            symbol_type = elfenums.STT(constexpr.ELF64_ST_TYPE(info_raw))
            symbol_binding = elfenums.STB(constexpr.ELF64_ST_BIND(info_raw))
            symbol_visibility = elfenums.STV(sym.st_other)
            if sym.st_value != 0:
                self.symbols[symbol_name] = sym.st_value

            symbol_entry_dict = dict(sym)
            symbol_entry_dict['name'] = symbol_name
            symbol_entry_dict['type'] = symbol_type
            symbol_entry_dict['binding'] = symbol_binding
            symbol_entry_dict['visibility'] = symbol_visibility
            # self.symbol_entries.append(elfstructs.Sym(**symbol_entry_dict))
            self.symbol_entries.append(sym_tuple(**symbol_entry_dict))

        # not sure if these ever actually have values set, might need to re evaluate
        for sym in self._dyn_sym_array:
            symbol_name = string_at_offset(self._dynamic_string_table, sym.st_name)
            info_raw = sym.st_info
            # decode sym type and binding
            symbol_type = elfenums.STT(constexpr.ELF64_ST_TYPE(info_raw))
            symbol_binding = elfenums.STB(constexpr.ELF64_ST_BIND(info_raw))
            symbol_visibility = elfenums.STV(sym.st_other)
            # if sym.st_value != 0:
            self.dyn_symbols[symbol_name] = sym.st_value

            symbol_entry_dict = dict(sym)
            symbol_entry_dict['name'] = symbol_name
            symbol_entry_dict['type'] = symbol_type
            symbol_entry_dict['binding'] = symbol_binding
            symbol_entry_dict['visibility'] = symbol_visibility
            self.symbol_entries.append(elfstructs.Sym(**symbol_entry_dict))

    def _parse_phdrs(self):
        extra_fields = ['type', 'flags']
        phdr_tuple = namedtuple('Phdr', extra_fields + list(dict(self._ElfW_Phdr._fields_).keys()))
        for phdr in self._phdr_array:
            phdr_type = elfenums.PT(phdr.p_type)
            phdr_flags = elfenums.PF(phdr.p_flags)
            phdr_dict = dict(phdr)
            phdr_dict['type'] = phdr_type
            phdr_dict['flags'] = phdr_flags
            # self.program_headers.append(elfstructs.Phdr(**phdr_dict))
            self.program_headers.append(phdr_tuple(**phdr_dict))
            if phdr.p_type == elfenums.PT.PT_LOAD:
                self._load_entries.append(phdr)

    def _parse_dyn_entries(self):
        extra_fields = ['type']
        dyn_tuple = namedtuple('Dyn', extra_fields + list(dict(self._ElfW_Dyn._fields_).keys()))
        for d in self._dyn_array:
            tag_type = elfenums.DT(d.d_tag)
            if tag_type == elfenums.DT.DT_NEEDED:
                self.needed_libraries.append(string_at_offset(self._dynamic_string_table, d.d_un.d_ptr))
            elif tag_type == elfenums.DT.DT_FLAGS_1:
                self.dynamic_flags |= elfenums.DF_1(d.d_un.d_val)

            dyn_dict = dict(d)
            dyn_dict['type'] = tag_type
            # self.dynamic_entries.append(elfstructs.Dyn(**dyn_dict))
            self.dynamic_entries.append(dyn_tuple(**dyn_dict))

    def offset_to_vaddr(self, offset):
        for phdr in self._load_entries:
            if (phdr.p_offset <= offset) and (offset <= phdr.p_offset + phdr.p_filesz):
                return (offset - phdr.p_offset) + phdr.p_vaddr

    def vaddr_to_offset(self, addr):
        for phdr in self._load_entries:
            if (phdr.p_vaddr <= addr) and (addr <= (phdr.p_vaddr + phdr.p_memsz)):
                return (addr - phdr.p_vaddr) + phdr.p_offset


    def _get_relocation_enum_for_machine(self):
        """There are lots of different relocation architectures supported,
        but even more machine types. """
        for k, v in elfenums.MACHINE_TYPE_TO_RELOCATION_TYPE_MAPPING.items():
            if self.e_machine in k:
                return v

    def _parse_rela_entries(self):
        extra_fields = ['name', 'type']
        rela_tuple = namedtuple('Rela', extra_fields + list(dict(self._ElfW_Rela._fields_).keys()) + ['r_sym'])
        for rela in self._rela_array:
            rela_info = rela.r_info
            rela_sym = self._constexpr['ELFW_R_SYM'](rela_info)
            rela_type = self.relocation_enum(self._constexpr['ELFW_R_TYPE'](rela_info))
            name = string_at_offset(self._dynamic_string_table, self._dyn_sym_array[rela_sym].st_name)
            rela_dict = dict(rela)
            rela_dict['name'] = name
            rela_dict['type'] = rela_type
            rela_dict['r_sym'] = rela_sym
            # self.relocation_entries.append(elfstructs.Rela(**rela_dict))
            self.relocation_entries.append(rela_tuple(**rela_dict))

