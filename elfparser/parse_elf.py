#!/usr/bin/env python3

from . import instantiate_ctype_with_backing, set_backing_value, set_backing_value_from_elf_offset
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
        self.symbol_entries = []
        self.dynamic_entries = []
        self.relocation_entries = []

        self._lazy_load = lazy_load
        if self._lazy_load is False:
            e = self._fd.read()
            self.__elf_array = (c_ubyte*len(e)).from_buffer(bytearray(e))
        else:
            self.__elf_array = None

        self._parse_ident()
        self._apply_elf_structures()
        self._parse_ehdr()
        self._parse_shdrs()
        self._parse_symbol_entries()

    def __get_c_array_at_offset(self, offset, size, reset_pos=True):
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
        ident_buf = self.__get_c_array_at_offset(self.__original_offset, sizeof(elfstructs.Elf_Ident))
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
        ehdr_buf = self.__get_c_array_at_offset(self.__original_offset, sizeof(self._ElfW_Ehdr_memory_class))
        ehdr = self._ehdr = cast(ehdr_buf, POINTER(self._ElfW_Ehdr)).contents
        self.e_type = elfenums.ET(ehdr.e_type)
        self.e_machine = elfenums.EM(ehdr.e_machine)

        # setup section header array
        shdr_array_memory_class = self._ElfW_Shdr*ehdr.e_shnum
        # get backing of the whole section header array
        shdr_array_buffer = self.__get_c_array_at_offset(ehdr.e_shoff, ehdr.e_shentsize*ehdr.e_shnum)
        self._shdr_array = cast(shdr_array_buffer, POINTER(shdr_array_memory_class)).contents

        # string table for section header names
        shstrshdr = self._shdr_array[ehdr.e_shstrndx]
        self._shstrtab = self.__get_c_array_at_offset(shstrshdr.sh_offset, shstrshdr.sh_size)

        # setup progam header array / segment array
        phdr_array_memory_class = self._ElfW_Phdr*ehdr.e_phnum
        phdr_array_buffer = self.__get_c_array_at_offset(ehdr.e_phoff, ehdr.e_phentsize*ehdr.e_phnum)
        self._phdr_array = cast(phdr_array_buffer, POINTER(phdr_array_memory_class)).contents

    def _parse_shdrs(self):
        # maybe check for  weird occurrances here, like having 7 string tables
        # TODO: make a subclass of namedtuple that only prints certain fields in the repr
        section_tuple = namedtuple('Section', ['name', 'type'] + list(dict(self._ElfW_Shdr._fields_).keys()))
        for shdr in self._shdr_array:
            section_type = elfenums.SHT(shdr.sh_type)
            section_name = string_at_offset(self._shstrtab, shdr.sh_name)
            if section_type == elfenums.SHT.SHT_STRTAB and section_name == '.strtab':
                self._string_table = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                  shdr.sh_size)
            elif section_type == elfenums.SHT.SHT_STRTAB and section_name == '.dynstr':
                self._dynamic_string_table = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                          shdr.sh_size)
            elif section_type == elfenums.SHT.SHT_DYNSYM and section_name == '.dynsym':
                dyn_sym_array_memory_class = self._ElfW_Sym * (shdr.sh_size // sizeof(self._ElfW_Sym))
                dyn_sym_array_buffer = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                    shdr.sh_size)

                self._dyn_sym_array = cast(dyn_sym_array_buffer, POINTER(dyn_sym_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_SYMTAB and section_name == '.symtab':
                sym_array_memory_class = self._ElfW_Sym * (shdr.sh_size // sizeof(self._ElfW_Sym))
                sym_array_buffer = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                shdr.sh_size)
                self._sym_array = cast(sym_array_buffer, POINTER(sym_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_DYNAMIC and section_name == '.dynamic':
                dyn_array_memory_class = self._ElfW_Dyn * (shdr.sh_size // sizeof(self._ElfW_Dyn))
                dyn_array_buffer = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                shdr.sh_size)
                self._dyn_array = cast(dyn_array_buffer, POINTER(dyn_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_RELA:
                rela_array_memory_class = self._ElfW_Rela * (shdr.sh_size // sizeof(self._ElfW_Rela))
                rela_array_buffer = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                 shdr.sh_size)
                self._rela_array = cast(rela_array_buffer, POINTER(rela_array_memory_class)).contents
            elif section_type == elfenums.SHT.SHT_REL:
                rel_array_memory_class = self._ElfW_Rel * (shdr.sh_size // sizeof(self._ElfW_Rel))
                rel_array_buffer = self.__get_c_array_at_offset(shdr.sh_offset,
                                                                shdr.sh_size)
                self._rel_array = cast(rel_array_buffer, POINTER(rel_array_memory_class)).contents

            section_dict = dict(shdr)
            section_dict['name'] = section_name
            section_dict['type'] = section_type

            self.sections.append(section_tuple(**section_dict))

    def _parse_symbol_entries(self):
        extra_fields = ['name', 'type', 'binding', 'visibility']
        sym_tuple = namedtuple('Symbol', extra_fields + list(dict(self._ElfW_Sym._fields_).keys()))
        for sym in sym_array:
            symbol_name = string_at_offset(main_string_table, sym.st_name)
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
            self.symbol_entries.append(sym_tuple(**symbol_entry_dict))






with open("chal", "rb") as f:
    ident_buf_class = c_ubyte*sizeof(elfstructs.Elf_Ident)
    ident_buf = ident_buf_class.from_buffer(bytearray(f.read(sizeof(elfstructs.Elf_Ident))))
    ident = cast(ident_buf, POINTER(elfstructs.Elf_Ident)).contents
    f.seek(0)
    e = f.read()

elf_array = (c_ubyte*len(e)).from_buffer(bytearray(e))

ehdr = cast(elf_array, POINTER(elfstructs.Elf64_Ehdr)).contents

phdr_array_class = (ehdr.e_phnum * elfstructs.Elf64_Phdr)
phdr_array = phdr_array_class.from_buffer(elf_array, ehdr.e_phoff)

shdr_array_class = (ehdr.e_shnum * elfstructs.Elf64_Shdr)
shdr_array = shdr_array_class.from_buffer(elf_array, ehdr.e_shoff)

# get the section header for the section header string table
shstr = shdr_array[ehdr.e_shstrndx]
# section_header_string_table = bytes(elf_array[shstr.sh_offset:shstr.sh_offset + shstr.sh_size])
section_header_string_table = (c_ubyte*shstr.sh_size).from_buffer(elf_array, shstr.sh_offset)

sym_class = (c_ubyte*sizeof(elfstructs.Elf64_Sym))
dyn_class = (c_ubyte*sizeof(elfstructs.Elf64_Dyn))

# pull out the section header string table
# section_names = [i.decode() for i in section_header_string_table.split(b'\x00') if i != b'']

strtab_shdr = None
dynsym_shdr = None
dynstr_shdr = None
symtab_shdr = None
dynamic_shdr = None
rela_shdr = None
rel_shdr = None

print("section headers")
for shdr in shdr_array:
    section_type = elfenums.SHT(shdr.sh_type)
    print(section_type)
    section_name = string_at_offset(section_header_string_table, shdr.sh_name)
    if section_type == elfenums.SHT.SHT_STRTAB and section_name == '.strtab':
        strtab_shdr = shdr
        main_string_table = (c_ubyte*shdr.sh_size).from_buffer(elf_array, shdr.sh_offset)
    elif section_type == elfenums.SHT.SHT_STRTAB and section_name == '.dynstr':
        dynstr_shdr = shdr
        dynamic_string_table = (c_ubyte*shdr.sh_size).from_buffer(elf_array, shdr.sh_offset)
    elif section_type == elfenums.SHT.SHT_DYNSYM and section_name == '.dynsym':
        dynsym_shdr = shdr
        dyn_sym_array_class = elfstructs.Elf64_Sym * (shdr.sh_size // sizeof(elfstructs.Elf64_Sym))
        dyn_sym_array = dyn_sym_array_class.from_buffer(elf_array, dynsym_shdr.sh_offset)
    elif section_type == elfenums.SHT.SHT_SYMTAB and section_name == '.symtab':
        symtab_shdr = shdr
        sym_array_class = elfstructs.Elf64_Sym * (shdr.sh_size // sizeof(elfstructs.Elf64_Sym))
        sym_array = sym_array_class.from_buffer(elf_array, symtab_shdr.sh_offset)
    elif section_type == elfenums.SHT.SHT_DYNAMIC and section_name == '.dynamic':
        dynamic_shdr = shdr
        dyn_array_class = elfstructs.Elf64_Dyn * (shdr.sh_size // sizeof(dyn_class))
        dyn_array = dyn_array_class.from_buffer(elf_array, shdr.sh_offset)
    elif section_type == elfenums.SHT.SHT_RELA:
        rela_shdr = shdr
        rela_array_class = elfstructs.Elf64_Rela * (shdr.sh_size // sizeof(elfstructs.Elf64_Rela))
        rela_array = rela_array_class.from_buffer(elf_array, shdr.sh_offset)
    elif section_type == elfenums.SHT.SHT_REL:
        rel_shdr = shdr
        rel_array_class = elfstructs.Elf64_Rel * (shdr.sh_size // sizeof(elfstructs.Elf64_Rel))
        rel_array = rel_array_class.from_buffer(elf_array, shdr.sh_offset)


    print(section_name)
    print(shdr)
    print()


print("regular syms")
for sym in sym_array:
    symbol_name = string_at_offset(main_string_table, sym.st_name)
    info_raw = sym.st_info
    # decode sym type and binding
    symbol_type = elfenums.STT(constexpr.ELF64_ST_TYPE(info_raw))
    symbol_binding = elfenums.STB(constexpr.ELF64_ST_BIND(info_raw))
    symbol_visibility = elfenums.STV(sym.st_other)
    print(symbol_name)
    print(symbol_type)
    print(symbol_binding)
    print(symbol_visibility)
    print(sym)
    print()


print("dynamic syms")

for sym in dyn_sym_array:
    symbol_name = string_at_offset(dynamic_string_table, sym.st_name)
    info_raw = sym.st_info
    # decode sym type and binding
    symbol_type = elfenums.STT(constexpr.ELF64_ST_TYPE(info_raw))
    symbol_binding = elfenums.STB(constexpr.ELF64_ST_BIND(info_raw))
    symbol_visibility = elfenums.STV(sym.st_other)
    print(symbol_name)
    print(symbol_type)
    print(symbol_binding)
    print(symbol_visibility)
    print(sym)
    print()

print("dynamic entries")

for d in dyn_array:
    tag_type = elfenums.DT(d.d_tag)
    print(tag_type)
    print(hex(d.d_un.d_val))
    print(d)
    print()

print("phdr entries")

for phdr in phdr_array:
    phdr_type = elfenums.PT(phdr.p_type)
    phdr_flags = elfenums.PF(phdr.p_flags)
    print(phdr_type)
    print(phdr_flags)
    print(phdr)
    print()

print("rela entries")

for rela in rela_array:
    rela_info = rela.r_info
    rela_sym = constexpr.ELF64_R_SYM(rela_info)
    # rela_type = elfenums.R(constexpr.ELF64_R_TYPE(rela_info))
    print(string_at_offset(dynamic_string_table, dyn_sym_array[rela_sym].st_name))
    # print(rela_type)
    print(rela)
    print()


