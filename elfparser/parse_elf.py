#!/usr/bin/env python3

from . import instantiate_ctype_with_backing, set_backing_value, set_backing_value_from_elf_offset
from . import elfstructs
from . import elfenums
from . import elfmacros
from ctypes import c_ubyte, sizeof, addressof, cast, POINTER, create_string_buffer, string_at
import _ctypes


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


with open("chal", "rb") as f:
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


    print(section_name)
    print(shdr)
    print()


print("regular syms")
for sym in sym_array:
    symbol_name = string_at_offset(main_string_table, sym.st_name)
    info_raw = sym.st_info
    # decode sym type and binding
    symbol_type = elfenums.STT(elfmacros.ELF64_ST_TYPE(info_raw))
    symbol_binding = elfenums.STB(elfmacros.ELF64_ST_BIND(info_raw))
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
    symbol_type = elfenums.STT(elfmacros.ELF64_ST_TYPE(info_raw))
    symbol_binding = elfenums.STB(elfmacros.ELF64_ST_BIND(info_raw))
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
    rela_sym = elfmacros.ELF64_R_SYM(rela_info)
    # rela_type = elfenums.R(elfmacros.ELF64_R_TYPE(rela_info))
    print(string_at_offset(dynamic_string_table, dyn_sym_array[rela_sym].st_name))
    # print(rela_type)
    print(rela)
    print()


