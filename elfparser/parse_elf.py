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

shdr_array_class = (ehdr.e_shnum * elfstructs.Elf64_Shdr)
shdr_array = shdr_array_class.from_buffer(elf_array, ehdr.e_shoff)

# get the section header for the section header string table
shstr = shdr_array[ehdr.e_shstrndx]
# section_header_string_table = bytes(elf_array[shstr.sh_offset:shstr.sh_offset + shstr.sh_size])
section_header_string_table = (c_ubyte*shstr.sh_size).from_buffer(elf_array, shstr.sh_offset)

# pull out the section header string table
# section_names = [i.decode() for i in section_header_string_table.split(b'\x00') if i != b'']

for shdr in shdr_array:
    print(elfenums.SHT(shdr.sh_type))
    print(string_at_offset(section_header_string_table, shdr.sh_name))
    print(shdr)
    print()

sym_class = (c_ubyte*sizeof(elfstructs.Elf64_Sym))

symtab_shdr = [i for i in shdr_array if i.sh_type == elfenums.SHT.SHT_SYMTAB][0]

sym_array_class = elfstructs.Elf64_Sym * (symtab_shdr.sh_size // sizeof(elfstructs.Elf64_Sym))
sym_array = sym_array_class.from_buffer(elf_array, symtab_shdr.sh_offset)

# decode sym type
[elfenums.STT(elfmacros.ELF64_ST_TYPE(i.st_info)) for i in sym_array]

# sym_backing, sym = instantiate_ctype_with_backing(elfstructs.Elf64_Sym)

# for i in range(ehdr.e_shnum):
#     set_backing_value_from_elf_offset(shdr_backing, e, ehdr.e_shoff + (i*len(shdr_backing)))
#     print("%d: %s" % (i, elfenums.SHT(shdr.sh_type)))
#     print(shdr)


