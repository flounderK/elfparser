#!/usr/bin/env python3

from . import instantiate_ctype_with_backing, set_backing_value, set_backing_value_from_elf_offset
from . import elfstructs


with open("chal", "rb") as f:
    e = f.read()

ehdr_backing, ehdr = instantiate_ctype_with_backing(elfstructs.Elf64_Ehdr)
set_backing_value_from_elf_offset(ehdr_backing, e, 0)


shdr_backing, shdr = instantiate_ctype_with_backing(elfstructs.Elf64_Shdr)

for i in range(ehdr.e_shnum):
    set_backing_value_from_elf_offset(shdr_backing, e, ehdr.e_shoff + (i*len(shdr_backing)))
    print("%d" % i)
    print(shdr)


