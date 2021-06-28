#!/usr/bin/env python3

from ctypes import ARRAY, sizeof, POINTER, cast, c_ubyte
from . import elfmacros
from . import elfstructs


def instantiate_ctype_with_backing(classtype, backing=None):
    """Create an instance of the given type using the backing provided, or if
    no backing was provided create a backing as well"""
    if backing is None:
        backing = ARRAY(c_ubyte, sizeof(classtype))()
    else:
        if len(backing) != sizeof(classtype):
            raise Exception("Provided backing and classtype have different sizes")
    ptr = cast(backing, POINTER(classtype))

    return backing, ptr.contents


def set_backing_value(backing, value):
    backing[:] = value



# from .elfstructs import Elf32_Shdr, Elf64_Shdr, Elf32_Ehdr, Elf64_Ehdr
# from .elfstructs import Elf32_Phdr, Elf64_Phdr, Elf32_Rel, Elf64_Rel
# from .elfstructs import Elf32_Rela, Elf64_Rela, Elf32_Dyn, Elf64_Dyn
# from .elfstructs import Elf32_Move, Elf64_Move, Elf32_Lib, Elf64_Lib, Elf32_Verdef, Elf64_Verdef, Elf32_Verdaux, Elf64_Verdaux, Elf32_Verneed, Elf64_Verneed, Elf32_Vernaux, Elf64_Vernaux, Elf32_aux_t, Elf64_aux_t, Elf32_Nhdr, Elf64_Nhdr
# from .elfstructs import elf32_half, elf32_word, elf32_sword, elf32_xword, elf32_sxword, elf32_addr, elf32_off, elf32_section, elf32_versym
# from .elfstructs import elf64_half, elf64_word, elf64_sword, elf64_xword, elf64_sxword, elf64_addr, elf64_off, elf64_section, elf64_versym
