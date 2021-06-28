#!/usr/bin/env python3

from ctypes import ARRAY, sizeof, POINTER, cast, c_ubyte
from . import elfmacros
from . import elfstructs
from . import elfenums


def instantiate_ctype_with_backing(classtype, backing=None):
    """Create an instance of the given type using the backing provided, or if
    no backing was provided create a backing as well"""
    if backing is None:
        backing = ARRAY(c_ubyte, sizeof(classtype))()
    else:
        if len(backing) != sizeof(classtype):
            raise Exception("Provided backing and classtype have different sizes")
    ptr = cast(backing, POINTER(classtype))
    ptr.contents._elfparser_backing = backing

    return backing, ptr.contents


def set_backing_value(backing, value):
    backing[:] = value


def set_backing_value_from_elf_offset(backing, elf, offset):
    set_backing_value(backing, elf[offset:offset + len(backing)])

