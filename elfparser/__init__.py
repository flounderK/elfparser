#!/usr/bin/env python3

from ctypes import ARRAY, sizeof, POINTER, cast, c_ubyte
import sys


class GlobalContext:
    _instance = None
    big_endian_aliases = ['be', 'big', 'eb']
    little_endian_aliases = ['el', 'le', 'little']
    endiannesses = big_endian_aliases + little_endian_aliases

    _defaults = {'endian': sys.byteorder,
                 'bits': 32}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(GlobalContext, cls).__new__(cls, *args, **kwargs)

        return cls._instance

    def __init__(self, *args, **kwargs):
        self.__dict__.update(self._defaults)
        self.__dict__.update(kwargs)

    @property
    def endian(self):
        return self.__dict__.get('endian')

    @endian.setter
    def endian(self, val):
        exceptionstring = "Endian must be a string in {}".format(repr(self.endiannesses))
        if not isinstance(val, str):
            raise Exception(exceptionstring)

        lowered_val = val.lower()
        if lowered_val in self.big_endian_aliases:
            self.__dict__['endian'] = 'big'
        elif lowered_val in self.little_endian_aliases:
            self.__dict__['endian'] = 'little'
        else:
            raise Exception(exceptionstring)

    def __getitem__(self, item):
        return self.__dict__.get(item)

    def __setitem__(self, item, val):
        self.__dict__[item] = val

    def __iter__(self):
        for i in self.__dict__.items():
            yield i


context = GlobalContext()

from . import elftypes
from . import elfenums
from . import elfmacros
from . import elfstructs
from . import constexpr


