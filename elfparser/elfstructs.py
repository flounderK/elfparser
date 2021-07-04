#!/usr/bin/python3
from ctypes import c_ubyte, c_uint16, c_uint32, c_int32, c_uint64, c_int64, sizeof, cast, Structure, Union, ARRAY, POINTER, memmove, byref, addressof, Array
import _ctypes
from . import elfmacros
from . import elfenums
from .elftypes import elf32_addr, elf32_half, elf32_off, elf32_section, elf32_sword, elf32_sxword, elf32_versym, elf32_word, elf32_xword, elf64_addr, elf64_half, elf64_off, elf64_section, elf64_sword, elf64_sxword, elf64_versym, elf64_word, elf64_xword
from types import new_class
import sys

from . import context

_array_type = type(Array)


# borrowed from ctypes  to force unions nested within
# non-native endian structs to work correctly
def _other_endian(typ):
    """Return the type with the 'other' byte order.  Simple types like
    c_int and so on already have __ctype_be__ and __ctype_le__
    attributes which contain the types, for more complicated types
    arrays and structures are supported.
    """
    # check _OTHER_ENDIAN attribute (present if typ is primitive type)
    if hasattr(typ, _OTHER_ENDIAN):
        return getattr(typ, _OTHER_ENDIAN)
    # if typ is array
    if isinstance(typ, _array_type):
        return _other_endian(typ._type_) * typ._length_
    # if typ is structure
    if issubclass(typ, Structure):
        return typ

    if issubclass(typ, Union):
        return typ
    raise TypeError("This type does not support other endian: %s" % typ)


class _swapped_meta(type(Structure), type(Union)):
    def __setattr__(self, attrname, value):
        if attrname == "_fields_":
            fields = []
            for desc in value:
                name = desc[0]
                typ = desc[1]
                rest = desc[2:]
                fields.append((name, _other_endian(typ)) + rest)
            value = fields
        super().__setattr__(attrname, value)

################################################################

# Note: The Structure metaclass checks for the *presence* (not the
# value!) of a _swapped_bytes_ attribute to determine the bit order in
# structures containing bit fields.

if sys.byteorder == "little":
    _OTHER_ENDIAN = "__ctype_be__"

    LittleEndianStructure = Structure

    class BigEndianStructure(Structure, metaclass=_swapped_meta):
        """Structure with big endian byte order"""
        __slots__ = ()
        _swappedbytes_ = None

    NonNativeStructure = BigEndianStructure

elif sys.byteorder == "big":
    _OTHER_ENDIAN = "__ctype_le__"

    BigEndianStructure = Structure

    class LittleEndianStructure(Structure, metaclass=_swapped_meta):
        """Structure with little endian byte order"""
        __slots__ = ()
        _swappedbytes_ = None

    NonNativeStructure = LittleEndianStructure





class NiceHexFieldRepr:
    def __repr__(self):
        return "\n".join([("%s: %#x" % (k, getattr(self, k))) if issubclass(v, _ctypes._SimpleCData)
                          else ("%s: %s" % (k, bytes(getattr(self, k))))
                          for k, v in self._fields_])


class CtypesByteLevelManipulation:
    def copy(self):
        """Byte level copy constructor"""
        sizeof_self = sizeof(self)
        new_backing_class = (c_ubyte * sizeof_self)
        new_backing = new_backing_class.from_buffer_copy(self)
        # if the backing for this object is available, just memmove from that
        new_instance_ptr = cast(new_backing, POINTER(self.__class__))
        new_instance_ptr.contents._elfparser_backing = new_backing
        return new_instance_ptr.contents

    def write_into(self, bytevals):
        """Copy byte values from bytevals into the current backing of
        the object"""
        mutable_bytevals = bytearray(bytevals)
        sizeof_self = sizeof(self)
        backing_class = (c_ubyte * sizeof_self)
        # backing = backing_class.from_buffer(self)

        # temporary backing that will hold the values c
        temp_backing = backing_class.from_buffer(mutable_bytevals)
        memmove(byref(self), temp_backing, sizeof_self)

    def __iter__(self):
        for k, v in self._fields_:
            yield (k, getattr(self, k))


class Elf_Ident(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("ei_elfmag", c_ubyte*4),
                ("ei_class", c_ubyte),
                ("ei_data", c_ubyte),
                ("ei_version", c_ubyte),
                ("ei_osabi", c_ubyte),
                ("ei_abiversion", c_ubyte),
                ("ei_pad", c_ubyte*7)]



class Elf32_Shdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("sh_name", elf32_word),
                ("sh_type", elf32_word),
                ("sh_flags", elf32_word),
                ("sh_addr", elf32_addr),
                ("sh_offset", elf32_off),
                ("sh_size", elf32_word),
                ("sh_link", elf32_word),
                ("sh_info", elf32_word),
                ("sh_addralign", elf32_word),
                ("sh_entsize", elf32_word)]


class Elf64_Shdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("sh_name", elf64_word),
                ("sh_type", elf64_word),
                ("sh_flags", elf64_xword),
                ("sh_addr", elf64_addr),
                ("sh_offset", elf64_off),
                ("sh_size", elf64_xword),
                ("sh_link", elf64_word),
                ("sh_info", elf64_word),
                ("sh_addralign", elf64_xword),
                ("sh_entsize", elf64_xword)]


class Elf32_Ehdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("e_ident", Elf_Ident),
                ("e_type", elf32_half),
                ("e_machine", elf32_half),
                ("e_version", elf32_word),
                ("e_entry", elf32_addr),
                ("e_phoff", elf32_off),
                ("e_shoff", elf32_off),
                ("e_flags", elf32_word),
                ("e_ehsize", elf32_half),
                ("e_phentsize", elf32_half),
                ("e_phnum", elf32_half),
                ("e_shentsize", elf32_half),
                ("e_shnum", elf32_half),
                ("e_shstrndx", elf32_half)]


class Elf64_Ehdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("e_ident", Elf_Ident),
                ("e_type", elf64_half),
                ("e_machine", elf64_half),
                ("e_version", elf64_word),
                ("e_entry", elf64_addr),
                ("e_phoff", elf64_off),
                ("e_shoff", elf64_off),
                ("e_flags", elf64_word),
                ("e_ehsize", elf64_half),
                ("e_phentsize", elf64_half),
                ("e_phnum", elf64_half),
                ("e_shentsize", elf64_half),
                ("e_shnum", elf64_half),
                ("e_shstrndx", elf64_half)]


class Elf32_Chdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("ch_type", elf32_word),
                ("ch_size", elf32_word),
                ("ch_addralign", elf32_word)]


class Elf64_Chdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("ch_type", elf64_word),
                ("ch_reserved", elf64_word),
                ("ch_size", elf64_xword),
                ("ch_addralign", elf64_xword)]


class Elf32_Phdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("p_type", elf32_word),
                ("p_offset", elf32_off),
                ("p_vaddr", elf32_addr),
                ("p_paddr", elf32_addr),
                ("p_filesz", elf32_word),
                ("p_memsz", elf32_word),
                ("p_flags", elf32_word),
                ("p_align", elf32_word)]


class Elf64_Phdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("p_type", elf64_word),
                ("p_flags", elf64_word),
                ("p_offset", elf64_off),
                ("p_vaddr", elf64_addr),
                ("p_paddr", elf64_addr),
                ("p_filesz", elf64_xword),
                ("p_memsz", elf64_xword),
                ("p_align", elf64_xword)]


class Elf32_Sym(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("st_name", elf32_word),
                ("st_value", elf32_addr),
                ("st_size", elf32_word),
                ("st_info", c_ubyte),
                ("st_other", c_ubyte),
                ("st_shndx", elf32_section)]


class Elf64_Sym(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("st_name", elf64_word),
                ("st_info", c_ubyte),
                ("st_other", c_ubyte),
                ("st_shndx", elf64_section),
                ("st_value", elf64_addr),
                ("st_size", elf64_xword)]


class Elf32_Syminfo(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("si_boundto", elf32_half),
                ("si_flags", elf32_half)]


class Elf64_Syminfo(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("si_boundto", elf64_half),
                ("si_flags", elf64_half)]


class Elf32_Rel(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("r_offset", elf32_addr),
                ("r_info", elf32_word)]


class Elf64_Rel(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("r_offset", elf64_addr),
                ("r_info", elf64_xword)]


class Elf32_Rela(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("r_offset", elf32_addr),
                ("r_info", elf32_word),
                ("r_addend", elf32_sword)]


class Elf64_Rela(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("r_offset", elf64_addr),
                ("r_info", elf64_xword),
                ("r_addend", elf64_sxword)]


class Elf32_Dyn(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf32_Dyn_d_un(Union):
        _fields_ = [("d_val", elf32_word),
                    ("d_ptr", elf32_addr)]
    _fields_ = [("d_tag", elf32_sword),
                ("d_un", _Elf32_Dyn_d_un)]


class Elf64_Dyn(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf64_Dyn_d_un(Union):
        _fields_ = [("d_val", elf64_xword),
                    ("d_ptr", elf64_addr)]
    _fields_ = [("d_tag", elf64_sxword),
                ("d_un", _Elf64_Dyn_d_un)]


class Elf32_Move(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("m_value", elf32_xword),
                ("m_info", elf32_word),
                ("m_poffset", elf32_word),
                ("m_repeat", elf32_half),
                ("m_stride", elf32_half)]


class Elf64_Move(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("m_value", elf64_xword),
                ("m_info", elf64_xword),
                ("m_poffset", elf64_xword),
                ("m_repeat", elf64_half),
                ("m_stride", elf64_half)]


class Elf32_gptab(Union, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf32_gptab_gt_header(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
        _fields_ = [("gt_current_g_value", elf32_word),
                    ("gt_unused", elf32_word)]

    class _Elf32_gptab_gt_entry(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
        _fields_ = [("gt_g_value", elf32_word),
                    ("gt_bytes", elf32_word)]
    _fields_ = [("gt_header", _Elf32_gptab_gt_header),
                ("gt_entry", _Elf32_gptab_gt_entry)]


class Elf32_RegInfo(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("ri_gprmask", elf32_word),
                ("ri_cprmask", elf32_word*4),
                ("ri_gp_value", elf32_sword)]


class Elf_Options(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("kind", c_ubyte),
                ("size", c_ubyte),
                ("section", elf32_section),
                ("info", elf32_word)]


class Elf_Options_Hw(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("hwp_flags1", elf32_word),
                ("hwp_flags2", elf32_word)]


class Elf32_Lib(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("l_name", elf32_word),
                ("l_time_stamp", elf32_word),
                ("l_checksum", elf32_word),
                ("l_version", elf32_word),
                ("l_flags", elf32_word)]


class Elf64_Lib(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("l_name", elf64_word),
                ("l_time_stamp", elf64_word),
                ("l_checksum", elf64_word),
                ("l_version", elf64_word),
                ("l_flags", elf64_word)]


class Elf_MIPS_ABIFlags_v0(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("version", elf32_half),
                ("isa_level", c_ubyte),
                ("isa_rev", c_ubyte),
                ("gpr_size", c_ubyte),
                ("cpr1_size", c_ubyte),
                ("cpr2_size", c_ubyte),
                ("fp_abi", c_ubyte),
                ("isa_ext", elf32_word),
                ("ases", elf32_word),
                ("flags1", elf32_word),
                ("flags2", elf32_word)]


class Elf32_Verdef(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vd_version", elf32_half),
                ("vd_flags", elf32_half),
                ("vd_ndx", elf32_half),
                ("vd_cnt", elf32_half),
                ("vd_hash", elf32_word),
                ("vd_aux", elf32_word),
                ("vd_next", elf32_word)]


class Elf64_Verdef(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vd_version", elf64_half),
                ("vd_flags", elf64_half),
                ("vd_ndx", elf64_half),
                ("vd_cnt", elf64_half),
                ("vd_hash", elf64_word),
                ("vd_aux", elf64_word),
                ("vd_next", elf64_word)]


class Elf32_Verdaux(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vda_name", elf32_word),
                ("vda_next", elf32_word)]


class Elf64_Verdaux(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vda_name", elf64_word),
                ("vda_next", elf64_word)]


class Elf32_Verneed(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vn_version", elf32_half),
                ("vn_cnt", elf32_half),
                ("vn_file", elf32_word),
                ("vn_aux", elf32_word),
                ("vn_next", elf32_word)]


class Elf64_Verneed(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vn_version", elf64_half),
                ("vn_cnt", elf64_half),
                ("vn_file", elf64_word),
                ("vn_aux", elf64_word),
                ("vn_next", elf64_word)]


class Elf32_Vernaux(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vna_hash", elf32_word),
                ("vna_flags", elf32_half),
                ("vna_other", elf32_half),
                ("vna_name", elf32_word),
                ("vna_next", elf32_word)]


class Elf64_Vernaux(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("vna_hash", elf64_word),
                ("vna_flags", elf64_half),
                ("vna_other", elf64_half),
                ("vna_name", elf64_word),
                ("vna_next", elf64_word)]


class Elf32_aux_t(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf32_aux_t_a_un(Union):
        _fields_ = [("a_val", c_uint32)]
    _fields_ = [("a_type", c_uint32),
                ("a_un", _Elf32_aux_t_a_un)]


class Elf64_aux_t(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf64_aux_t_a_un(Union):
        _fields_ = [("a_val", c_uint64)]
    _fields_ = [("a_type", c_uint64),
                ("a_un", _Elf64_aux_t_a_un)]


class Elf32_Nhdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("n_namesz", elf32_word),
                ("n_descsz", elf32_word),
                ("n_type", elf32_word)]


class Elf64_Nhdr(Structure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    _fields_ = [("n_namesz", elf64_word),
                ("n_descsz", elf64_word),
                ("n_type", elf64_word)]



# these first four non native structures have to be redefined because ctypes
# doesn't support BigEndian Unions right now
class Elf32_aux_t_NonNative(NonNativeStructure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf32_aux_t_a_un_NonNative(Union, metaclass=_swapped_meta):
        _swappedbytes_ = None
        _fields_ = [("a_val", c_uint32)]
    _fields_ = [("a_type", c_uint32),
                ("a_un", _Elf32_aux_t_a_un_NonNative)]


class Elf32_Dyn_NonNative(NonNativeStructure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf32_Dyn_d_un_NonNative(Union, metaclass=_swapped_meta):
        _swappedbytes_ = None
        _fields_ = [("d_val", elf32_word),
                    ("d_ptr", elf32_addr)]
    _fields_ = [("d_tag", elf32_sword),
                ("d_un", _Elf32_Dyn_d_un_NonNative)]


class Elf64_aux_t_NonNative(NonNativeStructure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf64_aux_t_a_un_NonNative(Union, metaclass=_swapped_meta):
        _swappedbytes_ = None
        _fields_ = [("a_val", c_uint64)]
    _fields_ = [("a_type", c_uint64),
                ("a_un", _Elf64_aux_t_a_un_NonNative)]


class Elf64_Dyn_NonNative(NonNativeStructure, NiceHexFieldRepr, CtypesByteLevelManipulation):
    class _Elf64_Dyn_d_un_NonNative(Union, metaclass=_swapped_meta):
        _swappedbytes_ = None
        _fields_ = [("d_val", elf64_xword),
                    ("d_ptr", elf64_addr)]
    _fields_ = [("d_tag", elf64_sxword),
                ("d_un", _Elf64_Dyn_d_un_NonNative)]


Elf32_Ehdr_NonNative = new_class('Elf32_Ehdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Ehdr_NonNative._fields_ = Elf32_Ehdr._fields_.copy()

Elf32_Chdr_NonNative = new_class('Elf32_Chdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Chdr_NonNative._fields_ = Elf32_Chdr._fields_.copy()

Elf32_Lib_NonNative = new_class('Elf32_Lib_NonNative',
                                bases=(NonNativeStructure,
                                       NiceHexFieldRepr,
                                       CtypesByteLevelManipulation))
Elf32_Lib_NonNative._fields_ = Elf32_Lib._fields_.copy()

Elf32_Move_NonNative = new_class('Elf32_Move_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Move_NonNative._fields_ = Elf32_Move._fields_.copy()

Elf32_Nhdr_NonNative = new_class('Elf32_Nhdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Nhdr_NonNative._fields_ = Elf32_Nhdr._fields_.copy()

Elf32_Phdr_NonNative = new_class('Elf32_Phdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Phdr_NonNative._fields_ = Elf32_Phdr._fields_.copy()

Elf32_Rel_NonNative = new_class('Elf32_Rel_NonNative',
                                bases=(NonNativeStructure,
                                       NiceHexFieldRepr,
                                       CtypesByteLevelManipulation))
Elf32_Rel_NonNative._fields_ = Elf32_Rel._fields_.copy()

Elf32_Rela_NonNative = new_class('Elf32_Rela_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Rela_NonNative._fields_ = Elf32_Rela._fields_.copy()

Elf32_Shdr_NonNative = new_class('Elf32_Shdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf32_Shdr_NonNative._fields_ = Elf32_Shdr._fields_.copy()

Elf32_Sym_NonNative = new_class('Elf32_Sym_NonNative',
                                bases=(NonNativeStructure,
                                       NiceHexFieldRepr,
                                       CtypesByteLevelManipulation))
Elf32_Sym_NonNative._fields_ = Elf32_Sym._fields_.copy()

Elf32_Syminfo_NonNative = new_class('Elf32_Syminfo_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf32_Syminfo_NonNative._fields_ = Elf32_Syminfo._fields_.copy()

Elf32_Verdaux_NonNative = new_class('Elf32_Verdaux_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf32_Verdaux_NonNative._fields_ = Elf32_Verdaux._fields_.copy()

Elf32_Verdef_NonNative = new_class('Elf32_Verdef_NonNative',
                                   bases=(NonNativeStructure,
                                          NiceHexFieldRepr,
                                          CtypesByteLevelManipulation))
Elf32_Verdef_NonNative._fields_ = Elf32_Verdef._fields_.copy()

Elf32_Vernaux_NonNative = new_class('Elf32_Vernaux_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf32_Vernaux_NonNative._fields_ = Elf32_Vernaux._fields_.copy()

Elf32_Verneed_NonNative = new_class('Elf32_Verneed_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf32_Verneed_NonNative._fields_ = Elf32_Verneed._fields_.copy()


Elf64_Ehdr_NonNative = new_class('Elf64_Ehdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Ehdr_NonNative._fields_ = Elf64_Ehdr._fields_.copy()


Elf64_Chdr_NonNative = new_class('Elf64_Chdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Chdr_NonNative._fields_ = Elf64_Chdr._fields_.copy()

Elf64_Lib_NonNative = new_class('Elf64_Lib_NonNative',
                                bases=(NonNativeStructure,
                                       NiceHexFieldRepr,
                                       CtypesByteLevelManipulation))
Elf64_Lib_NonNative._fields_ = Elf64_Lib._fields_.copy()

Elf64_Move_NonNative = new_class('Elf64_Move_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Move_NonNative._fields_ = Elf64_Move._fields_.copy()

Elf64_Nhdr_NonNative = new_class('Elf64_Nhdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Nhdr_NonNative._fields_ = Elf64_Nhdr._fields_.copy()

Elf64_Phdr_NonNative = new_class('Elf64_Phdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Phdr_NonNative._fields_ = Elf64_Phdr._fields_.copy()

Elf64_Rel_NonNative = new_class('Elf64_Rel_NonNative',
                                bases=(NonNativeStructure,
                                       NiceHexFieldRepr,
                                       CtypesByteLevelManipulation))
Elf64_Rel_NonNative._fields_ = Elf64_Rel._fields_.copy()

Elf64_Rela_NonNative = new_class('Elf64_Rela_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Rela_NonNative._fields_ = Elf64_Rela._fields_.copy()

Elf64_Shdr_NonNative = new_class('Elf64_Shdr_NonNative',
                                 bases=(NonNativeStructure,
                                        NiceHexFieldRepr,
                                        CtypesByteLevelManipulation))
Elf64_Shdr_NonNative._fields_ = Elf64_Shdr._fields_.copy()

Elf64_Sym_NonNative = new_class('Elf64_Sym_NonNative',
                                bases=(NonNativeStructure,
                                       NiceHexFieldRepr,
                                       CtypesByteLevelManipulation))
Elf64_Sym_NonNative._fields_ = Elf64_Sym._fields_.copy()

Elf64_Syminfo_NonNative = new_class('Elf64_Syminfo_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf64_Syminfo_NonNative._fields_ = Elf64_Syminfo._fields_.copy()

Elf64_Verdaux_NonNative = new_class('Elf64_Verdaux_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf64_Verdaux_NonNative._fields_ = Elf64_Verdaux._fields_.copy()

Elf64_Verdef_NonNative = new_class('Elf64_Verdef_NonNative',
                                   bases=(NonNativeStructure,
                                          NiceHexFieldRepr,
                                          CtypesByteLevelManipulation))
Elf64_Verdef_NonNative._fields_ = Elf64_Verdef._fields_.copy()

Elf64_Vernaux_NonNative = new_class('Elf64_Vernaux_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf64_Vernaux_NonNative._fields_ = Elf64_Vernaux._fields_.copy()

Elf64_Verneed_NonNative = new_class('Elf64_Verneed_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf64_Verneed_NonNative._fields_ = Elf64_Verneed._fields_.copy()

Elf32_gptab_NonNative = new_class('Elf32_gptab_NonNative',
                                  bases=(NonNativeStructure,
                                         NiceHexFieldRepr,
                                         CtypesByteLevelManipulation))
Elf32_gptab_NonNative._fields_ = Elf32_gptab._fields_.copy()

Elf32_RegInfo_NonNative = new_class('Elf32_RegInfo_NonNative',
                                    bases=(NonNativeStructure,
                                           NiceHexFieldRepr,
                                           CtypesByteLevelManipulation))
Elf32_RegInfo_NonNative._fields_ = Elf32_RegInfo._fields_.copy()

Elf_Options_NonNative = new_class('Elf_Options_NonNative',
                                  bases=(NonNativeStructure,
                                         NiceHexFieldRepr,
                                         CtypesByteLevelManipulation))
Elf_Options_NonNative._fields_ = Elf_Options._fields_.copy()

Elf_Options_Hw_NonNative = new_class('Elf_Options_Hw_NonNative',
                                     bases=(NonNativeStructure,
                                            NiceHexFieldRepr,
                                            CtypesByteLevelManipulation))
Elf_Options_Hw_NonNative._fields_ = Elf_Options_Hw._fields_.copy()

Elf_MIPS_ABIFlags_v0_NonNative = new_class('Elf_MIPS_ABIFlags_v0_NonNative',
                                           bases=(NonNativeStructure,
                                                  NiceHexFieldRepr,
                                                  CtypesByteLevelManipulation))
Elf_MIPS_ABIFlags_v0_NonNative._fields_ = Elf_MIPS_ABIFlags_v0._fields_.copy()


NATIVE_ELF32_STRUCTURES = {"ElfW_Ehdr": Elf32_Ehdr,
                           "ElfW_Shdr": Elf32_Shdr,
                           "ElfW_Chdr": Elf32_Chdr,
                           "ElfW_Sym": Elf32_Sym,
                           "ElfW_Syminfo": Elf32_Syminfo,
                           "ElfW_Rel": Elf32_Rel,
                           "ElfW_Rela": Elf32_Rela,
                           "ElfW_Phdr": Elf32_Phdr,
                           "ElfW_Dyn": Elf32_Dyn,
                           "ElfW_Verdef": Elf32_Verdef,
                           "ElfW_Verdaux": Elf32_Verdaux,
                           "ElfW_Verneed": Elf32_Verneed,
                           "ElfW_Vernaux": Elf32_Vernaux,
                           "ElfW_aux_t": Elf32_aux_t,
                           "ElfW_Nhdr": Elf32_Nhdr,
                           "ElfW_Move": Elf32_Move,
                           "ElfW_gptab": Elf32_gptab,
                           "ElfW_RegInfo": Elf32_RegInfo,
                           "Elf_Options": Elf_Options,
                           "Elf_Options_Hw": Elf_Options_Hw,
                           "ElfW_Lib": Elf32_Lib,
                           "Elf_MIPS_ABIFlags_v0": Elf_MIPS_ABIFlags_v0}

NATIVE_ELF64_STRUCTURES = {"ElfW_Ehdr": Elf64_Ehdr,
                           "ElfW_Shdr": Elf64_Shdr,
                           "ElfW_Chdr": Elf64_Chdr,
                           "ElfW_Sym": Elf64_Sym,
                           "ElfW_Syminfo": Elf64_Syminfo,
                           "ElfW_Rel": Elf64_Rel,
                           "ElfW_Rela": Elf64_Rela,
                           "ElfW_Phdr": Elf64_Phdr,
                           "ElfW_Dyn": Elf64_Dyn,
                           "ElfW_Verdef": Elf64_Verdef,
                           "ElfW_Verdaux": Elf64_Verdaux,
                           "ElfW_Verneed": Elf64_Verneed,
                           "ElfW_Vernaux": Elf64_Vernaux,
                           "ElfW_aux_t": Elf64_aux_t,
                           "ElfW_Nhdr": Elf64_Nhdr,
                           "ElfW_Move": Elf64_Move,
                           "ElfW_gptab": Elf32_gptab,
                           "ElfW_RegInfo": Elf32_RegInfo,
                           "Elf_Options": Elf_Options,
                           "Elf_Options_Hw": Elf_Options_Hw,
                           "ElfW_Lib": Elf64_Lib,
                           "Elf_MIPS_ABIFlags_v0": Elf_MIPS_ABIFlags_v0}

NON_NATIVE_ELF32_STRUCTURES = {"ElfW_Ehdr": Elf32_Ehdr_NonNative,
                               "ElfW_Shdr": Elf32_Shdr_NonNative,
                               "ElfW_Chdr": Elf32_Chdr_NonNative,
                               "ElfW_Sym": Elf32_Sym_NonNative,
                               "ElfW_Syminfo": Elf32_Syminfo_NonNative,
                               "ElfW_Rel": Elf32_Rel_NonNative,
                               "ElfW_Rela": Elf32_Rela_NonNative,
                               "ElfW_Phdr": Elf32_Phdr_NonNative,
                               "ElfW_Dyn": Elf32_Dyn_NonNative,
                               "ElfW_Verdef": Elf32_Verdef_NonNative,
                               "ElfW_Verdaux": Elf32_Verdaux_NonNative,
                               "ElfW_Verneed": Elf32_Verneed_NonNative,
                               "ElfW_Vernaux": Elf32_Vernaux_NonNative,
                               "ElfW_aux_t": Elf32_aux_t_NonNative,
                               "ElfW_Nhdr": Elf32_Nhdr_NonNative,
                               "ElfW_Move": Elf32_Move_NonNative,
                               "ElfW_gptab": Elf32_gptab_NonNative,
                               "ElfW_RegInfo": Elf32_RegInfo_NonNative,
                               "Elf_Options": Elf_Options_NonNative,
                               "Elf_Options_Hw": Elf_Options_Hw_NonNative,
                               "ElfW_Lib": Elf32_Lib_NonNative,
                               "Elf_MIPS_ABIFlags_v0": Elf_MIPS_ABIFlags_v0_NonNative}

NON_NATIVE_ELF64_STRUCTURES = {"ElfW_Ehdr": Elf64_Ehdr_NonNative,
                               "ElfW_Shdr": Elf64_Shdr_NonNative,
                               "ElfW_Chdr": Elf64_Chdr_NonNative,
                               "ElfW_Sym": Elf64_Sym_NonNative,
                               "ElfW_Syminfo": Elf64_Syminfo_NonNative,
                               "ElfW_Rel": Elf64_Rel_NonNative,
                               "ElfW_Rela": Elf64_Rela_NonNative,
                               "ElfW_Phdr": Elf64_Phdr_NonNative,
                               "ElfW_Dyn": Elf64_Dyn_NonNative,
                               "ElfW_Verdef": Elf64_Verdef_NonNative,
                               "ElfW_Verdaux": Elf64_Verdaux_NonNative,
                               "ElfW_Verneed": Elf64_Verneed_NonNative,
                               "ElfW_Vernaux": Elf64_Vernaux_NonNative,
                               "ElfW_aux_t": Elf64_aux_t_NonNative,
                               "ElfW_Nhdr": Elf64_Nhdr_NonNative,
                               "ElfW_Move": Elf64_Move_NonNative,
                               "ElfW_gptab": Elf32_gptab_NonNative,
                               "ElfW_RegInfo": Elf32_RegInfo_NonNative,
                               "Elf_Options": Elf_Options_NonNative,
                               "Elf_Options_Hw": Elf_Options_Hw_NonNative,
                               "ElfW_Lib": Elf64_Lib_NonNative,
                               "Elf_MIPS_ABIFlags_v0": Elf_MIPS_ABIFlags_v0_NonNative}
