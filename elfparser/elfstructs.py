#!/usr/bin/python3
from ctypes import c_ubyte, c_uint16, c_uint32, c_int32, c_uint64, c_int64, sizeof, cast, Structure, Union, ARRAY, POINTER, memmove, byref, addressof
import _ctypes
from . import elfmacros


elf32_half = c_uint16
elf32_word = c_uint32
elf32_sword = c_int32
elf32_xword = c_uint64
elf32_sxword = c_int64
elf32_addr = c_uint32
elf32_off = c_uint32
elf32_section = c_uint16
elf32_versym = elf32_half


elf64_half = c_uint16
elf64_word = c_uint32
elf64_sword = c_int32
elf64_xword = c_uint64
elf64_sxword = c_int64
elf64_addr = c_uint64
elf64_off = c_uint64
elf64_section = c_uint16
elf64_versym = elf64_half


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
    _fields_ = [("e_ident", c_ubyte*elfmacros.EI_NIDENT),
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
    _fields_ = [("e_ident", c_ubyte*elfmacros.EI_NIDENT),
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

