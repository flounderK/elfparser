
from .elftypes import Elf32_Addr, Elf32_Half, Elf32_Off, Elf32_Section, Elf32_Sword, Elf32_Sxword, Elf32_Versym, Elf32_Word, Elf32_Xword, Elf64_Addr, Elf64_Half, Elf64_Off, Elf64_Section, Elf64_Sword, Elf64_Sxword, Elf64_Versym, Elf64_Word, Elf64_Xword
from . import elfenums


def ELF32_ST_BIND(val):
    return ((0xff & (val)) >> 4)


def ELF32_ST_TYPE(val):
    return ((val) & 0xf)


def ELF32_ST_INFO(bind, typ):
    return (((bind) << 4) + ((typ) & 0xf))


def ELF64_ST_BIND(val):
    return ((0xff & (val)) >> 4)


def ELF64_ST_TYPE(val):
    return ((val) & 0xf)


def ELF64_ST_INFO(bind, typ):
    return (((bind) << 4) + ((typ) & 0xf))


def ELF32_ST_VISIBILITY(o):
    return ((o) & 0x03)


def ELF64_ST_VISIBILITY(o):
    return ((o) & 0x03)


def ELF32_R_SYM(val):
    return ((val) >> 8)


def ELF32_R_TYPE(val):
    return ((val) & 0xff)


def ELF32_R_INFO(sym, typ):
    return (((sym) << 8) + ((typ) & 0xff))


def ELF64_R_SYM(i):
    return ((i) >> 32)


def ELF64_R_TYPE(i):
    return ((i) & 0xffffffff)


def ELF64_R_INFO(sym, typ):
    return ((((sym)) << 32) + (typ))


def DT_VALTAGIDX(tag):
    return (elfenums.DT.DT_VALRNGHI - (tag))


def DT_ADDRTAGIDX(tag):
    return (elfenums.DT.DT_ADDRRNGHI - (tag))


def DT_VERSIONTAGIDX(tag):
    return (elfenums.DT.DT_VERNEEDNUM - (tag))


def DT_EXTRATAGIDX(tag):
    return ((Elf32_Word)-((tag) << 1 >> 1)-1)


def ELF32_M_SYM(info):
    return ((info) >> 8)


def ELF32_M_SIZE(info):
    return (0xff & (info))


def ELF32_M_INFO(sym, size):
    return (((sym) << 8) + (0xff & size))


def ELF64_M_SYM(info):
    return ELF32_M_SYM(info)


def ELF64_M_SIZE(info):
    return ELF32_M_SIZE(info)


def ELF64_M_INFO(sym, size):
    return ELF32_M_INFO(sym, size)


def EF_ARM_EABI_VERSION(flags):
    return ((flags) & elfenums.EF.EF_ARM_EABIMASK)


