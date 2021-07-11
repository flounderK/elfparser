
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


ELF32_CONSTEXPR = {
    "DT_ADDRTAGIDX": DT_ADDRTAGIDX,
    "DT_EXTRATAGIDX": DT_EXTRATAGIDX,
    "DT_VALTAGIDX": DT_VALTAGIDX,
    "DT_VERSIONTAGIDX": DT_VERSIONTAGIDX,
    "EF_ARM_EABI_VERSION": EF_ARM_EABI_VERSION,
    "ELFW_M_INFO": ELF32_M_INFO,
    "ELFW_M_SIZE": ELF32_M_SIZE,
    "ELFW_M_SYM": ELF32_M_SYM,
    "ELFW_R_INFO": ELF32_R_INFO,
    "ELFW_R_SYM": ELF32_R_SYM,
    "ELFW_R_TYPE": ELF32_R_TYPE,
    "ELFW_ST_BIND": ELF32_ST_BIND,
    "ELFW_ST_INFO": ELF32_ST_INFO,
    "ELFW_ST_TYPE": ELF32_ST_TYPE,
    "ELFW_ST_VISIBILITY": ELF32_ST_VISIBILITY,
}

ELF64_CONSTEXPR = {
    "DT_ADDRTAGIDX": DT_ADDRTAGIDX,
    "DT_EXTRATAGIDX": DT_EXTRATAGIDX,
    "DT_VALTAGIDX": DT_VALTAGIDX,
    "DT_VERSIONTAGIDX": DT_VERSIONTAGIDX,
    "EF_ARM_EABI_VERSION": EF_ARM_EABI_VERSION,
    "ELFW_M_INFO": ELF64_M_INFO,
    "ELFW_M_SIZE": ELF64_M_SIZE,
    "ELFW_M_SYM": ELF64_M_SYM,
    "ELFW_R_INFO": ELF64_R_INFO,
    "ELFW_R_SYM": ELF64_R_SYM,
    "ELFW_R_TYPE": ELF64_R_TYPE,
    "ELFW_ST_BIND": ELF64_ST_BIND,
    "ELFW_ST_INFO": ELF64_ST_INFO,
    "ELFW_ST_TYPE": ELF64_ST_TYPE,
    "ELFW_ST_VISIBILITY": ELF64_ST_VISIBILITY,
}


# elf machine const expressions

def ARCH_DT(dt_arch, x):
    getattr(dt_arch, '%s_%s' % (dt_arch.__name__, x)) - elfenums.DT.DT_LOPROC + elfenums.DT.DT_NUM


def DT_PPC64(x):
    return ARCH_DT(elfenums.DT_PPC64, x)


def DT_PPC(x):
    return ARCH_DT(elfenums.DT_PPC, x)


def DT_IA_64(x):
    return ARCH_DT(elfenums.DT_IA_64, x)


def DT_ALPHA(x):
    return ARCH_DT(elfenums.DT_ALPHA, x)


def DT_AARCH64(x):
    return ARCH_DT(elfenums.DT_AARCH64, x)


def DT_MIPS(x):
    return ARCH_DT(elfenums.DT_MIPS, x)


def PPC_LO(v):
    return ((v) & 0xffff)


def PPC_HI(v):
    return (((v) >> 16) & 0xffff)


def PPC_HA(v):
    return PPC_HI ((v) + 0x8000)


def PPC_HIGHER(v):
    return (((v) >> 32) & 0xffff)


def PPC_HIGHERA(v):
    return PPC_HIGHER ((v) + 0x8000)


def PPC_HIGHEST(v):
    return (((v) >> 48) & 0xffff)


def PPC_HIGHESTA(v):
    return PPC_HIGHEST ((v) + 0x8000)


# sparc64
def ELF64_R_TYPE_ID(info):
    return ((info) & 0xff)

def ELF64_R_TYPE_DATA(info):
    return ((info) >> 8)


def R_IA64_TYPE(R):
    return  ((R) & -8)

def R_IA64_FORMAT(R):
    return ((R) & 7)

