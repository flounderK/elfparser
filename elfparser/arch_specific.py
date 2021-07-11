
from . import elfenums

ARCH_SPECIFIC_VALUES = \
    {
      "arm": {
        "ELF_MACHINE_NAME": "ARM",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0xf8000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_ARM.R_ARM_JUMP_SLOT,
        "ELF_MACHINE_PLT_REL": True,
        "ELF_MACHINE_NO_RELA": "defined RTLD_BOOTSTRAP",
        "ELF_MACHINE_NO_REL": False
      },
      "riscv": {
        "ELF_MACHINE_NAME": "RISC-V",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_RISCV.R_RISCV_JUMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "x86_64": {
        "ELF_MACHINE_NAME": "x86_64",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_X86_64.R_X86_64_JUMP_SLOT,
        "ELF_MACHINE_IRELATIVE": elfenums.R_X86_64.R_X86_64_IRELATIVE,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "i386": {
        "ELF_MACHINE_NAME": "i386",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0xf8000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_386.R_386_JMP_SLOT,
        "ELF_MACHINE_PLT_REL": True,
        "ELF_MACHINE_NO_RELA": "defined RTLD_BOOTSTRAP",
        "ELF_MACHINE_NO_REL": False
      },
      "s390-32": {
        "ELF_MACHINE_NAME": "s390",
        "EM_S390_OLD": 0xA390,
        "ELF_MACHINE_USER_ADDRESS_MASK": 0xf8000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_390.R_390_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "s390-64": {
        "ELF_MACHINE_NAME": "s390x",
        "ELF_MACHINE_IRELATIVE": elfenums.R_390.R_390_IRELATIVE,
        "EM_S390_OLD": 0xA390,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_390.R_390_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "powerpc64": {
        "ELF_MACHINE_NAME": "powerpc64",
        "ELF_MULT_MACHINES_SUPPORTED": "",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_PPC64.R_PPC64_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False,
        "PLT_INITIAL_ENTRY_WORDS": "2",
        "PLT_ENTRY_WORDS": True,
        "GLINK_INITIAL_ENTRY_WORDS": "8",
        "GLINK_ENTRY_WORDS(I)": True
      },
      "powerpc32": {
        "ELF_MACHINE_NAME": "powerpc",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0xf0000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_PPC.R_PPC_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "sparc64": {
        "ELF_MACHINE_NAME": "sparc64",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_SPARC.R_SPARC_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "sparc32": {
        "ELF_MACHINE_NAME": "sparc",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_SPARC.R_SPARC_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "ia64": {
        "ELF_MACHINE_NAME": "ia64",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_IA64.R_IA64_IPLTLSB,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False,
        "R_IA64_FORMAT_32MSB": 4,
        "R_IA64_FORMAT_32LSB": 5,
        "R_IA64_FORMAT_64MSB": 6,
        "R_IA64_FORMAT_64LSB": 7,
        "ELF_MACHINE_REL_RELATIVE": True
      },
      "nios2": {
        "ELF_MACHINE_NAME": "nios2",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_NIOS2.R_NIOS2_JUMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "alpha": {
        "ELF_MACHINE_NAME": "alpha",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0x120000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_ALPHA.R_ALPHA_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False,
        "ELF_MACHINE_REL_RELATIVE": True
      },
      "aarch64": {
        "ELF_MACHINE_NAME": "aarch64",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_AARCH64.R_AARCH64_JUMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "mips": {
        "ELF_MACHINE_NAME": "MIPS",
        "OFFSET_GP_GOT": 0x7ff0,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_MIPS.R_MIPS_JUMP_SLOT,
        "ELF_MACHINE_PLT_REL": True,
        "ELF_MACHINE_NO_REL": False,
        "ELF_MACHINE_NO_RELA": False,
        "ELF_MACHINE_USER_ADDRESS_MASK": 0x80000000
      },
      "arc": {
        "ELF_MACHINE_NAME": "arc",
        "ELF_MACHINE_JMP_SLOT": elfenums.R_ARC.R_ARC_JUMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "m68k": {
        "ELF_MACHINE_NAME": "m68k",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0x80000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_68K.R_68K_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "hppa": {
        "ELF_MACHINE_NAME": "hppa",
        "PA_GP_RELOC": True,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_PARISC.R_PARISC_IPLT,
        "ELF_MACHINE_SIZEOF_JMP_SLOT": "PLT_ENTRY_SIZE",
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "microblaze": {
        "ELF_MACHINE_NAME": "microblaze",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0x80000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_MICROBLAZE.R_MICROBLAZE_JUMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "csky": {
        "ELF_MACHINE_NAME": "csky",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0x80000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_CKCORE.R_CKCORE_JUMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      },
      "sh": {
        "ELF_MACHINE_NAME": "SH",
        "ELF_MACHINE_USER_ADDRESS_MASK": 0x80000000,
        "ELF_MACHINE_JMP_SLOT": elfenums.R_SH.R_SH_JMP_SLOT,
        "ELF_MACHINE_NO_REL": True,
        "ELF_MACHINE_NO_RELA": False
      }
    }
