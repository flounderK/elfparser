
from ctypes import c_uint16, c_uint32, c_int32, c_uint64, c_int64

Elf32_Half = elf32_half = c_uint16
Elf32_Word = elf32_word = c_uint32
Elf32_Sword = elf32_sword = c_int32
Elf32_Xword = elf32_xword = c_uint64
Elf32_Sxword = elf32_sxword = c_int64
Elf32_Addr = elf32_addr = c_uint32
Elf32_Off = elf32_off = c_uint32
Elf32_Section = elf32_section = c_uint16
Elf32_Versym = elf32_versym = elf32_half


Elf64_Half = elf64_half = c_uint16
Elf64_Word = elf64_word = c_uint32
Elf64_Sword = elf64_sword = c_int32
Elf64_Xword = elf64_xword = c_uint64
Elf64_Sxword = elf64_sxword = c_int64
Elf64_Addr = elf64_addr = c_uint64
Elf64_Off = elf64_off = c_uint64
Elf64_Section = elf64_section = c_uint16
Elf64_Versym = elf64_versym = elf64_half
