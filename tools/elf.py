
SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_NOBITS = 0, 1, 2, 3, 8
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 0x1, 0x2, 0x4
WA = SHF_WRITE | SHF_ALLOC
AX = SHF_ALLOC | SHF_EXEC
STT_FUNC, STB_GLOBAL = 2, 1

def _u(b, o, n):
    return int.from_bytes(b[o:o + n], 'little')

def _s(b, o):
    end = b.index(b'\0', o)
    return b[o:end].decode('latin1')

class Section:
    def __init__(self, data, sh, st_off):
        sh_name = _u(data, sh + 0, 4)
        self.sh_type = _u(data, sh + 4, 4)
        self.sh_flags = _u(data, sh + 8, 4)
        self.sh_addr = _u(data, sh + 12, 4) # "[virtual] address at which the section's first byte should reside" or 0
        self.sh_offset = _u(data, sh + 16, 4) # "byte offset from the beginning of the file to the first byte in the section"
        self.sh_size = _u(data, sh + 20, 4)
        self.name = _s(data, st_off + sh_name)

        if self.sh_type != SHT_NOBITS and self.sh_size > 0:
            self.data = data[self.sh_offset:self.sh_offset + self.sh_size]

    def __repr__(self):
        return f'Section("{self.name}", {self.sh_type:x}, {self.sh_flags:x}, {self.sh_addr:x},' \
            f' {self.sh_offset:x}, {self.sh_size:x}, ' + (', %x' % self.lma if self.lma else '!LOAD') + ')'


class Elf:
    sections = []
    named_sections = dict()
    symbols = []
    named_symbols = dict()

    def __init__(self, data):
        if data[:4] != b'\x7fELF' or data[4] != 1 or data[5] != 1:
            raise Exception(f"Not a 32-bit little-endian ELF")

        e_phoff = _u(data, 0x1c, 4)
        e_phentsize = _u(data, 0x2a, 2)
        e_phnum = _u(data, 0x2c, 2)
        loads = []                           # (p_offset, p_paddr, p_filesz)

        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            if _u(data, ph, 4) != 1:         # PT_LOAD
                continue
            loads.append((_u(data, ph + 4, 4),      # p_offset
                          _u(data, ph + 12, 4),     # p_paddr (LMA)
                          _u(data, ph + 16, 4)))    # p_filesz

        def lma_of(sh_offset, sh_addr):
            for p_off, p_paddr, p_filesz in loads:
                if p_off <= sh_offset < p_off + p_filesz:
                    return p_paddr + (sh_offset - p_off)
            return None

        e_shoff = _u(data, 0x20, 4)
        e_shentsize = _u(data, 0x2e, 2)
        e_shnum = _u(data, 0x30, 2)
        e_shstrndx = _u(data, 0x32, 2)

        st_off = _u(data, e_shoff + e_shstrndx * e_shentsize + 16, 4)

        for i in range(1, e_shnum):
            sh = e_shoff + i * e_shentsize
            section = Section(data, sh, st_off)
            section.lma = lma_of(section.sh_offset, section.sh_addr)
            self.sections.append(section)
            self.named_sections[section.name] = section

            if section.sh_type == SHT_SYMTAB:
                strtab_i = _u(data, sh + 24, 4)     # sh_link -> string table section
                st_off1 = _u(data, e_shoff + strtab_i * e_shentsize + 16, 4)

                for so in range(section.sh_offset, section.sh_offset + section.sh_size, 16):
                    st_name = _u(data, so, 4)
                    st_value = _u(data, so + 4, 4)
                    st_shndx = _u(data, so + 14, 2)
                    if st_name == 0 or st_shndx == 0:
                        continue

                    name = _s(data, st_off1 + st_name)
                    self.symbols.append((name, st_value))
                    self.named_symbols[name] = st_value
