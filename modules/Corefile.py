import lief
from .constants import *

class Corefile:

    reg_group = {
        "aarch64":lief.ELF.CorePrStatus.Registers.AARCH64,
        "armv7":lief.ELF.CorePrStatus.Registers.ARM,
        "x86":lief.ELF.CorePrStatus.Registers.X86,
        "x86_64":lief.ELF.CorePrStatus.Registers.X86_64
    }

    def __init__(self, filepath, arch):
        self.filepath = filepath
        self.core = lief.parse(filepath)
        self.regs = {}
        self.arch = arch
        self.segments = []
        for segment in self.core.segments:
            self.segments.append(segment)

    def isCore(self):
        for note in self.core.notes:
            if isinstance(note, lief.ELF.CorePrStatus):
                return True
        return False
    
    def isSupported(self):
        if self.arch in self.reg_group:
            return True
        return False
        
    def registers(self):
        if self.regs:
            return self.regs
        
        self.regs = {}
        for note in self.core.notes:
            if not isinstance(note, lief.ELF.CorePrStatus):
                continue
            reg_values = note.register_values
            for reg in arch[self.arch]["prestateOpts"]:
                try:
                    value = getattr(self.reg_group[self.arch],reg.upper())
                    self.regs[reg] = reg_values[value.value]
                except:
                    continue
        return self.regs

    def read(self, address, size):
        for segment in self.segments:
            start = segment.virtual_address
            end = start + segment.virtual_size
            if start <= address < end:
                offset = address - start
                data = segment.content[offset:offset + size]
                return bytes(data)
        return b''