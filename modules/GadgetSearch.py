from binaryninja import *
from .constants import *
from capstone import *
from logging import *

# Useful
# bv.get_segment_at(bv.find_next_data(bv.start,b'\xc3')).executable
class GadgetSearch:
    gadget_pool = {}

    def __init__(self, bv, count=6, repeat=False):
        current_addr = bv.start
        control_insn = arch[bv.arch.name]['controls']
        for ctrl in control_insn:
            while current_addr is not None:
                current_addr = bv.find_next_data(current_addr,ctrl)
                if current_addr is None:
                    break
                save = current_addr
                for i in range(0,count):
                    # Count back 6 from ctrl instruction, stop counting back if byte is non-executable or another ctrl instruction is encountered
                    if not bv.get_segment_at(current_addr).executable or ctrl in bv.read(current_addr,1):
                        break
                    else:
                        current_addr = save-i
                        asm = ""
                        insn = bv.read(current_addr,i+1)
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                        for i in md.disasm(insn,0x1000):
                            asm += i.mnemonic+" ; "
                        if not repeat:
                            if asm in list(self.gadget_pool.values()):
                                continue

                        self.gadget_pool[current_addr] = asm
                current_addr = save+1