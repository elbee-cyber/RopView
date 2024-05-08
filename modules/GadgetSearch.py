from binaryninja import *
from .constants import *
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
                    if not bv.get_segment_at(current_addr).executable:
                        break
                    else:
                        insn = ""
                        current_addr = save-i
                        while current_addr != save:
                            curr = bv.get_disassembly(current_addr).split()
                            if ctrl in bv.read(current_addr,1):
                                current_addr = save
                                break
                            insn += ' '.join(curr)+" ; "
                            current_addr += 1
                        insn += ' '.join(bv.get_disassembly(current_addr).split())+" ; "
                        current_addr = save-i
                        if not repeat:
                            if insn in list(self.gadget_pool.values()):
                                break
                        self.gadget_pool[current_addr] = "          " + insn
                current_addr = save+1
        log_info(str(self.gadget_pool),"Untitled ROP Assist")