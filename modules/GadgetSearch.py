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
        possible_gadgets = []
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
                        disasm = ''
                        current_addr = save-i
                        md = Cs(capstone_arch[bv.arch.name], bitmode(bv.arch.name))
                        insn = bv.read(current_addr,i+1)
                        for i in md.disasm(insn, 0x1000):
                            if i.op_str == '':
                                disasm += i.mnemonic + ' ; '
                            else:
                                disasm += i.mnemonic + ' ' + i.op_str + ' ; '
                        if insn.count(ctrl) > 1:
                            break
                        if disasm == '' or disasm == ' ':
                            continue
                        if not repeat:
                            if insn in possible_gadgets:
                                continue
                            possible_gadgets.append(insn)
                        self.gadget_pool[current_addr] = disasm
                current_addr = save+1
        #log_info(str(self.gadget_pool),"Untitled ROP Assist")