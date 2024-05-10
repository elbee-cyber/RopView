from binaryninja import *
from .constants import *

class GadgetSearch:
    """
    Custom tool that discovers ROP gadgets in executable segments of memory.
    """

    # Stores a dict of gadgets {addr:mnemonic}
    gadget_pool = {}
    gadget_pool_raw = {}

    def __init__(self, bv, count=8, repeat=False):
        """
        Responsible for parsing executable segments of memory, counting back from
        *op instructions for gadgets and populating the pool.
        :param `bv`: BinaryView object of the current plugin pane.
        :param `count`: How many bytes back to process a gadget (default=8).
        :param `repeat`: Include duplicate gadgets (default=False).
        """
        current_addr = bv.start
        # Resolve a list of control-flow instructions for the arch
        control_insn = arch[bv.arch.name]['controls']
        # Used to check for duplicates
        used_gadgets = []
        # Capstone instance used for disassembly
        md = Cs(capstone_arch[bv.arch.name], bitmode(bv.arch.name))
        for ctrl in control_insn:
            raw = next(md.disasm(ctrl, 0x1000)).mnemonic
            # While bv.find_next_data(ctrl) returns true
            while current_addr is not None:
                current_addr = bv.find_next_data(current_addr,ctrl)
                if current_addr is None:
                    break
                # Save the actual current insn site before editing it in place for count
                save = current_addr
                for i in range(0,count):
                    if not bv.get_segment_at(current_addr).executable:
                        break
                    else:
                        disasm = ''
                        # Disassemble from insn_site-i to ctrl_insn
                        current_addr = save-i
                        insn = bv.read(current_addr,i+1)
                        for i in md.disasm(insn, 0x1000):
                            if i.op_str == '':
                                disasm += i.mnemonic + ' ; '
                            else:
                                disasm += i.mnemonic + ' ' + i.op_str + ' ; '
                        if insn.count(ctrl) > 1:
                            break
                        if disasm == '' or disasm == ' ' or raw not in disasm:
                            continue
                        if not repeat:
                            if insn in used_gadgets:
                                continue
                            used_gadgets.append(insn)
                        self.gadget_pool[current_addr] = disasm
                        self.gadget_pool_raw[current_addr] = insn
                # Prepare next insn site
                current_addr = save+1
