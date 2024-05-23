from binaryninja import *
from .constants import *

class GadgetSearch:
    """
    Discovers ROP gadgets in executable segments of memory.
    """

    def __init__(self, bv, depth=16, repeat=False, rop=True, jop=True, cop=True, multibranch=False):
        """
        Responsible for gadget searching with applied options. 
        Find all control instructions in executable segments and count back by depth, saving each gadget
        :param bv: BinaryView
        :param depth: How many bytes back from a ctrl to save gadgets (instructions on x86 do not have a constant size, special handling required for other archs) (default=11)
        :param repeat: Include duplicate gadgets (default=False)
        """

        # Exposed for renderer access
        self.rop, self.jop, self.cop, self.repeat, self.depth, self.multibranch = rop, jop, cop, repeat, depth, multibranch

        # Dict of gadget mnemonics {addr:str}
        self.gadget_pool = {}

        # Dict of raw gadgets {addr:bytes}
        self.gadget_pool_raw = {}

        # Control-flow instructions
        control_insn = []
        if rop:
            control_insn += arch[bv.arch.name]['ret']
        if jop:
            control_insn += arch[bv.arch.name]['jumps']

        # Used to check for duplicates
        used_gadgets = []

        # Capstone instance used for disassembly
        md = Cs(capstone_arch[bv.arch.name], bitmode(bv.arch.name)[0])

        # Search for all types of OP
        for ctrl in control_insn:
            # Start at first address of the loaded binary
            current_addr = bv.start

            try:
                # Current control instruction for search
                raw = next(md.disasm(ctrl, 0x1000)).mnemonic
            except StopIteration:
                continue

            # if current_addr is None, search complete
            while current_addr is not None:
                # Current address of control instruction to analyze
                current_addr = bv.find_next_data(current_addr,ctrl)
                if current_addr is None:
                    break
                # Save the actual gadget site, sub-gadgets are derived via editing in place
                save = current_addr
                for i in range(0,depth):
                    # Make sure potential gadget site is in executable segment
                    if not bv.get_segment_at(current_addr).executable:
                        break
                    else:
                        disasm = ''
                        # Current gadget site based on depth
                        current_addr = save-i
                        insn = bv.read(current_addr,i+len(ctrl))
                        # Save current gadget to disasm
                        for i in md.disasm(insn, 0x1000):
                            if i.op_str == '':
                                disasm += i.mnemonic + ' ; '
                            else:
                                disasm += i.mnemonic + ' ' + i.op_str + ' ; '

                        # Double gadget case
                        if insn.count(ctrl) > 1:
                            break
                        # No gadget case
                        if disasm == '' or disasm == ' ' or raw[:3] not in disasm:
                            continue
                        # If repeat=False and gadget already found do not save, otherwise stash in used_gadgets
                        if not repeat:
                            if insn in used_gadgets:
                                continue
                            used_gadgets.append(insn)
                        # Append found gadget to gadget pool mnemonic and raw
                        self.gadget_pool[current_addr] = disasm
                        self.gadget_pool_raw[current_addr] = insn
                # Prepare start bound for next search
                current_addr = save+1
