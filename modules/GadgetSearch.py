from binaryninja import *
from .constants import *
import re

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
        control_insn = ()
        if rop:
            control_insn += gadgets[bv.arch.name]['rop']
        if jop:
            control_insn += gadgets[bv.arch.name]['jop']
        if cop:
            control_insn += gadgets[bv.arch.name]['cop']

        # Used to check for duplicates
        used_gadgets = []

        # Capstone instance used for disassembly
        md = Cs(capstone_arch[bv.arch.name], bitmode(bv.arch.name)[0])

        for ctrl in control_insn:
            curr_site = bv.start
            while curr_site != None:
                # Find potential gadget site
                curr_site = bv.find_next_data(curr_site,ctrl[0])
                if curr_site is None:
                    break

                # Saved to increase after depth search
                save = curr_site

                # Confirm the gadget site contains the current control instruction
                if re.match(ctrl[2],bv.read(curr_site,ctrl[1])) != None:
                    for i in range(0,depth):
                        if not bv.get_segment_at(curr_site).executable:
                            break
                        else:
                            curr_site = save-i
                            insn = bv.read(curr_site,i+ctrl[1])
                            disasm = ''
                            for val in md.disasm(insn,0x1000):
                                disasm += val.mnemonic + ' ' + val.op_str + ' ; '
                            disasm = disasm.replace('  ',' ')

                            # Multi-branch check
                            if not multibranch:
                                occured = 0
                                for mnemonic in gadgets[bv.arch.name]['mnemonics']:
                                    if mnemonic in disasm:
                                        occured += 1
                                if occured > 1:
                                    break
                            
                            # Double gadget check
                            if disasm == '' or disasm == ' ' or ctrl[3] not in disasm:
                                continue

                            # Duplicates
                            if not repeat:
                                if insn in used_gadgets:
                                    continue
                                used_gadgets.append(insn)
                            
                            # All checks passed, save to cache
                            self.gadget_pool[curr_site] = disasm
                            self.gadget_pool_raw[curr_site] = insn

                # Next address for search
                curr_site = save+1
