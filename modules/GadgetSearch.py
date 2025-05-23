from binaryninja import run_progress_dialog, worker_interactive_enqueue
from capstone import Cs
import re

from .constants import gadgets, capstone_arch, arch, bitmode


class GadgetSearch:
    """
    Discovers ROP gadgets in executable segments of memory.
    """

    def __init__(self, bv, depth=10, rop=True, jop=False, cop=False, sys=True, thumb=False):
        """
        Responsible for gadget searching with applied options.
        Find all control instructions in executable segments and count back by depth, saving each gadget
        :param bv: BinaryView
        :param depth: How many bytes back from a ctrl to save gadgets (instructions on x86 do not have a constant size, special handling required for other archs) (default=11)
        """

        # Exposed for renderer access
        self.rop, self.jop, self.cop, self.depth, self.sys = rop, jop, cop, depth, sys
        self.__cache = ''
        self.__bv = bv
        self.arch = bv.arch.name

        # !! GadgetSearch should be the only entity allowed to modify this !! #
        # Dict of gadget mnemonics {addr:str}
        bv.session_data['RopView']['gadget_disasm'] = {}
        # Dict of raw gadgets {addr:bytes}
        bv.session_data['RopView']['gadget_asm'] = {}

        if thumb:
            self.arch = 'thumb'

        # Load from cache or prepare for search
        self.__control_insn = ()
        if rop:
            if (bv.session_data['RopView']['cache']['rop_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'rop'
                run_progress_dialog("Loading ROP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[self.arch]['rop']
        if jop:
            if (bv.session_data['RopView']['cache']['jop_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'jop'
                run_progress_dialog("Loading JOP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[self.arch]['jop']
        if cop:
            if (bv.session_data['RopView']['cache']['cop_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'cop'
                run_progress_dialog("Loading COP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[self.arch]['cop']
        if sys:
            if (bv.session_data['RopView']['cache']['sys_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'sys'
                run_progress_dialog("Loading SYS cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[self.arch]['sys']

        # Save depth
        bv.session_data['RopView']['depth'] = depth

        # Start gadget search, return success
        bv.session_data['RopView']['loading_canceled'] = not run_progress_dialog("Loading gadgets",True,self.loadGadgets)

    def loadGadgets(self,update):
        # Capstone instance used for disassembly
        md = Cs(capstone_arch[self.arch], bitmode(self.arch))

        ds = arch[self.arch]['delay_slot']

        # update
        curr = self.__bv.start
        last_iter = 0
        full = (self.__bv.end - self.__bv.start) * len(self.__control_insn)
        if self.arch == 'thumb':
            alignment = 2
        else:
            alignment = arch[self.arch]['alignment']

        for ctrl in self.__control_insn:
            # Exists incase a group is len==1
            if ctrl == ():
                continue

            # Used for progress iter
            last_iter += 1

            curr_site = self.__bv.start

            while curr_site is not None:
                # Find potential gadget site
                curr_site = self.__bv.find_next_data(curr_site,ctrl[0])

                if curr_site is None:
                    break
                elif alignment != 1:
                    curr_site -= (alignment - len(ctrl[0]))

                # Alignment==1 if no alignment
                if curr_site % alignment != 0:
                    curr_site += alignment
                    continue

                # Saved to increase after depth search
                save = curr_site

                # Progress bar
                curr = save + (self.__bv.end * last_iter)
                if update(curr,full) is False:
                    self.__bv.session_data['RopView']['gadget_disasm'] = {}
                    self.__bv.session_data['RopView']['gadget_asm'] = {}
                    fflush(self.__bv)
                    return False

                # Confirm the gadget site contains the current control instruction
                if re.match(ctrl[2],self.__bv.read(curr_site,ctrl[1])) is not None:
                    for i in range(0,self.depth):
                        segment = self.__bv.get_segment_at(curr_site)

                        if segment is None or not segment.executable:
                            break
                        else:
                            index = i * alignment
                            curr_site = save - index
                            insn_size = index + ctrl[1]

                            # Handle delay slots
                            if ds:
                                insn_size += 4

                            insn = self.__bv.read(curr_site,insn_size)
                            disasm = ''
                            for val in md.disasm(insn,0x1000):
                                disasm += val.mnemonic + ' ' + val.op_str + ' ; '
                            disasm = disasm.replace('  ',' ')

                            # Check blacklisted interrupts
                            contains_block = False
                            for block in arch[self.arch]['blacklist']:
                                if block in disasm:
                                    contains_block = True
                                    break
                            if contains_block:
                                continue

                            # Double gadget check
                            occured = 0
                            for mnemonic in gadgets[self.arch]['mnemonics']:
                                matches = len(re.findall(mnemonic,disasm))
                                if matches > 0:
                                    occured += matches
                            if occured > 1:
                                continue

                            # Broken gadget check
                            if not disasm == '' and not disasm == ' ':
                                tokened = disasm.split(';')
                                if ds:
                                    # tokened[-1] is empty, tokened [-2] is delay slot, tokened[-3] is ctrl
                                    if len(tokened) < 3:
                                        continue
                                    broken = ctrl[3] not in tokened[-3]
                                else:
                                    broken = ctrl[3] not in tokened[-2]
                                if broken:
                                    continue
                            else:
                                continue

                            # Cache (cache should contain ALL gadget sites) (ive heard .update(tuple) is faster than .update(dict))
                            if ctrl in gadgets[self.arch]['rop']:
                                self.__bv.session_data['RopView']['cache']['rop_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['rop_asm'].update([(curr_site, insn)])
                            elif ctrl in gadgets[self.arch]['jop']:
                                self.__bv.session_data['RopView']['cache']['jop_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['jop_asm'].update([(curr_site, insn)])
                            elif ctrl in gadgets[self.arch]['cop']:
                                self.__bv.session_data['RopView']['cache']['cop_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['cop_asm'].update([(curr_site, insn)])
                            elif ctrl in gadgets[self.arch]['sys']:
                                self.__bv.session_data['RopView']['cache']['sys_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['sys_asm'].update([(curr_site, insn)])

                            # All checks passed, save to pool
                            self.__bv.session_data['RopView']['gadget_disasm'].update([(curr_site, disasm)])
                            self.__bv.session_data['RopView']['gadget_asm'].update([(curr_site, insn)])

                # Next address for search
                curr_site = save + alignment

        # Save metadata to bv
        worker_interactive_enqueue(self.saveCache)

        return True

    def saveCache(self):
        self.__bv.store_metadata("RopView.rop_disasm",self.__bv.session_data['RopView']['cache']['rop_disasm'])
        self.__bv.store_metadata("RopView.rop_asm",self.__bv.session_data['RopView']['cache']['rop_asm'])
        self.__bv.store_metadata("RopView.jop_disasm",self.__bv.session_data['RopView']['cache']['jop_disasm'])
        self.__bv.store_metadata("RopView.jop_asm",self.__bv.session_data['RopView']['cache']['jop_asm'])
        self.__bv.store_metadata("RopView.cop_disasm",self.__bv.session_data['RopView']['cache']['cop_disasm'])
        self.__bv.store_metadata("RopView.cop_asm",self.__bv.session_data['RopView']['cache']['cop_asm'])
        self.__bv.store_metadata("RopView.sys_disasm",self.__bv.session_data['RopView']['cache']['sys_disasm'])
        self.__bv.store_metadata("RopView.sys_asm",self.__bv.session_data['RopView']['cache']['sys_asm'])
        self.__bv.store_metadata("RopView.gadget_disasm",self.__bv.session_data['RopView']['gadget_disasm'])
        self.__bv.store_metadata("RopView.gadget_asm",self.__bv.session_data['RopView']['gadget_asm'])

    def load_from_cache(self, update):
        disasm_key = self.__cache + "_disasm"
        asm_key = self.__cache + "_asm"
        disasm_cache = self.__bv.session_data['RopView']['cache'][disasm_key]
        asm_cache = self.__bv.session_data['RopView']['cache'][asm_key]

        # For progress bar
        iteration = 0
        full = len(disasm_cache)

        for addr,value in asm_cache.items():
            update(iteration,full)
            self.__bv.session_data['RopView']['gadget_asm'][addr] = value
            self.__bv.session_data['RopView']['gadget_disasm'][addr] = disasm_cache[addr]
            iteration += 1
