from .constants import *
import re
from binaryninja import *

class GadgetSearch:
    """
    Discovers ROP gadgets in executable segments of memory.
    """

    def __init__(self, bv, depth=10, rop=True, jop=False, cop=False, sys=True):
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

        ### !! GadgetSearch should be the only entity allowed to modify this !! ###
        # Dict of gadget mnemonics {addr:str}
        bv.session_data['RopView']['gadget_disasm'] = {}
        # Dict of raw gadgets {addr:bytes}
        bv.session_data['RopView']['gadget_asm'] = {}

        # Load from cache or prepare for search
        self.__control_insn = ()
        if rop:
            if (bv.session_data['RopView']['cache']['rop_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'rop'
                run_progress_dialog("Loading ROP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['rop']
        if jop:
            if (bv.session_data['RopView']['cache']['jop_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'jop'
                run_progress_dialog("Loading JOP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['jop']
        if cop:
            if (bv.session_data['RopView']['cache']['cop_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'cop'
                run_progress_dialog("Loading COP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['cop']
        if sys:
            if (bv.session_data['RopView']['cache']['sys_disasm'] != {}) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'sys'
                run_progress_dialog("Loading SYS cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['sys']

        # Save depth
        bv.session_data['RopView']['depth'] = depth

        # Start gadget search, return success
        bv.session_data['RopView']['loading_canceled'] = not run_progress_dialog("Loading gadgets",True,self.loadGadgets)

    def loadGadgets(self,update):
        # Capstone instance used for disassembly
        md = Cs(capstone_arch[self.__bv.arch.name], bitmode(self.__bv.arch.name))

        # update
        curr = self.__bv.start
        last_iter = 0
        full = (self.__bv.end-self.__bv.start) * len(self.__control_insn)

        for ctrl in self.__control_insn:
            # Used for progress iter
            last_iter +=1

            curr_site = self.__bv.start

            while curr_site is not None:
                # Find potential gadget site
                curr_site = self.__bv.find_next_data(curr_site,ctrl[0])

                if curr_site is None:
                    break
                else:
                    curr_site -= (arch[self.__bv.arch.name]['alignment']-len(ctrl[0]))

                # Saved to increase after depth search
                save = curr_site

                # Progress bar
                curr = save+(self.__bv.end*last_iter)
                if update(curr,full) == False:
                    self.__bv.session_data['RopView']['gadget_disasm'] = {}
                    self.__bv.session_data['RopView']['gadget_asm'] = {}
                    fflush(self.__bv)
                    return False

                # Confirm the gadget site contains the current control instruction
                if re.match(ctrl[2],self.__bv.read(curr_site,ctrl[1])) is not None:
                    for i in range(0,self.depth):
                        if not self.__bv.get_segment_at(curr_site).executable:
                            break
                        else:
                            index = i*arch[self.__bv.arch.name]['alignment']
                            curr_site = save-index
                            insn = self.__bv.read(curr_site,index+ctrl[1])
                            disasm = ''
                            for val in md.disasm(insn,0x1000):
                                disasm += val.mnemonic + ' ' + val.op_str + ' ; '
                            disasm = disasm.replace('  ',' ')

                            # Check blacklisted interrupts
                            contains_block = False
                            for block in arch[self.__bv.arch.name]['blacklist']:
                                if block in disasm:
                                    contains_block = True
                                    break
                            if contains_block:
                                break

                            # Double gadget check
                            occured = 0
                            for mnemonic in gadgets[self.__bv.arch.name]['mnemonics']:
                                matches = len(re.findall(mnemonic,disasm))
                                if matches > 0:
                                    occured += matches
                            if occured > 1:
                                continue
                            
                            # Broken gadget check
                            if disasm == '' or disasm == ' ' or ctrl[3] not in disasm.split(';')[-2]:
                                continue

                            # Cache (cache should contain ALL gadget sites) (ive heard .update(tuple) is faster than .update(dict))
                            if ctrl in gadgets[self.__bv.arch.name]['rop']:
                                self.__bv.session_data['RopView']['cache']['rop_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['rop_asm'].update([(curr_site, insn)])
                            elif ctrl in gadgets[self.__bv.arch.name]['jop']:
                                self.__bv.session_data['RopView']['cache']['jop_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['jop_asm'].update([(curr_site, insn)])
                            elif ctrl in gadgets[self.__bv.arch.name]['cop']:
                                self.__bv.session_data['RopView']['cache']['cop_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['cop_asm'].update([(curr_site, insn)])
                            elif ctrl in gadgets[self.__bv.arch.name]['sys']:
                                self.__bv.session_data['RopView']['cache']['sys_disasm'].update([(curr_site, disasm)])
                                self.__bv.session_data['RopView']['cache']['sys_asm'].update([(curr_site, insn)])
                            
                            # All checks passed, save to pool
                            self.__bv.session_data['RopView']['gadget_disasm'].update([(curr_site, disasm)])
                            self.__bv.session_data['RopView']['gadget_asm'].update([(curr_site, insn)])

                # Next address for search
                curr_site = save+arch[self.__bv.arch.name]['alignment']
        
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
        disasm_key = self.__cache+"_disasm"
        asm_key = self.__cache+"_asm"
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