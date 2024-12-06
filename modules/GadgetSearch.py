from .constants import *
import re
from binaryninja import *
from .cache import cache

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
        self.cache = cache(bv)

        ### !! GadgetSearch should be the only entity allowed to modify this !! ###
        self.cache.gcache.flush()

        # Load from cache or prepare for search
        self.__control_insn = ()
        if rop:
            if (not self.cache.rop_cache.isEmpty()) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'rop'
                run_progress_dialog("Loading ROP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['rop']
        if jop:
            if (not self.cache.jop_cache.isEmpty()) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'jop'
                run_progress_dialog("Loading JOP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['jop']
        if cop:
            if (not self.cache.cop_cache.isEmpty()) and (depth == bv.session_data['RopView']['depth']):
                self.__cache = 'cop'
                run_progress_dialog("Loading COP cache",False,self.load_from_cache)
            else:
                self.__control_insn += gadgets[bv.arch.name]['cop']
        if sys:
            if (not self.cache.sys_cache.isEmpty()) and (depth == bv.session_data['RopView']['depth']):
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

        # temporary
        rop_disasm = {}
        rop_asm = {}
        jop_disasm = {}
        jop_asm = {}
        cop_disasm = {}
        cop_asm = {}
        sys_disasm = {}
        sys_asm = {}
        g_disasm = {}
        g_asm = {}

        for ctrl in self.__control_insn:
            # Used for progress iter
            last_iter +=1

            curr_site = self.__bv.start

            while curr_site != None:
                # Find potential gadget site
                curr_site = self.__bv.find_next_data(curr_site,ctrl[0])
                if curr_site is None:
                    break

                # Saved to increase after depth search
                save = curr_site

                # Progress bar
                curr = save+(self.__bv.end*last_iter)
                if update(curr,full) == False:
                    self.cache.fullflush()
                    return False

                # Confirm the gadget site contains the current control instruction
                if re.match(ctrl[2],self.__bv.read(curr_site,ctrl[1])) != None:
                    for i in range(0,self.depth):
                        if not self.__bv.get_segment_at(curr_site).executable:
                            break
                        else:
                            curr_site = save-i

                            insn = self.__bv.read(curr_site,i+ctrl[1])
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
                                continue

                            # Double gadget check
                            occured = 0
                            for mnemonic in gadgets[self.__bv.arch.name]['mnemonics']:
                                if mnemonic in disasm:
                                    occured += disasm.count(mnemonic)
                            if occured > 1:
                                break
                            
                            # Broken gadget check
                            if disasm == '' or disasm == ' ' or ctrl[3] not in disasm.split(';')[-2]:
                                continue

                            # save all gadgets for cache commit later (only make large stores)
                            if ctrl in gadgets[self.__bv.arch.name]['rop']:
                                rop_disasm.update({curr_site:disasm})
                                rop_asm.update({curr_site:insn})
                            elif ctrl in gadgets[self.__bv.arch.name]['jop']:
                                jop_disasm.update({curr_site:disasm})
                                jop_asm.update({curr_site:insn})
                            elif ctrl in gadgets[self.__bv.arch.name]['cop']:
                                cop_disasm.update({curr_site:disasm})
                                cop_asm.update({curr_site:insn})
                            elif ctrl in gadgets[self.__bv.arch.name]['sys']:
                                sys_disasm.update({curr_site:disasm})
                                sys_asm.update({curr_site:insn})
                            
                            g_disasm.update({curr_site:disasm})
                            g_asm.update({curr_site:insn})

                # Next address for search
                curr_site = save+1
        # store final pools (make large stores only)
        self.cache.rop_cache.store_disasm(rop_disasm)
        self.cache.rop_cache.store_asm(rop_asm)
        self.cache.jop_cache.store_disasm(jop_disasm)
        self.cache.jop_cache.store_asm(jop_asm)
        self.cache.cop_cache.store_disasm(cop_disasm)
        self.cache.cop_cache.store_asm(cop_asm)
        self.cache.sys_cache.store_disasm(sys_disasm)
        self.cache.sys_cache.store_asm(sys_asm)
        self.cache.gcache.store_disasm(g_disasm)
        self.cache.gcache.store_asm(g_asm)
        return True

    def load_from_cache(self, update):
        caches = {"rop":self.cache.rop_cache,"jop":self.cache.jop_cache,"cop":self.cache.cop_cache,"sys":self.cache.sys_cache}
        disasm_cache = caches[self.__cache].load_disasm()
        asm_cache = caches[self.__cache].load_asm()
        
        # For progress bar
        iteration = 0
        full = len(disasm_cache)

        for addr,value in asm_cache.items():
            update(iteration,full)
            self.cache.gcache.store_asm({addr:value})
            self.cache.gcache.store_disasm({addr:disasm_cache[addr]})
            iteration += 1
