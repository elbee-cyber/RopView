from .constants import *
from unicorn import *
from unicorn.unicorn_const import *
import struct

class GadgetAnalysis:
    '''
    Responsible for performing gadget analysis and resolving analysis results.
    '''

    # Cache of already emulated instructions
    emulated = {}

    # Last prestate used
    last_prestate = {}

    # Cache of end states (will be used for searching)
    saved_end_states = {}

    # Cache of gadgets that fail
    saved_fails = {}

    def __init__(self, bv, addr, gadget_str):
        '''
        Sets up new analysis context
        :param bv: A binaryview object
        :param addr: The address of the gadget to analyze
        :param gadget_str: The mnemonic of the gadget to analyze (used to resolve address if addr==-1)
        '''

        self.addr = addr
        self.gadget_str = gadget_str
        self.bv = bv

        # The gadget asm
        if addr not in bv.session_data['RopView']['gadget_asm']:
            return
        self._gadget_Raw = bv.session_data['RopView']['gadget_asm'][addr]

        # Gadget str split by instruction
        self.instructions = gadget_str.split(';')
        self.instructions.pop()

        # Architecture, bitmode and corresponding registers
        self._arch = bv.arch.name
        self.bm = int(arch[self._arch]['bitmode']/8)
        self.registers = arch[self._arch]['registers']

        # Empty end state
        self.end_state = {}

        # Empty prestate (registers initialized to 0)
        self.prestate = {}

        # If mappings are added, remember to clear this for new gadget context
        self.prestate[arch[self._arch]['sp'][0]] = 0x2100
        for reg in self.registers:
            self.prestate[reg] = 0

        # Error
        self.err = 0

    def set_prestate(self, context):
        '''
        Configures the prestate register values before emulation. A user can define the values of registers before analysis runs.
        :param context: A dictionary mapping of register values ({reg:value})
        '''
        # Empty effect caches if prestate changed
        if context != self.last_prestate:
            self.emulated = {}
            self.saved_end_states = {}
            self.saved_fails = {}
            self.last_prestate = context
        for reg in list(context.keys()):
            if reg == 'empty':
                continue
            self.prestate[reg] = context[reg]

    def analyze(self):
        '''
        Used to initialize analysis and emulation context.
        :return: (step analysis, err)
        '''

        # Gadget already analyzed, return cache value
        if self.gadget_str in self.emulated:
            self.end_state = self.saved_end_states[self.gadget_str]
            self.err = self.saved_fails[self.gadget_str]
            return (self.emulated[self.gadget_str], self.err)

        # A list of dictionaries denoting context at each step
        self.results = []

        # Instruction count
        self.inst_cnt = self.gadget_str.count(';')

        # Cyclic data copied onto the emu stack based on gadget length
        self.__cyclic_data = self.cyclic(self.inst_cnt*(self.gadget_str.count(',')+1)*2)

        # Resolved mappings saved here
        self.derefs = []

        # Denotes last invalid memory fetch, used by viewtype for display
        self.last_access = []

        # Setup emulator context for analysis
        mu = Uc(uarch[self._arch], ubitmode[self._arch])
        self.uc = mu

        # Configure register context to prestate
        for reg, value in self.prestate.items():
            mu.reg_write(arch[self._arch]['uregs'][reg],value)

        # gadget .text
        mu.mem_map(0x1000,0x1000)
        mu.mem_write(0x1000,self._gadget_Raw)
        mu.mem_protect(0x1000, 0x1000, (UC_PROT_READ+UC_PROT_EXEC))

        # stack
        stack_size = 0x1000
        while True:
            try:
                mu.mem_map(0x2000,stack_size)
                mu.mem_write(0x2100,self.__cyclic_data[0])
                mu.mem_protect(0x2000,stack_size,(UC_PROT_READ+UC_PROT_WRITE))
                break
            except:
                mu.mem_unmap(0x2000,stack_size)
                stack_size *= 2
        mu.reg_write(arch[self._arch]['uregs']['sp'],0x2100)

        # Used recursively for realtime memory resolving (binary->emulation)
        mappings = []

        # The full register context from the previous step
        self.last_state = {}

        # The disasm from the previous step
        self.last_inst = ''

        # Registers that the gadget effects
        self.clobbered = []

        # A dictionary full of clobbered registers and their prestate values
        self.used_regs = {}

        # Holds the last non-corrupted stack pointer value
        self.__last_addr = 0x2100

        # Holds the last pc loc to detect branching
        self.__last_pc = 0x1000

        # Add hook for step analysis
        ch = mu.hook_add(UC_HOOK_CODE, self.analyze_step)

        # Add hook to handle interrupts/syscalls
        hi = mu.hook_add(UC_HOOK_INTR, self.__hook_intr)

        # Emulate and analyze
        self._emulate(mu, mappings)

        # Get the final register context
        ## Should this only be set to RISC architectures?
        context = {}
        for reg in self.registers:
            context[reg] = mu.reg_read(arch[self._arch]['uregs'][reg])
        
        diff = self.reg_diff(context)

        # Hook del
        mu.hook_del(ch)
        mu.hook_del(hi)

        # Unmap all unicorn regions
        self.uc_release(mu)

        # Find and rename cyclic registers
        i = 0
        for state in self.results:
            for key,value in state.items():
                if value in self.__cyclic_data[1]:
                    self.results[i][key] = 'Full control (stack) (offset {})'.format(str(int(self.__cyclic_data[1].index(value)*self.bm)))
            i += 1
        for key,value in diff.items():
            if value in self.__cyclic_data[1]:
                diff[key] = 'Full control (stack) (offset {})'.format(str(int(self.__cyclic_data[1].index(value)*self.bm)))

        # Save err_desc as step value for halted instruction
        if self.err != 0:
            self.results.append({'Analysis halted':err_desc[self.err]})
        else:
            # Save diffed registers to clobbered
            for reg in list(diff.keys()):
                if reg not in self.clobbered:
                    self.clobbered.append(reg)
            self.results.append(diff)
        
        # Build used_regs based off of clobbered registers and their prestate values
        for reg in self.clobbered:
            self.used_regs[reg] = self.prestate[reg]

        # Save in cache
        if self.gadget_str not in self.emulated:
            self.emulated[self.gadget_str] = self.results.copy()
        self.build_endstate()

        # Save fail
        self.saved_fails[self.gadget_str] = self.err

        return (self.results, self.err)

    def diagnose(self, access, addr, mappings):
        '''
        Called by the invalid memory hook for err diagnosis.
        :param access: The uc error constant
        :param addr: The address uc attempted to access
        :param mappings: A list of future mappings to realtime resolve
        :return: A GA error constant
        '''
        # Check if the address accessed is mapped in the binary
        segment = self.bv.get_segment_at(addr)
        if addr == 0:
            mappings.insert(0,-1)
            return GA_ERR_NULL # Null dereference (No recovery)
        if addr == self.last_access[0] and len(self.derefs) > 12:
            mappings.insert(0,-1)
            return GA_ERR_RECURSION
        if access == UC_MEM_WRITE:
            mappings.insert(0,-1)
            return GA_ERR_WRITE # Invalid write of % at % (No recovery)
        if access == UC_MEM_READ:
            mappings.insert(0,-1)
            return GA_ERR_READ # Invalid read of % at % (No recovery)
        if access == UC_MEM_FETCH:
            mappings.insert(0,-1)
            return GA_ERR_FETCH # Invalid execution at % (No recovery)
        if access == UC_MEM_READ_UNMAPPED:
            if segment is None:
                mappings.insert(0,-1)
                return GA_ERR_READ_UNMAPPED # Attempted to read unmapped memory at % (Speculative) (No recovery)'
            if self.err == GA_ERR_READ_UNRESOLVED:
                mappings.insert(0,-1)
            return GA_ERR_READ_UNRESOLVED # Attempted to read unmapped memory at % (Realtime resolve)
        if access == UC_MEM_WRITE_UNMAPPED:
            if segment is None:
                mappings.insert(0,-1)
                return GA_ERR_WRITE_UNMAPPED # Attempted to write to unmapped memory (% to %) (Speculative) (No recovery)
            if self.err == GA_ERR_WRITE_UNRESOLVED:
                mappings.insert(0,-1)
            return GA_ERR_WRITE_UNRESOLVED # Attempted to write unmapped memory at % (Realtime resolve)
        if access == UC_MEM_FETCH_UNMAPPED:
            mappings.insert(0,-1)
            return GA_ERR_FETCH_UNMAPPED # Attempted to fetch unmapped memory at % (No recovery)
        if access == UC_MEM_WRITE_PROT:
            mappings.insert(0,-1)
            return GA_ERR_WRITE_PROT # Attempted write to non-writable memory (% to %) (No recovery)
        if access == UC_MEM_FETCH_PROT:
            mappings.insert(0,-1)
            return GA_ERR_FETCH_PROT # Attempted executing non-executable memory (%) (No recovery)
        if access == UC_MEM_READ_PROT:
            mappings.insert(0,-1)
            return GA_ERR_READ_PROT # Attempted reading non-readable memory (%) (No recovery)\
        mappings.insert(0,-1)
        return GA_ERR_UNKNOWN

    def _emulate(self, mu, mappings, start=0x1000):
        '''
        Respponsible for gadget emulation, hooks/case handling and realtime resolving.
        :param mu: The configured unicorn object
        :param mappings: A list of mappings to resolve
        :param start: Where to start the emulation (default is the beginning of the gadget)
        '''
        # Used in step hook to determine if the current code is the first instruction
        self.__base_addr = start

        # If -1 in mappings, diagnosis determined an unrecoverable error
        if -1 in mappings:
            return self.err
        
        # Resolve all mappings (assume valid and resolvable)
        for map in mappings:
            self._add_context(mu, map)
            self.derefs.append(mappings.pop(mappings.index(map)))
        
        # Add hook to catch memory violations, diagnose and add future mappings
        h = mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid, mappings)

        try:
            # Attempt emulation
            mu.emu_start(start,0x1000+len(self._gadget_Raw),count=self.inst_cnt)
            mu.hook_del(h)
            if self.err == GA_ERR_INTR:
                self.err = GA_ERR_INTR
            else:
                self.err = 0
            return 0
        except UcError as e:
            # A memory violation occured
            mu.hook_del(h)

            if self.err == GA_ERR_INTR:
                mappings.insert(0,-1)
                return 0

            # If the last instruction executed was the last instruction to execute, ignore
            if self.last_inst in self.instructions[-1]:
                self.err = 0
                return 0

            # If the stack was corrupted, reassign sp, move start and emulate again
            if self.stackCorrupt(mu):
                sp = arch[self._arch]['uregs'][arch[self._arch]['sp'][0]]
                mu.reg_write(sp,self.__last_addr)
                mappings = []
                self.__base_addr = start+len(self.last_asm)
                return self._emulate(mu,mappings,start+len(self.last_asm))

            # Emulate again (the hook should have populated mappings)
            return self._emulate(mu,mappings)

    def uc_release(self, uc):
        '''
        Unmaps all regions in a unicorn emulation
        :param uc: Unicorn object
        '''
        for region in uc.mem_regions():
            uc.mem_unmap(region[0],((region[1]-region[0])+1))

    def __hook_intr(self, uc, intro, foobar):
        self.err = GA_ERR_INTR
        self.uc_release(uc)
        uc.emu_stop()

    def hook_mem_invalid(self, uc, access, address, size, value, mappings):
        '''
        Hook used to catch memory violations.
        Adds to mapping and diagnoses appropiately
        :param uc: Unicorn object
        :param access: The UC error code
        :param address: The value that access was attempted on
        :param value: The value that was attempted for access
        :param mappings: The mappings containing addresses to resolve
        '''
        # Add address to mappings (a -1 will be inserted at [0] if unrecoverable)
        mappings.append(address)

        # Save last access for viewtype display
        if address in self.__cyclic_data[1]:
            self.last_access = ['Stack data',self.__cyclic_data[1].index(address)*self.bm]
        else:
            self.last_access = [address,value]

        # Diagnose
        self.err = self.diagnose(access, address, mappings)

    def cyclic(self, n):
        '''
        Responsible for building cyclic date based on the bitmode and requested size
        :param n: Size of cyclic data
        :return: A tuple of the packed and unpacked cyclic data for easy translation for caller
        '''
        base = int(str(ord('A'))*self.bm,16)
        unpacked = []
        packed = b''
        for i in range(0,n):
            unpacked.append(base)
            base += 1
        if self.bm == 8:
            for p in unpacked:
                packed = packed + struct.pack('l',p)
        else:
            for p in unpacked:
                packed = packed + struct.pack('i',p)
        return (packed,unpacked)

    def _add_context(self, uc, addr):
        '''
        Adds a mapping that encompasses addr to the unicorn context
        Sets the mappings corresponding protections and data according to its location in the binary
        :param uc: Unicorn object
        :param addr: Address to map
        '''
        # Get the nearest boundary and size for mapping addr
        to_map = self._get_boundary_info(addr)

        # Try/catch incase memory is already mapped
        try:
            uc.mem_map(to_map[0], to_map[1])
        except UcError:
            return

        # Resolve segment data
        uc.mem_write(to_map[0], self.bv.read(to_map[0],to_map[1]))

        # Resolve segment protections
        seg = self.bv.get_segment_at(addr)
        prot = 0
        if seg.readable:
            prot += UC_PROT_READ
        if seg.writable:
            prot += UC_PROT_WRITE
        if seg.executable:
            prot += UC_PROT_EXEC
        uc.mem_protect(to_map[0], to_map[1], prot)

    def _get_boundary_info(self, addr):
        '''
        Gets the nearest aligned virtual page boundary for the corresponding address
        Gets the size that encapsulated the address from the given page boundary
        :param addr: The address to map
        :return: (start, size)
        '''
        boundary = (addr & ~(4096-1))
        size = ((addr+10000) & ~(4096-1))-boundary
        return (boundary, size)

    def build_endstate(self):
        '''
        Builds an end state based on the last recorded value for each register
        '''
        for state in self.results:
            for reg in list(state.keys()):
                self.end_state[reg] = state[reg]
        self.saved_end_states[self.gadget_str] = self.end_state.copy()
    
    def reg_diff(self,context):
        '''
        Diffs the clobbered register values between current and last step of execution
        :param context: The current register context
        :return: Returns a context containing only clobbered registers
        '''
        diff = {}
        for reg,val in context.items():
            if reg not in self.last_state:
                continue
            if context[reg] != self.last_state[reg]:
                diff[reg] = context[reg]
        remove = []
        for reg,val in diff.items():
            low = arch[self._arch]['loweraccess']
            if reg in low:
                for rl in low[reg]:
                    if rl in diff:
                        remove.append(rl)
        for rl in remove:
            diff.pop(rl)
        self.last_state = context
        return diff

    def stackCorrupt(self,mu):
        '''
        Checks for stack pointer corruption
        Updates __last_addr if sp is not corrupt
        :param mu: Unicorn object
        :return: Returns T/F
        '''
        sp = arch[self._arch]['uregs'][arch[self._arch]['sp'][0]]
        stack_val = mu.reg_read(sp)
        if stack_val in self.__cyclic_data[1]:
            return True
        self.__last_addr = stack_val
        return False

    def analyze_step(self, mu, address, size, data):
        '''
        This hook is executed BEFORE its corresponding instruction
        Step analysis and diffing is done here
        :param mu: Unicorn object
        :param address: The address of PC
        :param size: The size of the current instruction
        :param data: Unused user data
        '''
        disasm = ''
        context = {}

        # Check if sp is corrupt
        corrupt = self.stackCorrupt(mu)

        # Current asm
        asm = mu.mem_read(address,size)

        # Current disasm
        md = Cs(capstone_arch[self._arch], bitmode(self._arch))
        for i in md.disasm(asm, 0x1000):
            disasm += i.mnemonic+' '+i.op_str

        # Save last disasm, asm
        self.last_inst = disasm
        self.last_asm = asm

        # Build a context based on every register
        for reg in self.registers:
            context[reg] = mu.reg_read(arch[self._arch]['uregs'][reg])

        # If the first instruction of the gadget is being called, set last_state for reg diffing and skip it
        if address == self.__base_addr:
            self.last_state = context
            return

        # Diff full, current context to last context
        diff = self.reg_diff(context)

        # Save diffed registers to clobbered
        for reg in list(diff.keys()):
            if reg not in self.clobbered:
                self.clobbered.append(reg)

        # Check if branch occured
        if abs(address - self.__last_pc) > 16:
            diff['Control flow changed'] = 'Branch to '+hex(address)
        self.__last_pc = address

        # If last execution cycle an unresolved write/write (recoverable) occured, add the value of the deref to the diff
        if self.err == GA_ERR_WRITE_UNRESOLVED and len(self.derefs) > 0:
            self.err = 0
            diff[hex(self.derefs[-1])] = str(bytes(mu.mem_read(self.derefs[-1],8))) + ' ({})'.format(self.bv.get_sections_at(self.derefs[-1])[0].name)
        if self.err == GA_ERR_READ_UNRESOLVED and len(self.derefs) > 0:
            self.err = 0
            diff['Reads from '+hex(self.derefs[-1])] = str(bytes(mu.mem_read(self.derefs[-1],8))) + ' ({})'.format(self.bv.get_sections_at(self.derefs[-1])[0].name)
        # If the stack pointer is corrupted, add to diff
        if corrupt:
            sp = arch[self._arch]['sp'][0]
            diff[sp] = 'Stack pivot (stack)'
            self.clobbered.append(sp)
        # Update diff for current step
        self.results.append(diff)

    def saveState(self):
        return State(self.results,self.err,self.used_regs,self.instructions,self.prestate,self.last_access,self.end_state)

class State:
    def __init__(self, results, err, used_regs, instructions, prestate, last_access, end_state):
        self.results = results
        self.err = err 
        self.used_regs = used_regs
        self.instructions = instructions
        self.prestate = prestate
        self.last_access = last_access
        self.end_state = end_state