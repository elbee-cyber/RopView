from .constants import *
from unicorn import *
import struct
from binaryninja import log_info

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

    def __init__(self, bv, addr, gadget_str, gadget_pool_raw, gadget_pool):
        '''
        Sets up new analysis context
        :param bv_arch: A string representing the project arch derived via the Binja api used to resolve constants
        :param addr: The address of the gadget to analyze (-1 will result in address resolving using gadget_str)
        :param gadget_str: The mnemonic of the gadget to analyze (used to resolve address if addr==-1)
        :param gadget_pool_raw: The current gadget pool for bytes ({addr:bytes})
        :param gadget_pool: The current gadget pool for mnemonics ({addr:str})
        '''

        # Likely called from an error handler (remaining gadget), resolve addr of sub-gadget
        if addr == -1:
            addr = self.resolve(gadget_str,gadget_pool)

        self.addr = addr
        self.gadget_str = gadget_str
        self.data = gadget_pool_raw[addr]
        self.bv_arch = bv.arch.name
        self.bv = bv
        self.instructions = gadget_str.split(';')
        self.bm = int(arch[self.bv_arch]['bitmode']/8)
        self.registers = arch[self.bv_arch]['registers']
        self.prestate = {}
        self.prestate_exclude = []
        self.end_state = {}
        index = 0
        for reg in self.registers:
            if reg in gadget_str:
                if 'sp' in reg:
                    self.prestate[reg] = 0x2100
                else:
                    reg = reg.replace(' ','')
                    self.prestate[reg] = 0
                    self.registers[index] = reg
            index += 1
        self.err = 0
        self.err_data = None

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
            if reg in self.gadget_str:
                reg = reg.replace(' ','')
                self.prestate[reg] = context[reg]
            if reg in list(arch[self.bv_arch]['loweraccess'].keys()):
                for lower in arch[self.bv_arch]['loweraccess'][reg]:
                    if lower in self.gadget_str:
                        self.prestate[reg] = context[reg]
                        if reg not in self.gadget_str:
                            self.prestate_exclude.append(reg)

    def resolve(self, gadget_str, gadget_pool):
        '''
        Resolves the address of a gadget from a gadget_str. Used by case handling to resolve sub-gadgets.
        :param gadget_str: The gadget string
        :param gadget_pool: The gadget pool to resolve from
        '''
        return list(gadget_pool.keys())[list(gadget_pool.values()).index(gadget_str)]

    def analyze(self):
        '''
        Used to initialize analysis, call analysis and perform static analysis on current context.
        :return: Returns a tuple containing the step-by-step context results, an error code and error data
        '''
        # Gadget already analyzed, return cache value
        if self.gadget_str in self.emulated:
            self.end_state = self.saved_end_states[self.gadget_str]
            self.err = self.saved_fails[self.gadget_str]
            return (self.emulated[self.gadget_str], self.err, self.err_data)

        # Emulation step counter
        self.count = 0

        # A list of dictionaries denoting context at each emulation step
        self.results = []

        # Instruction count
        self.inst_cnt = self.gadget_str.count(';')

        # Cyclic data copied onto the emu stack based on gadget length
        self.cyclic_data = self.cyclic(self.inst_cnt*2)
    
        self.analyze_gadget()

        # Find cyclic registers
        i = 0
        for state in self.results:
            for key,value in state.items():
                if value in self.cyclic_data[1]:
                    self.results[i][key] = 'Full control'
            i += 1
        # Save in cache
        if self.gadget_str not in self.emulated:
            self.emulated[self.gadget_str] = self.results.copy()

        self.build_endstate()
        
        # Save fail
        self.saved_fails[self.gadget_str] = self.err

        return (self.results, self.err, self.err_data)

    def analyze_gadget(self):
        '''
        Responsible for analysis and step-by-step context saving using unicorn engine emulation
        '''

        mu = Uc(uarch[self.bv_arch],ubitmode[self.bv_arch])

        # Set registers according to prestate
        for key,value in self.prestate.items():
            mu.reg_write(arch[self.bv_arch]['uregs'][key],value)

        # Redefine prestate registers for correct display (incase a lower access register was used)
        for key,value in self.prestate.items():
            self.prestate[key] = mu.reg_read(arch[self.bv_arch]['uregs'][key])

        # Map memory, copy gadget to text and set up stack
        mu.mem_map(0x1000,4096*2)
        mu.mem_write(0x1000,self.data)
        mu.mem_write(0x2100,self.cyclic_data[0])
        mu.reg_write(arch[self.bv_arch]['uregs']['sp'],0x2100)

        # Step hook to update results with step context
        handle = mu.hook_add(UC_HOOK_CODE, self.analyze_step)
        try:
            mu.emu_start(0x1000,0x1000+len(self.data),count=self.inst_cnt-1)
            self.analyze_step(mu,0,0,0)
        except UcError as e:
            # Minimal case handling is done here because of issues /w unicorn and recursion, caller handles cases.
            mu.hook_del(handle)
            mu.emu_stop()
            if e.errno == UC_ERR_READ_UNMAPPED:
                # Case 1: Stack pivot (UC_ERR_READ_UNMAPPED and SP in last_executed)
                for sp in arch[self.bv_arch]['sp']:
                    if sp in self.last_executed[1]:
                        try:
                            self.results[-1][sp] = 'Stack pivot'
                        except IndexError:
                            self.results.append({sp:'Stack pivot'})
                        index = self.instructions.index(self.last_executed[1])
                        remaining = (';'.join(self.instructions[index+1:-1])+'; ')[1:]
                        self.err = GA_ERR_STACKPIVOT
                        self.err_data = remaining
            if e.errno == UC_ERR_READ_UNMAPPED or e.errno == UC_ERR_WRITE_UNMAPPED or e.errno == UC_ERR_FETCH_UNMAPPED:
                # Case 3: Fetch from PC
                for pc in arch[self.bv_arch]['pc']:
                    if pc in self.last_executed[1] and self.err == 0:
                        self.err = GA_ERR_DEREF_PC
                        try:
                            self.results[-1][pc] = 'Cannot accurately analyze fetches based on PC'
                        except IndexError:
                            self.results.append({pc:'Cannot accurately analyze fetches based on PC'})
                
                derefs = ([-1], [-1])
                if self.err == 0:
                    derefs = self.parseDerference(self.last_executed[1],mu)

                # Case 2: Null deref
                if 0 in derefs[0] and self.err == 0:
                    self.err = GA_NULL_DEREF
                    for reg in derefs[1]:
                        try:
                            self.results[-1][reg] = 'Null dereference'
                        except IndexError:
                            self.results.append({reg:'Null dereference'})

                sizes = {'byte':1,'word':2,'dword':4,'qword':8}
                log_info(derefs, "RopView - derefs")
                # Case 3: Read
                if self.err == 0 and e.errno == UC_ERR_READ_UNMAPPED:                       
                    # Statically mapped check
                    pass

                if self.err == 0 and e.errno == UC_ERR_WRITE_UNMAPPED:
                    # Statically mapped and writable check
                    pass

                log_info("Unimplemented handling: "+str(e),"Untitled RopView")
        mu.mem_unmap(0x1000,4096*2)

    def bvResolve(self, addr, size):
        boundary = (addr & ~(4096-1))
        size = addr-boundary+size
        return (boundary,size)

    def parseDerference(self, inst, mu):
        '''
        Parses instruction string for dereferences using specified unicorn context
        :param inst: The instruction that caused that could not be fetched
        :param mu: Unicorn context
        :return: Returns a tuple of (dereferenced locations, dereferenced registers)
        '''
        derefs = []
        regs = []
        if 'x86' in self.bv_arch:
            for index, token in enumerate(inst):
                if token == '[':
                    start = index
                    end = index+1
                    curr = inst[end]
                    while curr != ']':
                        end += 1
                        curr = inst[end]
                    location = inst[start+1:end]
                    for reg in self.registers:
                        if reg in location:
                            location = location.replace(reg, str(mu.reg_read(arch[self.bv_arch]['uregs'][reg])))
                            regs.append(reg)
                    location = eval(location)
                    if location < 0:
                        location = location + (1 << 32)
                    derefs.append(location)
        return (derefs, regs)

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

    def build_endstate(self):
        '''
        Builds an end state based on the last recorded value for each register
        '''
        for state in self.results:
            for reg in list(state.keys()):
                self.end_state[reg] = state[reg]
        self.saved_end_states[self.gadget_str] = self.end_state.copy()
    
    def analyze_step(self, mu, address, size, data):
        '''
        Analyzes emulation step. Behaviour is as follows:
        - Save current instruction being analyzed in case error triggers case
        - Handling of instructions performing stack manipulation
        - Save state of instruction and append to results, states include modified registers and values
        :param mu: Unicorn object
        :param address: Address of currently executing instruction in unicorn emulation
        :param size: Size of currently executing instruction in unicorn emulation
        :param data: Unused user-supplied data to hook
        '''
        # Saved for case handling
        self.last_executed = (address,self.instructions[self.count-1])

        # No cycle, no effects, skip first call
        if self.count == 0:
            self.last_executed = (address,self.instructions[0])
            self.count += 1
            return
        
        # Current step state (results[count] = curr_state)
        curr_state = {}
        for reg in self.registers:
            if reg in self.instructions[self.count-1]:
                # Check if instruction modifies stack
                for sp in arch[self.bv_arch]['sp']:
                    if sp == reg:
                        sp_value = mu.reg_read(arch[self.bv_arch]['uregs'][reg])
                        distance = 0x2100 - sp_value
                        # SP contains stack data (full control)
                        if sp_value in self.cyclic_data[1]:
                            curr_state[reg] = 'Stack pivot'
                        # Stack grown or shrunk
                        elif distance < 0:
                            curr_state[reg] = sp+'+'+hex(abs(distance))+' ('+hex(sp_value)+')'
                        else:
                            curr_state[reg] = sp+'-'+hex(abs(distance))+' ('+hex(sp_value)+')'
                        break
                    else:
                        # Save register value to step context
                        curr_state[reg] = mu.reg_read(arch[self.bv_arch]['uregs'][reg])
        self.results.append(curr_state)
        self.count += 1
