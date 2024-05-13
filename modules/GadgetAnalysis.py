from binaryninja import *
from .constants import *
from unicorn import *
import struct
from keystone import *

class GadgetAnalysis:

    emulated = {}
    instructions = []
    count = 0 # DECLARE LOCALLY
    registers = []

    saved_end_states = {}
    end_state = {}

    cache = {
        'stack_pivots':{},
        'full_control':{},
        'write_at':{}
    }

    def __init__(self,bv_arch,addr,gadget_str,gadget_pool_raw,gadget_pool):
        if addr == -1:
            addr = self.resolve(gadget_str,gadget_pool)

        self.addr = addr
        self.gadget_str = gadget_str
        self.data = gadget_pool_raw[addr]
        self.bv_arch = bv_arch
        self.instructions = gadget_str.split(';')
        self.bm = int(arch[self.bv_arch]['bitmode']/8)
        self.registers = arch[self.bv_arch]['registers']
        self.prestate = {}
        self.end_state = {}
        for reg in self.registers:
            if reg in gadget_str:
                self.prestate[reg] = 0
        self.err = 0
        self.err_data = None

    def set_prestate(self,context):
        for reg in list(context.keys()):
            if reg in self.gadget_str:
                self.prestate[reg] = context[reg]

    def resolve(self,gadget_str,gadget_pool):
        return list(gadget_pool.keys())[list(gadget_pool.values()).index(gadget_str)]

    def analyze(self):
        if self.gadget_str in self.emulated:
            self.end_state = self.saved_end_states[self.gadget_str]
            return (self.emulated[self.gadget_str], self.err, self.err_data)
        self.count = 0
        self.results = []
        self.inst_cnt = self.gadget_str.count(';')
        self.cyclic_data = self.cyclic(self.inst_cnt+1)
        self.analyze_gadget()

        # Find cyclic registers
        i = 0
        for state in self.results:
            for key,value in state.items():
                if value in self.cyclic_data[1]:
                    if self.addr not in self.cache['full_control']:
                        self.cache[self.addr] = self.gadget_str
                    self.results[i][key] = 'Full control'
                    self.end_state[key] = 'Full control'
            i += 1
        self.saved_end_states[self.gadget_str] = self.end_state
        # Save in cache
        if self.gadget_str not in self.emulated:
            self.emulated[self.gadget_str] = self.results.copy()

        return (self.results, self.err, self.err_data)

    def analyze_gadget(self):
        self.count = 0
        mu = Uc(uarch[self.bv_arch],ubitmode[self.bv_arch])

        # Set prestate
        for key,value in self.prestate.items():
            mu.reg_write(arch[self.bv_arch]['uregs'][key],value)

        # Mapping
        mu.mem_map(0x1000,4096)
        mu.mem_map(0x2000,4096)

        # text
        mu.mem_write(0x1000,b'\x00'*4096)
        mu.mem_write(0x1000,self.data)
        
        # stack
        mu.mem_write(0x2000,b'\x00'*4096)
        mu.mem_write(0x2100,self.cyclic_data[0])
        mu.reg_write(arch[self.bv_arch]['uregs']['sp'],0x2100)

        # Get effects
        handle = mu.hook_add(UC_HOOK_CODE, self.analyze_step)
        try:
            mu.emu_start(0x1000,0x1000+len(self.data),count=self.inst_cnt-1)
            self.analyze_step(mu,0,0,0)
        # Minimal case handling in analysis, let ViewType do it
        except UcError as e:
            mu.hook_del(handle)
            mu.emu_stop()
            if e.errno == UC_ERR_READ_UNMAPPED:
                # Case 2: Stack pivot (UC_ERR_READ_UNMAPPED and SP in last_executed)
                for sp in arch[self.bv_arch]['sp']:
                    if sp in self.last_executed[1]:
                        self.results[-1][sp] = 'Stack pivot'
                        self.end_state[sp] = 'Stack pivot'
                        index = self.instructions.index(self.last_executed[1])
                        remaining = (';'.join(self.instructions[index+1:-1])+'; ')[1:]
                        self.err = GA_ERR_STACKPIVOT
                        self.err_data = remaining
            elif e.errno == UC_ERR_WRITE_UNMAPPED:
                pass
            elif e.errno == UC_ERR_FETCH_UNMAPPED:
                pass
        mu.mem_unmap(0x1000,4096*2)

    def cyclic(self,n):
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
        return [packed,unpacked]
    
    def analyze_step(self, mu, address, size, data):
        self.last_executed = (address,self.instructions[self.count-1])
        stack_insn = False
        if self.count == 0:
            self.count += 1
            return
        curr_state = {}
        for reg in self.registers:
            if reg in self.instructions[self.count-1]:
                for sp in arch[self.bv_arch]['sp']:
                    if sp == reg:
                        stack_insn = True
                        distance = 0x2100 - mu.reg_read(arch[self.bv_arch]['uregs'][reg])
                        if mu.reg_read(arch[self.bv_arch]['uregs'][reg]) in self.cyclic_data[1]:
                            curr_state[reg] = 'Stack pivot'
                            self.end_state[reg] = 'Stack pivot'
                        elif distance < 0:
                            curr_state[reg] = sp+'+'+hex(abs(distance))+' ('+hex(mu.reg_read(arch[self.bv_arch]['uregs'][reg]))+')'
                            self.end_state[reg] = sp+'+'+hex(abs(distance))+' ('+hex(mu.reg_read(arch[self.bv_arch]['uregs'][reg]))+')'
                        else:
                            curr_state[reg] = sp+'-'+hex(abs(distance))+' ('+hex(mu.reg_read(arch[self.bv_arch]['uregs'][reg]))+')'
                            self.end_state[reg] = sp+'-'+hex(abs(distance))+' ('+hex(mu.reg_read(arch[self.bv_arch]['uregs'][reg]))+')'
                if stack_insn:
                    stack_insn = False
                else:
                    curr_state[reg] = mu.reg_read(arch[self.bv_arch]['uregs'][reg])
                    self.end_state[reg] = mu.reg_read(arch[self.bv_arch]['uregs'][reg])
        self.results.append(curr_state)
        self.count += 1
