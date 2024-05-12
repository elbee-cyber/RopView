from binaryninja import *
from .constants import *
from unicorn import *
import struct
from keystone import *

class GadgetAnalysis:

    details = [] # RETURN LOCALLY
    emulated = {}
    instructions = []
    count = 0 # DECLARE LOCALLY
    registers = []

    cache = {
        'stack_pivots':{},
        'full_control':{},
        'write_at':{}
    }

    def __init__(self,addr,gadget_str,bv,gadget_pool_raw):
        self.addr = addr
        self.gadget_str = gadget_str
        self.bv = bv
        self.data = gadget_pool_raw[addr]
        self.bv_arch = bv.arch.name
        self.instructions = gadget_str.split(';')
        self.bm = int(arch[self.bv_arch]['bitmode']/8)
        self.registers = arch[self.bv_arch]['registers']
                
        # T - Stack pivot case
        # F - No stack pivot
        # REDO THIS CHECK SO STACK PIVOTS ARE INSERTED IN ORDER OF GADGET EFFECT AND EXECUTION CONTINUES IF GADGET HAS MORE INSTs
        '''
        pivotExists = False
        eliminate = 0
        self.stack_pointers = arch[self.bv_arch]['sp']
        for sp in self.stack_pointers:
            if sp in gadget_str:
                pivotExists = True
        if pivotExists:
            if addr not in self.cache['stack_pivots']:
                self.cache['stack_pivots'][addr] = gadget_str
            md = Ks(keystone_arch[bv.arch.name], bitmode(bv.arch.name)[1])
            i = 0
            for inst in self.instructions:
                for sp in self.stack_pointers:
                    if sp in inst:
                        self.details.append({sp:'Stack pivot'})
                        self.stack_pivots.append(md.asm(bytes(inst,'utf8'), as_bytes=True)[0])
                    i += 1
            for pivot in self.stack_pivots:
                data = data.replace(pivot,b'')
                eliminate += 1
            if len(data) == 1:
                self.emulated[gadget_str] = self.details.copy()
                return
        '''

    def analyze(self):
        # Case 1: Gadget already emulated
        if self.gadget_str in self.emulated:
            return self.emulated[self.gadget_str]
        self.count = 0
        self.inst_executed = 0
        self.results = []
        self.analyze_gadget()
        i = 0
        for state in self.results:
            for key,value in state.items():
                if value in self.cyclic_data[1]:
                    if self.addr not in self.cache['full_control']:
                        self.cache[self.addr] = self.gadget_str
                    self.results[i][key] = 'Full control (offset {})'.format((self.cyclic_data[1].index(value)*self.bm)+(self.bm*self.inst_executed))
            i += 1

        if self.gadget_str not in self.emulated:
            self.emulated[self.gadget_str] = self.results.copy()
        return self.results

    def analyze_gadget(self):
        inst_cnt = self.gadget_str.count(';')
        self.bytes_executed = 0
        self.count = 0
        mu = Uc(uarch[self.bv_arch],ubitmode[self.bv_arch])

        # text
        mu.mem_map(0x1000,4096)
        mu.mem_write(0x1000,self.data)
        
        # Generate cyclic stack (replace later)
        self.cyclic_data = self.cyclic(inst_cnt+1)

        # stack
        mu.mem_map(0x2000,4096)
        mu.mem_write(0x2100,self.cyclic_data[0])
        mu.reg_write(arch[self.bv_arch]['uregs']['sp'],0x2100)

        # Get effects
        mu.hook_add(UC_HOOK_CODE, self.analyze_step)
        try:
            mu.emu_start(0x1000,0x1000+len(self.data),count=inst_cnt-1)
        except UcError as e:
            if e.errno == UC_ERR_READ_UNMAPPED:
                # Case 2: Stack pivot
                # TODO:
                # - Fix offset issue for remainder of the full_control steps
                # - Fix stack pivot duplicate
                for sp in arch[self.bv_arch]['sp']:
                    if sp in self.last_executed[1]:
                        self.results[-1][sp] = 'Stack pivot'
                        self.data = self.data[self.bytes_executed-self.byte_executed:]
                        self.analyze_gadget()

                        # Recurse with the chunk of instructions after this
                pass
            elif e.errno == UC_ERR_WRITE_UNMAPPED:
                pass
            elif e.errno == UC_ERR_FETCH_UNMAPPED:
                pass
            #log_info(str(self.data),'Untitled')
        self.analyze_step(mu,0,0,0)
        mu.mem_unmap(0x1000,4096*2)
        
        return self.results

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
        return (packed,unpacked)
    
    def analyze_step(self, mu, address, size, data):
        self.last_executed = (address,self.instructions[self.count-1])
        self.bytes_executed += size
        self.byte_executed = size
        #self.inst_executed += 1
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
                        if distance < 0:
                            curr_state[reg] = sp+'+'+hex(abs(distance))+' ('+hex(mu.reg_read(arch[self.bv_arch]['uregs'][reg]))+')'
                        else:
                            curr_state[reg] = sp+'-'+hex(abs(distance))+' ('+hex(mu.reg_read(arch[self.bv_arch]['uregs'][reg]))+')'
                if stack_insn:
                    stack_insn = False
                else:
                    curr_state[reg] = mu.reg_read(arch[self.bv_arch]['uregs'][reg])
        self.results.append(curr_state)
        self.count += 1
