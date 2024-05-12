from binaryninja import *
from .constants import *
from unicorn import *
import struct
from keystone import *

class GadgetAnalysis:

    '''
    [
        {'das':1,'dfs':2},
    ]
    '''
    details = []
    emulated = {}
    instructions = []
    count = 0
    registers = []
    stack_pivot_indexes = None
    stack_pivots = []

    # Future feature, options to give registers pre-states?
    # If pre-states are defined, display resulting register values
    def __init__(self,addr,gadget_str,bv,gadget_pool_raw):    
        self.details = []
        if gadget_str in self.emulated:
            self.details = self.emulated[gadget_str]
            return

        self.bv_arch = bv.arch.name
        inst_cnt = gadget_str.count(';')
        self.instructions = gadget_str.split(';')
        self.bm = int(arch[self.bv_arch]['bitmode']/8)
        n = 8 # Change x64 dependent

        # Save operand registers into details
        self.registers = arch[self.bv_arch]['registers']
        data = gadget_pool_raw[addr]
        
        # T - Stack pivot case
        # F - No stack pivot
        # REDO THIS CHECK SO STACK PIVOTS ARE INSERTED IN ORDER OF GADGET EFFECT AND EXECUTION CONTINUES IF GADGET HAS MORE INSTs
        stack_pointers = arch[self.bv_arch]['sp']
        for sp in stack_pointers:
            if sp in gadget_str:
                md = Ks(keystone_arch[bv.arch.name], bitmode(bv.arch.name)[1])
                self.stack_pivot_indexes = []
                i = 0
                for inst in self.instructions:
                    if sp in inst:
                        self.details.append({sp:'Stack pivot'})
                        self.stack_pivots.append(md.asm(bytes(inst,'utf8'), as_bytes=True)[0])
                        self.stack_pivot_indexes.append(i)
                    i += 1
                for pivot in self.stack_pivots:
                    data = data.replace(pivot,b'')
        if len(data) == 1 and self.stack_pivot_indexes != None:
            self.emulated[gadget_str] = self.details.copy()
            return

        mu = Uc(uarch[self.bv_arch],ubitmode[self.bv_arch])

        # text
        mu.mem_map(0x1000,4096)
        mu.mem_write(0x1000,data)

        # Generate cyclic stack (replace later)
        cyclic_data = self.cyclic(inst_cnt+1)

        # stack
        mu.mem_map(0x2000,4096)
        mu.mem_write(0x2000,cyclic_data[0])
        mu.reg_write(arch[self.bv_arch]['uregs']['sp'],0x2000)

        # Get effects
        mu.hook_add(UC_HOOK_CODE, self.analyze_step)
        mu.emu_start(0x1000,0x1000+len(data),count=inst_cnt-1)
        self.analyze_step(mu,0,0,0)

        #for reg in list(self.details.keys()):
        #    self.details[reg] = mu.reg_read(arch[self.bv_arch]['uregs'][reg])

        # Reassign details that contain a packed value to have full control
        # Special case: What if a register has FC, but a later instruction modifies it?
        # Should we implement an emulation hook? Consider how this will effect speed.
        # Special case: Detect arbritrary writes and hook dereferences ('Writes @ rax')
        # Possible descriptions of modification instead of plaintive results ie:
        # Subtract 3 from rax
        # XOR rax
        # Full control of rax
        # Subtract 3 from rax

        # Unanticipated algorithmic complexity
        # Method
        # Step 1 - Save program state (assign precontext if nessecary)
        # Step 2 - Emulation creation
        # Step 3 - Emulate, hook execution and record state changes
        # Step 4 - Compare to start state
        
        i = 0
        for state in self.details:
            for key,value in state.items():
                if value in cyclic_data[1]:
                    self.details[i][key] = 'Full control (offset {})'.format(cyclic_data[1].index(value)*self.bm)
            i += 1

        # Remember to unmmap
        mu.mem_unmap(0x1000,4096*2)
        #self.details = {}
        if gadget_str not in self.emulated:
            self.emulated[gadget_str] = self.details.copy()

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
        if self.count == 0:
            self.count += 1
            return
        curr_state = {}
        for reg in self.registers:
            if reg in self.instructions[self.count-1]:
                curr_state[reg] = mu.reg_read(arch[self.bv_arch]['uregs'][reg])
        self.details.append(curr_state)
        self.count += 1
