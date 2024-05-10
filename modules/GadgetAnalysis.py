from binaryninja import *
from .constants import *
from unicorn import *

class GadgetAnalysis:

    details = {}

    def __init__(self,addr,gadget_str,bv,gadget_pool_raw):
        bv_arch = bv.arch.name
        inst_cnt = gadget_str.count(';')
        n = 8 # Change x64 dependent

        # Save operand registers into details
        registers = arch[bv_arch]['registers']
        data = gadget_pool_raw[addr]
        for reg in registers:
            if reg in gadget_str:
                self.details[reg] = -1

        mu = Uc(uarch[bv_arch],ubitmode[bv_arch])

        # text
        mu.mem_map(0x1000,4096)
        mu.mem_write(0x1000,data)

        # Generate cyclic stack (replace later)
        sentinel = b'\xde\xad\xba\xbe'
        if arch[bv_arch][bitmode] == 64:
            sentinel = b'\xca\xfe\xbe\xef\xde\xad\xba\xbe'

        # stack
        mu.mem_map(0x2000,4096)
        mu.mem_write(0x2000,sentinel*inst_cnt)
        mu.reg_write(arch[bv_arch]['uregs']['sp'],0x2000)

        # Get effects
        mu.emu_start(0x1000,0x1000+len(data),count=inst_cnt-1)
        for reg in list(self.details.keys()):
            self.details[reg] = mu.reg_read(arch[bv_arch]['uregs'][reg])

        # Reassign details that contain a sentinel value to have full control

        # Remember to unmmap
        log_info(str(self.details),"Untitled ROP Plugin")
        
