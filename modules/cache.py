class cache:
    def __init__(self,bv):
        self.bv = bv

    def build(self):
        self.bv.store_metadata("RopView.rop_asm",{})
        self.bv.store_metadata("RopView.rop_disasm",{})
        self.rop_cache = rop_cache(self.bv)
        self.bv.store_metadata("RopView.cop_asm",{})
        self.bv.store_metadata("RopView.cop_disasm",{})
        self.cop_cache = cop_cache(self.bv)
        self.bv.store_metadata("RopView.jop_asm",{})
        self.bv.store_metadata("RopView.jop_disasm",{})
        self.jop_cache = jop_cache(self.bv)
        self.bv.store_metadata("RopView.sys_asm",{})
        self.bv.store_metadata("RopView.sys_disasm",{})
        self.sys_cache = sys_cache(self.bv)
        self.bv.store_metadata("RopView.g_asm",{})
        self.bv.store_metadata("RopView.g_disasm",{})
        self.gcache = gcache(self.bv)
        self.bv.store_metadata("RopView.analysis",{})
        self.analysis_cache = analysis_cache(self.bv)

    def fullflush(self):
        self.rop_cache.flush()
        self.cop_cache.flush()
        self.sys_cache.flush()
        self.gcache.flush()
        self.analysis_cache.flush()

class rop_cache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.rop_disasm")) + len(self.bv.query_metadata("RopView.rop_asm")) == 0

    def store_disasm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.rop_disasm",self.bv.query_metadata("RopView.rop_disasm") | item)

    def store_asm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.rop_asm",self.bv.query_metadata("RopView.rop_asm") | item)

    def load_disasm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.rop_disasm")[addr]

    def load_asm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.rop_asm")[addr]

    def flush(self):
        self.bv.remove_metadata("RopView.rop_asm")
        self.bv.remove_metadata("RopView.rop_disasm")
        self.bv.store_metadata("RopView.rop_asm",{})
        self.bv.store_metadata("RopView.rop_disasm",{})

class cop_cache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.cop_disasm")) + len(self.bv.query_metadata("RopView.cop_asm")) == 0

    def store_disasm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.cop_disasm",self.bv.query_metadata("RopView.cop_disasm") | item)

    def store_asm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.cop_asm",self.bv.query_metadata("RopView.cop_asm") | item)

    def load_disasm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.cop_disasm")[addr]

    def load_asm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.cop_asm")[addr]

    def flush(self):
        self.bv.remove_metadata("RopView.cop_asm")
        self.bv.remove_metadata("RopView.cop_disasm")
        self.bv.store_metadata("RopView.cop_asm",{})
        self.bv.store_metadata("RopView.cop_disasm",{})

class jop_cache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.jop_disasm")) + len(self.bv.query_metadata("RopView.jop_asm")) == 0

    def store_disasm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.jop_disasm",self.bv.query_metadata("RopView.jop_disasm") | item)

    def store_asm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.jop_asm",self.bv.query_metadata("RopView.jop_asm") | item)

    def load_disasm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.jop_disasm")[addr]

    def load_asm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.jop_asm")[addr]

    def flush(self):
        self.bv.remove_metadata("RopView.jop_asm")
        self.bv.remove_metadata("RopView.jop_disasm")
        self.bv.store_metadata("RopView.jop_asm",{})
        self.bv.store_metadata("RopView.jop_disasm",{})

class sys_cache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.sys_disasm")) + len(self.bv.query_metadata("RopView.sys_asm")) == 0

    def store_disasm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.sys_disasm",self.bv.query_metadata("RopView.sys_disasm") | item)

    def store_asm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.sys_asm",self.bv.query_metadata("RopView.sys_asm") | item)

    def load_disasm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.sys_disasm")[addr]

    def load_asm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.sys_asm")[addr]

    def flush(self):
        self.bv.remove_metadata("RopView.sys_asm")
        self.bv.remove_metadata("RopView.sys_disasm")
        self.bv.store_metadata("RopView.sys_asm",{})
        self.bv.store_metadata("RopView.sys_disasm",{})

class gcache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.g_disasm")) + len(self.bv.query_metadata("RopView.g_asm")) == 0

    def store_disasm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.g_disasm",self.bv.query_metadata("RopView.g_disasm") | item)

    def store_asm(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.g_asm",self.bv.query_metadata("RopView.g_asm") | item)

    def load_disasm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.g_disasm")[addr]

    def load_asm(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.g_asm")[addr]

    def flush(self):
        self.bv.remove_metadata("RopView.g_asm")
        self.bv.remove_metadata("RopView.g_disasm")
        self.bv.store_metadata("RopView.g_asm",{})
        self.bv.store_metadata("RopView.g_disasm",{})

class analysis_cache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.analysis")) == 0

    def store(self, item: dict) -> dict:
        self.bv.store_metadata("RopView.analysis",self.bv.query_metadata("RopView.analysis") | item)

    def load(self, addr: int) -> int:
        return self.bv.query_metadata("RopView.analysis")[addr]

    def flush(self):
        self.bv.remove_metadata("RopView.analysis")
        self.bv.store_metadata("RopView.analysis",{})
