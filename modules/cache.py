class cache:
    def __init__(self,bv):
        self.bv = bv
        self.rop_cache = rop_cache(self.bv)
        self.cop_cache = cop_cache(self.bv)
        self.jop_cache = jop_cache(self.bv)
        self.sys_cache = sys_cache(self.bv)
        self.gcache = gcache(self.bv)
        self.analysis_cache = analysis_cache(self.bv)

    def build(self):
        try:
            self.bv.session_data['RopView']['g_disasm'] = self.bv.query_metadata("RopView.g_disasm")
            self.bv.session_data['RopView']['g_asm'] = self.bv.query_metadata("RopView.g_asm")
            self.bv.session_data['RopView']['analysis'] = self.bv.query_metadata("RopView.analysis")
        except KeyError:
            self.bv.store_metadata("RopView.rop_asm",{})
            self.bv.store_metadata("RopView.rop_disasm",{})
            self.bv.store_metadata("RopView.cop_asm",{})
            self.bv.store_metadata("RopView.cop_disasm",{})
            self.bv.store_metadata("RopView.jop_asm",{})
            self.bv.store_metadata("RopView.jop_disasm",{})
            self.bv.store_metadata("RopView.sys_asm",{})
            self.bv.store_metadata("RopView.sys_disasm",{})
            self.bv.store_metadata("RopView.g_asm",{})
            self.bv.store_metadata("RopView.g_disasm",{})
            self.bv.store_metadata("RopView.analysis",{})
            self.bv.session_data['RopView']['g_disasm'] = {}
            self.bv.session_data['RopView']['g_asm'] = {}
            self.bv.session_data['RopView']['analysis'] = {}

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

    def store_disasm(self, item):
        tmp = self.bv.query_metadata("RopView.rop_disasm")
        tmp.update(item)
        self.bv.store_metadata("RopView.rop_disasm",tmp)

    def store_asm(self, item):
        tmp = self.bv.query_metadata("RopView.rop_asm")
        tmp.update(item)
        self.bv.store_metadata("RopView.rop_asm",tmp)

    def load_disasm(self):
        # weird metadata bug converts dict keys to strings
        tmp = self.bv.query_metadata("RopView.rop_disasm")
        print("Accessed rop_cache")
        return {int(k):v for k,v in tmp.items()}

    def load_asm(self):
        tmp = self.bv.query_metadata("RopView.rop_asm")
        return {int(k):v for k,v in tmp.items()}

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

    def store_disasm(self, item):
        tmp = self.bv.query_metadata("RopView.cop_disasm")
        tmp.update(item)
        self.bv.store_metadata("RopView.cop_disasm",tmp)

    def store_asm(self, item):
        tmp = self.bv.query_metadata("RopView.cop_asm")
        tmp.update(item)
        self.bv.store_metadata("RopView.cop_asm",tmp)

    def load_disasm(self):
        tmp = self.bv.query_metadata("RopView.cop_disasm")
        return {int(k):v for k,v in tmp.items()}

    def load_asm(self):
        tmp = self.bv.query_metadata("RopView.cop_asm")
        return {int(k):v for k,v in tmp.items()}

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

    def store_disasm(self, item):
        tmp = self.bv.query_metadata("RopView.jop_disasm")
        tmp.update(item)
        self.bv.store_metadata("RopView.jop_disasm",tmp)

    def store_asm(self, item):
        tmp = self.bv.query_metadata("RopView.jop_asm")
        tmp.update(item)
        self.bv.store_metadata("RopView.jop_asm",tmp)

    def load_disasm(self):
        tmp = self.bv.query_metadata("RopView.jop_disasm")
        return {int(k):v for k,v in tmp.items()}

    def load_asm(self):
        tmp = self.bv.query_metadata("RopView.jop_asm")
        return {int(k):v for k,v in tmp.items()}

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

    def store_disasm(self, item):
        tmp = self.bv.query_metadata("RopView.sys_disasm")
        tmp.update(item)
        self.bv.store_metadata("RopView.sys_disasm",tmp)

    def store_asm(self, item):
        tmp = self.bv.query_metadata("RopView.sys_asm")
        tmp.update(item)
        self.bv.store_metadata("RopView.sys_asm",tmp)

    def load_disasm(self):
        tmp = self.bv.query_metadata("RopView.sys_disasm")
        return {int(k):v for k,v in tmp.items()}

    def load_asm(self):
        tmp = self.bv.query_metadata("RopView.sys_asm")
        return {int(k):v for k,v in tmp.items()}

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

    def store_disasm(self, item):
        tmp = self.bv.query_metadata("RopView.g_disasm")
        tmp.update(item)
        self.bv.store_metadata("RopView.g_disasm",tmp)
        self.bv.session_data['RopView']['g_disasm'].update(item)

    def store_asm(self, item):
        tmp = self.bv.query_metadata("RopView.g_asm")
        tmp.update(item)
        self.bv.store_metadata("RopView.g_asm",tmp)
        self.bv.session_data['RopView']['g_asm'].update(item)

    def load_disasm(self):
        return self.bv.session_data['RopView']['g_disasm']

    def load_asm(self):
        return self.bv.session_data['RopView']['g_asm']

    def flush(self):
        self.bv.remove_metadata("RopView.g_asm")
        self.bv.remove_metadata("RopView.g_disasm")
        self.bv.store_metadata("RopView.g_asm",{})
        self.bv.store_metadata("RopView.g_disasm",{})
        self.bv.session_data['RopView']['g_disasm'] = {}
        self.bv.session_data['RopView']['g_asm'] = {}

class analysis_cache:

    def __init__(self,bv):
        self.bv = bv

    def isEmpty(self):
        return len(self.bv.query_metadata("RopView.analysis")) == 0

    def store(self, item):
        tmp = self.bv.query_metadata("RopView.analysis")
        tmp.update(item)
        self.bv.store_metadata("RopView.analysis",tmp)
        self.bv.session_data['RopView']['analysis'].update(item)

    def load(self):
        return self.bv.session_data['RopView']['analysis']

    def flush(self):
        self.bv.remove_metadata("RopView.analysis")
        self.bv.store_metadata("RopView.analysis",{})
        self.bv.session_data['RopView']['analysis'] = {}
