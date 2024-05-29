from .constants import *
from .GadgetSearch import *
from .GadgetAnalysis import *
import pandas as pd
import re

class SearchFilter:

    def __init__(self, bv, ui, renderer):
        self.ui = ui
        self.bv = bv
        self.ui.lineEdit.returnPressed.connect(self.query)
        self.renderer = renderer
        self.regs = arch[self.bv.arch.name]['prestateOpts']
        self.buildDataFrame()
        self.last_semantic = list(self.bv.session_data['RopView']['gadget_asm'].keys())[0]

    def query(self):
        query = self.ui.lineEdit.text()

        # Empited query, return normal
        if query == '':
            self.renderer.gsearch()
            return

        # Parse disasm option
        if 'disasm' in query:
            if 'disasm.' in query:
                query = query.replace('disasm.','disasm.str.')
            query = query.replace(' ; ',';')
            query = query.replace(';',' ; ')

        # Parse bytes option
        if 'bytes' in query:
            if 'bytes.' in query:
                query = query.replace('bytes.','bytes.str.')
            query = query.replace('0x','')
            query = query.replace('\\x','')

        # Parse presets
        ## ppr
        if 'ppr' in query:
            preset = "(disasm.str.count('pop')==2 and disasm.str.contains('ret') and inst_cnt==3)"
            query = query.replace('ppr',preset)

        ## stack pivot
        if 'stack_pivot' in query:
            preset = "("
            for pivot in arch[self.bv.arch.name]['stack_pivots']:
                preset += "disasm.str.contains('"+pivot+"') or "
            preset = preset[:-3]+")"
            query = query.replace('stack_pivot',preset)
            debug_notify(query)

        # Save matching results
        try:
            resultsDF = self.full_df.query(query)
        except:
            show_message_box("Invalid query","An invalid search query was provided")
            return

        results = []
        for index, row in resultsDF.iterrows():
            results.append(row['addr'])

        semantic = False
        for reg in arch[self.bv.arch.name]['prestateOpts']:
            if re.match(reg+'[\>\<=\-+\/*]',query) != None:
                semantic = True
                break
        if semantic:
            self.semantic(query)

        # Build pool and update rendering
        pool = {}
        for addr in results:
            addr = int(addr)
            pool[addr] = self.bv.session_data['RopView']['gadget_disasm'][addr]
        self.renderer.update_and_sort(pool)

    def semantic(self,query):
        
        # Retrieve from cache
        address_range = list(self.bv.session_data['RopView']['gadget_asm'].keys())
        prestate = self.renderer.buildPrestate()
        reg_vals = {}
        res_cnt = len(self.full_df.query(query))

        # GadgetAnalysis
        for addr in address_range:
            # Populate [regs]
            if addr in self.bv.session_data['RopView']['cache']['analysis']:
                reg_vals = self.bv.session_data['RopView']['cache']['analysis'][addr].end_state
            else:
                ga = GadgetAnalysis(self.bv, addr, self.bv.session_data['RopView']['gadget_disasm'][addr])
                ga.set_prestate(prestate)
                ga.analyze()
                reg_vals = ga.end_state
                self.bv.session_data['RopView']['cache']['analysis'][addr] = ga.saveState()
            for reg in self.regs:
                if reg not in reg_vals:
                    reg_vals[reg] = 0

            # Find corresponding row
            break


    def buildDataFrame(self):
        raw = []
        inst_cnt = []

        # Append bytes and size searchables
        for addr,asm in self.bv.session_data['RopView']['gadget_asm'].items():
            raw.append(asm.hex())
            inst_cnt.append(self.bv.session_data['RopView']['gadget_disasm'][addr].count(';'))

        gadget_data = {
            'addr':list(self.bv.session_data['RopView']['gadget_asm'].keys()),
            'bytes':raw,
            'inst_cnt':inst_cnt,
            'disasm':list(self.bv.session_data['RopView']['gadget_disasm'].values())
        }
        self.full_df = pd.DataFrame(gadget_data)
        # Add reg columns
        for reg in self.regs:
            self.full_df[reg]=-1

    def addSemantic(self):
        pass
        