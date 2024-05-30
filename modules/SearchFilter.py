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

        # Format semicolons correctly
        query = query.replace(' ; ',';')
        query = query.replace(';',' ; ')

        # Parse bytes option
        if 'bytes' in query:
            if 'bytes.' in query:
                query = query.replace('bytes.','bytes.str.')
            query = query.replace('0x','')
            query = query.replace('\\x','')

        # Custom 
        if '.has(' in query:
            query = query.replace('.has(','.contains(')
        
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

        # Semantic regs
        semantic = []

        # Exclude sentinel from semantic search
        for reg in arch[self.bv.arch.name]['prestateOpts']:
            if re.match(reg+'[\>\<=\-+\/*]',query) != None:
                semantic.append(reg)
                query += " and not "+str(reg)+"=="+str(REG_NOT_ANALYZED)

        # Save matching results
        results = self.attemptQuery(query)

        if len(semantic) > 0:
            results = list(set(results + self.semantic(query)))

        # Build pool and update rendering
        if len(results) == 0:
            return

        pool = {}
        for addr in results:
            addr = int(addr)
            pool[addr] = self.bv.session_data['RopView']['gadget_disasm'][addr]
        self.renderer.update_and_sort(pool)

    def semantic(self,query):
        
        # Retrieve from cache
        results = []
        allowed_regs = arch[self.bv.arch.name]['prestateOpts']
        #address_range = list(self.bv.session_data['RopView']['gadget_asm'].keys())
        prestate = self.renderer.buildPrestate()
        reg_vals = {}
        res_cnt = len(self.attemptQuery(query))
        explicit_regs = []
        pop_cond = " or "
        cnt = 0

        # Build query to include control gadgets and add target registers
        add_pop_quer = False
        for reg in allowed_regs:
            if reg in query:
                pop_cond += reg+"==("+str(REG_CONTROLLED)+") or "
                explicit_regs.append(reg)
                add_pop_quer = True
        if add_pop_quer:
            query += pop_cond[:-4]

        # Only search spaces operating on target registers
        include = ""
        for reg in explicit_regs:
            include += "disasm.str.contains('"+reg+"') or "
        search_space = self.attemptQuery(include[:-4])

        df = self.attemptQuery(query)
        debug_notify(len(search_space))

        # GadgetAnalysis
        for addr in search_space:
            # Populate [regs]
            if addr in self.bv.session_data['RopView']['cache']['analysis']:
                reg_vals = self.bv.session_data['RopView']['cache']['analysis'][addr].end_state
            else:
                ga = GadgetAnalysis(self.bv, addr, self.bv.session_data['RopView']['gadget_disasm'][addr])
                ga.set_prestate(prestate)
                try:
                    ga.analyze()
                except:
                    break
                reg_vals = ga.end_state
                self.bv.session_data['RopView']['cache']['analysis'][addr] = ga.saveState()

            contains_used = False
            for reg in explicit_regs:
                if reg in reg_vals:
                    contains_used = True
                    break
            if not contains_used:
                continue

            for reg,val in reg_vals.items():
                if reg not in self.full_df.columns:
                    continue
                if reg not in allowed_regs:
                    continue
                if self.full_df.loc[self.full_df['addr'] == addr, reg].iloc[0] != REG_NOT_ANALYZED:
                    continue
                if not isinstance(val,int) and 'Full control' in val:
                    self.full_df.loc[self.full_df['addr'] == addr, reg] = REG_CONTROLLED
                else:
                    self.full_df.loc[self.full_df['addr'] == addr, reg] = val

            df = self.attemptQuery(query)
            debug_notify(len(df))
        results = df
        return results

    def attemptQuery(self,query):
        results = []
        try:
            resultsDF = self.full_df.query(query)
        except:
            try:
                resultsDF = self.full_df.query("disasm.str.contains('"+query+"')")
            except:
                show_message_box("Invalid query","An invalid search query was provided")
                return results
        for index, row in resultsDF.iterrows():
            results.append(row['addr'])
        return results

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
            self.full_df[reg]=REG_NOT_ANALYZED

    def addSemantic(self):
        pass
        