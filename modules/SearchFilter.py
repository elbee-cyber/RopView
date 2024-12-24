from .constants import *
from .GadgetSearch import *
from .GadgetAnalysis import *
import pandas as pd
import re,random

class SearchFilter:

    def __init__(self, bv, ui, renderer):
        self.ui = ui
        self.bv = bv
        self.ui.lineEdit.returnPressed.connect(self.spawnQuery)
        self.renderer = renderer
        self.regs = arch[self.bv.arch.name]['prestateOpts']
        self.buildDataFrame()

    def spawnQuery(self):
        self.setStatus("Searching...")
        execute_on_main_thread_and_wait(self.query)

    def query(self):
        self.renderer.ui.resultsLabel.setText('')
        query = self.ui.lineEdit.text()
        gaveAttr = False

        # Empited query, return normal
        if query == '':
            self.renderer.gsearch()
            return

        # Parse disasm option
        if 'disasm' in query:
            if 'disasm.' in query:
                query = query.replace('disasm.','disasm.str.')
            gaveAttr = True

        # Parse bytes option
        if 'bytes' in query:
            if 'bytes.' in query:
                query = query.replace('bytes.','bytes.str.')
            query = query.replace('0x','')
            query = query.replace('\\x','')
            gaveAttr = True

        # .has() -> .contains() 
        if '.has(' in query:
            query = query.replace('.has(','.contains(')
            gaveAttr = True
        
        # Parse presets
        for preset in arch[self.bv.arch.name]['presets']:
            if preset in query:
                query = query.replace(preset,arch[self.bv.arch.name]['presets'][preset])
                gaveAttr = True

        # Space mismatching
        query = query.replace(' =','=')
        query = query.replace(' -','-')
        query = query.replace(' +','+')
        query = query.replace(' /','/')
        query = query.replace(' *','*')
        query = query.replace(' <','<')
        query = query.replace(' >','>')
        query = query.replace('= ','=')
        query = query.replace('- ','-')
        query = query.replace('+ ','+')
        query = query.replace('/ ','/')
        query = query.replace('* ','*')
        query = query.replace('< ','<')
        query = query.replace('> ','>')
        
        if len(re.findall("=|-|\+|/|\*|<|>",query)) > 0:
            gaveAttr = True

        # Semantic regs
        semantic = []

        # Transform semantic searches of type reg[><=/*+-]
        ## Transformation: ((reg[><=/*+-] or reg==FULL_CONTROL) and not reg==NOT_ANALYZED)
        replacements = []
        for reg in arch[self.bv.arch.name]['prestateOpts']:
            if re.search(reg+'[\>\<=\-+\/*]',query) is not None:
                reg_matches = re.finditer(reg+'[\>\<=\-+\/*]{1,2}',query)
                for match in reg_matches:
                    extract_reg = re.sub('[\>\<=\-+\/*]{1,2}','',match.group())
                    space_index = query[match.span()[1]:].find(' ')
                    if space_index != -1:
                        subquery = query[match.span()[0]:space_index+len(query[:match.span()[1]])]
                    else:
                        subquery = query[match.span()[0]:]
                    replacements.append((subquery,"(({} or {}=={}) and not {}=={})".format(subquery, extract_reg, REG_CONTROLLED, extract_reg, REG_NOT_ANALYZED)))
                semantic.append(reg)
        for replacement in replacements:
            query = query.replace(replacement[0],replacement[1])

        if len(semantic) > 0:
            self.__semanticRegs = semantic
            if not run_progress_dialog("Performing semantic search",True,self.semantic):
                status = "Semantic search on "
                for reg in semantic:
                    status += reg+", "
                self.setStatus(status[:-2]+" canceled",True)

        # Default search behaviour
        if not gaveAttr and len(semantic) == 0:
            if "\\x" in query or "0x" in query:
                query = query.replace('0x','')
                query = query.replace('\\x','')
                query = "bytes.str.contains('{}')".format(query)
            else:
                query = "disasm.str.contains('{}')".format(query)

        # Save matching results
        results = self.attemptQuery(query)

        if len(semantic) > 0:
            if len(results) == 0:
                self.setStatus("Semantic search failed",True)
            else:
                self.setStatus("Semantic search completed")
        else:
            self.setStatus("Search completed")

        # Build pool and update rendering
        if len(results) == 0:
            return

        pool = {}
        for addr in results:
            addr = int(addr)
            pool[addr] = self.bv.session_data['RopView']['gadget_disasm'][addr]
        self.renderer.update_and_sort(pool)

    def semantic(self,update):
        allowed_regs = arch[self.bv.arch.name]['prestateOpts']
        prestate = self.renderer.buildPrestate()
        reg_vals = {}
        cnt = 1

        # Only search spaces operating on target registers
        include = ""
        for reg in self.__semanticRegs:
            include += "disasm.str.contains('"+reg+"') or "
        search_space = self.attemptQuery(include[:-4])
        random.shuffle(search_space)

        # Prevent exhaustion
        limit = int(self.ui.semanticBox.text())

        # GadgetAnalysis
        for addr in search_space:

            if cnt > limit:
                break

            if not update(cnt,limit):
                break
            cnt += 1

            contains_interrupt = False
            for interrupt in arch[self.bv.arch.name]['blacklist']:
                if interrupt in self.bv.session_data['RopView']['gadget_disasm'][addr]:
                    contains_interrupt = True
                    break
            if contains_interrupt:
                continue

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
                del ga

            contains_used = False
            for reg in self.__semanticRegs:
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
            del reg_vals

    def attemptQuery(self,query):
        results = []
        try:
            resultsDF = self.full_df.query(query)
        except Exception as e:
            self.setStatus("Invalid query provided, please try again",True)
            print(e)
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
        self.bv.session_data['RopView']['dataframe'] = self.full_df
        # Add reg columns
        for reg in self.regs:
            self.full_df[reg]=REG_NOT_ANALYZED

    def setStatus(self,text,error=False):
        self.renderer.ui.resultsLabel.setText(text)
        if error:
            self.renderer.ui.resultsLabel.setStyleSheet("QLabel { color : red; }")
        else:
            self.renderer.ui.resultsLabel.setStyleSheet("QLabel { color : white; }")