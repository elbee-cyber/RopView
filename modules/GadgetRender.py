from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem, QTreeWidgetItemIterator
from .GadgetSearch import GadgetSearch
from .constants import *
from binaryninja import log_info

class GadgetRender:
    '''
    Responsible for doing gadget search, rendering to UI gadget search pane, 
    connecting option changes and updating the pane based on option changes.

    Options:
    Bad bytes - Implemented
    Depth - Implemented
    Pnemonic blocks - Implemented
    Address range - Implemented
    Instruction count - Implemented
    ROP - Implemented
    COP
    JOP
    Multi branch
    Duplicates - Implemented
    Dump
    Color
    '''
    def __init__(self, bv, ui):
        '''
        Configure default options, initial gadgetsearch, display right registers into prestate options ui.
        '''
        self.bad_bytes = []
        self.depth = 16
        self.block = []
        self.address_range = []
        self.inst_cnt = 0
        self.rop = True
        self.jop = True
        self.cop = True
        self.multi_branch = False
        self.duplicates = False
        self.dump = False
        self.ui = ui
        self.bv = bv
        self.bv_arch = bv.arch.name

        self.ui.badBytesEdit.textChanged.connect(self.prepareBadBytes)
        self.ui.depthBox.textChanged.connect(self.prepareDepth)
        self.ui.blockEdit.textChanged.connect(self.prepareBlock)
        self.ui.rangeEdit.textChanged.connect(self.prepareRange)
        self.ui.instCntSpinbox.textChanged.connect(self.prepareInstCnt)
        self.ui.allOpt.clicked.connect(self.prepareRepeat)
        self.ui.ropOpt.clicked.connect(self.prepareROP)
        self.ui.copOpt.clicked.connect(self.prepareCOP)
        self.ui.jopOpt.clicked.connect(self.prepareJOP)
        self.ui.multibranchOpt.clicked.connect(self.prepareMultibranch)
        self.ui.dumpOpt.clicked.connect(self.prepareDump)
        self.ui.colorOpt.clicked.connect(self.prepareColor)

        self.gs = GadgetSearch(bv)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.render_gadgets(self.pool_sorted)

        # Load the correct register names into the analysis prestate UI (Options tab)
        reg_label = getattr(self.ui,"reglabel",-1)
        reg_label.setText(arch[self.bv_arch]['prestateOpts'][0]+'=')
        i = 2
        while reg_label != -1:
            reg_label = getattr(self.ui,"reglabel_"+str(i),-1)
            if reg_label == -1:
                break
            try:
                reg_label.setText(arch[self.bv_arch]['prestateOpts'][i-1]+'=')
            except IndexError:
                # Might look prettier if we do a modulo check to add horizontal spaces in the vertical layout so its all aligned
                reg_label.setVisible(False)
                getattr(self.ui,"regedit_"+str(i)).setVisible(False)
            i += 1

    def update_and_sort(self):
        '''
        Clears gadget search pane (ui)
        Calls sort (sorts sorted_pool according to options)
        Re renders gadget search pane (ui)

        Dont use recursion
        '''
        selected = self.ui.gadgetPane.selectedItems()
        isSelected = len(selected) > 0
        if isSelected:
            selected = selected[0].text(1)
        self.clear_gadgets()
        res = self.sort(self.gs.gadget_pool.copy()).items()
        self.render_gadgets(res)
        if isSelected:
            self.restore_selected(selected)
    
    def restore_selected(self,selected):
        iterator = QTreeWidgetItemIterator(self.ui.gadgetPane)
        for i in iterator:
            item = i.value()
            if item.text(1) == selected:
                item.setSelected(True)

    def clear_gadgets(self):
        '''
        Clears gadgets in search pane
        '''
        self.ui.statusLabel.setText("")
        self.ui.gadgetPane.clear()

    def render_gadgets(self,pool):
        '''
        Renders gadgets in pool into search pane
        '''
        addr_color = QBrush(QColor(108, 193, 108, 255))
        disasm_color = QBrush(QColor(255, 255, 255, 255))
        font = QFont()
        font.setFamily(u"Hack")
        # Add gadgets to gadget search pane
        self.ui.statusLabel.setText("Gadget count: "+str(len(pool)))
        for addr, text in pool:
            item = QTreeWidgetItem(self.ui.gadgetPane.topLevelItemCount())
            item.setText(0,hex(addr))
            item.setFont(1,font)
            item.setText(1,text)
            item.setForeground(0,addr_color)
            item.setForeground(1,disasm_color)
            self.ui.gadgetPane.addTopLevelItem(item)

    def sort(self, pool):
        '''
        Sorting logic according to options done here. Some options will require a new gadget search be done in (update gs)
        before actual sorting can take place (ei depth)
        '''

        # Bad bytes sort
        if self.bad_bytes != []:
            for b in self.bad_bytes:
                for addr in list(pool.keys()):
                    if b in hex(addr):
                        pool.pop(addr)

        # Hard pnemonic block sort
        if self.block != []:
            try:
                for insn in self.block:
                    for key,val in pool.items():
                        if insn in val:
                            pool.pop(key)
            except RuntimeError:
                pool = self.sort(pool)

        # Address range sort
        if self.address_range != []:
            try:
                for a in list(pool.keys()):
                    if not (a > self.address_range[0] and a < self.address_range[1]):
                        pool.pop(a)
            except RuntimeError:
                pool = self.sort(pool)

        # Inst cnt
        if self.inst_cnt != 0:
            try:
                for key, val in pool.items():
                    if len(val.split(';'))-1 > self.inst_cnt:
                        pool.pop(key)
            except RuntimeError:
                pool = self.sort(pool)

        return pool

    def buildPrestate(self):
        '''
        Builds prestate based on current analysis options
        '''
        prestate = {}
        reg_value = getattr(self.ui,"regedit",-1).text()
        reg_label = getattr(self.ui,"reglabel",-1).text().replace('=','')
        prestate[reg_label] = self.translateValue(reg_value)
        i = 2
        while reg_label != -1:
            reg_label = getattr(self.ui,"reglabel_"+str(i),-1)
            reg_value = getattr(self.ui,"regedit_"+str(i),-1)
            if reg_label == -1 or reg_value == -1:
                break
            prestate[reg_label.text().replace('=','')] = self.translateValue(reg_value.text())
            i += 1
        return prestate
        
    def translateValue(self,value):
        '''
        Translates hex strings
        '''
        ret = 0
        try:
            if '0x' in value:
                ret = int(value,16)
            else:
                ret = int(value)
        except ValueError:
            pass
        return ret

    def prepareBadBytes(self):
        '''
        Bad bytes option slot:
        - Assigns ui option to class option
        - update and sort
        '''
        self.bad_bytes = []
        bad = self.ui.badBytesEdit.text().split(',')
        for b in bad:
            try:
                check = int(b,16)
                self.bad_bytes.append(b.replace('0x',''))
            except:
                pass
        self.update_and_sort()

    def prepareDepth(self):
        '''
        Depth option slot:
        - Reinitializes gadget pool with new depth
        - update and sort
        '''
        dep = int(self.ui.depthBox.text())
        include_dup = self.gs.repeat
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        multibranch = self.gs.multibranch
        self.gs = GadgetSearch(self.bv,depth=dep,repeat=include_dup,rop=rop,jop=jop,cop=cop,multibranch=multibranch)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.update_and_sort()

    def prepareBlock(self):
        '''
        Pnemonic block option slot:
        - Assigns ui option to class option
        - update and sort
        '''
        self.block = []
        insns = self.ui.blockEdit.text().split(',')
        for insn in insns:
            self.block.append(insn)
        self.block = list(filter(None, self.block))
        self.update_and_sort()

    def prepareRange(self):
        self.address_range = []
        addr = self.ui.rangeEdit.text().split('-')
        try:
            self.address_range.append(int(addr[0],16))
            self.address_range.append(int(addr[1],16))
        except:
            pass
        self.update_and_sort()

    def prepareInstCnt(self):
        self.inst_cnt = 0
        cnt = int(self.ui.instCntSpinbox.text())
        if cnt != 0:
            self.inst_cnt = cnt
        self.update_and_sort()

    def prepareRepeat(self):
        include_dup = self.ui.allOpt.isChecked()
        dep = self.gs.depth
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        multibranch = self.gs.multibranch
        self.gs = GadgetSearch(self.bv,depth=dep,repeat=include_dup,rop=rop,jop=jop,cop=cop,multibranch=multibranch)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.update_and_sort()

    def prepareROP(self):
        rop = self.ui.ropOpt.isChecked()
        dep = self.gs.depth
        include_dup = self.gs.repeat
        jop = self.gs.jop
        cop = self.gs.cop
        multibranch = self.gs.multibranch
        self.gs = GadgetSearch(self.bv,depth=dep,repeat=include_dup,rop=rop,jop=jop,cop=cop,multibranch=multibranch)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.update_and_sort()

    def prepareCOP(self):
        cop = self.ui.copOpt.isChecked()
        dep = self.gs.depth
        include_dup = self.gs.repeat
        rop = self.gs.rop
        jop = self.gs.jop
        multibranch = self.gs.multibranch
        self.gs = GadgetSearch(self.bv,depth=dep,repeat=include_dup,rop=rop,jop=jop,cop=cop,multibranch=multibranch)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.update_and_sort()

    def prepareJOP(self):
        jop = self.ui.jopOpt.isChecked()
        dep = self.gs.depth
        include_dup = self.gs.repeat
        rop = self.gs.rop
        cop = self.gs.cop
        multibranch = self.gs.multibranch
        self.gs = GadgetSearch(self.bv,depth=dep,repeat=include_dup,rop=rop,jop=jop,cop=cop,multibranch=multibranch)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.update_and_sort()

    def prepareMultibranch(self):
        multibranch = self.ui.multibranchOpt.isChecked()
        dep = self.gs.depth
        include_dup = self.gs.repeat
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        self.gs = GadgetSearch(self.bv,depth=dep,repeat=include_dup,rop=rop,jop=jop,cop=cop,multibranch=multibranch)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.update_and_sort()

    def prepareDump(self):
        pass

    def prepareColor(self):
        pass