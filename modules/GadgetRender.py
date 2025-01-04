from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem, QTreeWidgetItemIterator
from .GadgetSearch import GadgetSearch
from .constants import *
from binaryninja import show_message_box, run_progress_dialog, get_save_filename_input
from PySide6.QtCore import QTimer
import re

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
    COP - Implemented
    JOP - Implemented
    SYS - Implemented
    Duplicates - Implemented
    Dump
    Color
    '''
    def __init__(self, bv, ui):
        '''
        Configure default options, initial gadgetsearch, display right registers into prestate options ui.
        '''
        self.bad_bytes = []
        self.depth = 10
        self.block = []
        self.address_range = []
        self.inst_cnt = 0
        self.multi_branch = False
        self.duplicates = False
        self.dump = False
        self.ui = ui
        self.bv = bv
        self.bv_arch = bv.arch.name
        self.__selected = None
        self.currentlyUnique = False

        options = {
            'rop': True,
            'jop': False,
            'cop': False,
            'sys': True
        }

        self.debounce_bb = QTimer()
        self.debounce_bb.setInterval(2000)
        self.debounce_bb.setSingleShot(True)
        self.debounce_bb.timeout.connect(self.prepareBadBytes)

        self.debounce_addr = QTimer()
        self.debounce_addr.setInterval(2000)
        self.debounce_addr.setSingleShot(True)
        self.debounce_addr.timeout.connect(self.prepareRange)

        self.debounce_block = QTimer()
        self.debounce_block.setInterval(2000)
        self.debounce_block.setSingleShot(True)
        self.debounce_block.timeout.connect(self.prepareBlock)

        self.debounce_instCnt = QTimer()
        self.debounce_instCnt.setInterval(2000)
        self.debounce_instCnt.setSingleShot(True)
        self.debounce_instCnt.timeout.connect(self.prepareInstCnt)

        self.debounce_depth = QTimer()
        self.debounce_depth.setInterval(2000)
        self.debounce_depth.setSingleShot(True)
        self.debounce_depth.timeout.connect(self.prepareDepth)

        self.ui.thumbOpt.setVisible(False)
        self.ui.badBytesEdit.textChanged.connect(self.debounce_bb.start)
        self.ui.depthBox.textChanged.connect(self.debounce_depth.start)
        self.ui.blockEdit.textChanged.connect(self.debounce_block.start)
        self.ui.rangeEdit.textChanged.connect(self.debounce_addr.start)
        self.ui.instCntSpinbox.textChanged.connect(self.debounce_instCnt.start)
        self.ui.allOpt.clicked.connect(self.prepareRepeat)
        self.ui.ropOpt.clicked.connect(self.prepareROP)
        self.ui.copOpt.clicked.connect(self.prepareCOP)
        self.ui.jopOpt.clicked.connect(self.prepareJOP)
        self.ui.sysOpt.clicked.connect(self.preparesys)
        self.ui.dumpOpt.clicked.connect(self.prepareDump)
        self.ui.thumbOpt.clicked.connect(self.prepareThumb)
        self.ui.clearCacheButton.clicked.connect(self.flush)
        self.ui.reloadButton.clicked.connect(self.gsearch)
        self.ui.exportButton.clicked.connect(self.export_gadgets)
        self.__selectedItem = None

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
        
        # Disable thumb option if not ARM
        if 'armv7' == self.bv_arch:
            self.ui.thumbOpt.setVisible(True)

        # mips is jop only
        if 'mips' in self.bv_arch:
            self.ui.jopOpt.setChecked(True)
            options['jop'] = True

        # remove empty gadget classes
        for pool in gadgets[self.bv_arch]:
            if not gadgets[self.bv_arch][pool]:
                getattr(self.ui,pool+"Opt").setVisible(False)
                options[pool] = False

        self.repool(self.depth,options['rop'],options['jop'],options['cop'],options['sys'])

    def update_and_sort(self,pool=None):
        '''
        Clears gadget search pane (ui)
        Re renders gadget search pane (ui)
        '''
        self.bv.session_data['RopView']['analysis_enabled'] = False
        self.__selected = self.ui.gadgetPane.selectedItems()
        isSelected = len(self.__selected) > 0
        if isSelected:
            self.__selected = self.__selected[0].text(1)
        self.clear_gadgets()
        if pool is None:
            # Investigate here if options/semantic bugs
            if len(self.ui.lineEdit.text()) > 0 and len(self.__allpool) > 0:
                self.currentlyUnique = False
                res = self.sort(self.__allpool).items()
            else:
                res = self.sort(self.bv.session_data['RopView']['gadget_disasm'].copy()).items()
        else:
            self.currentlyUnique = False
            res = self.sort(pool).items()
        self.render_gadgets(res)
        self.bv.session_data['RopView']['analysis_enabled'] = True
        if self.__selectedItem is not None:
            self.__selectedItem.setSelected(True)

    def repool(self,dep,rop,jop,cop,sys,thumb=False):
        self.gs = GadgetSearch(self.bv,depth=dep,rop=rop,jop=jop,cop=cop,sys=sys,thumb=thumb)
        self.currentlyUnique = False
        self.__allpool = self.bv.session_data['RopView']['gadget_disasm'].copy()
        if self.bv.session_data['RopView']['loading_canceled']:
            self.search_canceled()
        else:
            self.update_and_sort()

    def clear_gadgets(self):
        '''
        Clears gadgets in search pane
        '''
        self.ui.statusLabel.setText("")
        self.ui.gadgetPane.clear()

    def search_canceled(self):
        self.ui.gadgetPane.clear()
        self.ui.resultsLabel.setText("Gadget search canceled, reload pool in options")
        self.ui.resultsLabel.setStyleSheet("QLabel { color : red; }")

    def render_gadgets(self,pool):
        '''
        Renders gadgets in pool into search pane
        '''
        addr_color = QBrush(QColor(108, 193, 108, 255))
        disasm_color = QBrush(QColor(255, 255, 255, 255))
        font = QFont()
        font.setFamily(u"Hack")
        found = False
        # Add gadgets to gadget search pane
        self.ui.statusLabel.setText("Gadget count: "+str(len(pool)))
        for addr, text in pool:
            item = QTreeWidgetItem(self.ui.gadgetPane.topLevelItemCount())
            item.setText(0,hex(addr))
            item.setFont(2,font)
            item.setText(2,text)
            if self.dump:
                item.setText(1,self.bv.session_data['RopView']['gadget_asm'][addr].hex())
                item.setForeground(1,QBrush(QColor(136, 136, 145, 255)))
            if text == self.__selected and not found:
                self.__selectedItem = item
                found = True
            item.setForeground(0,addr_color)
            item.setForeground(2,disasm_color)
            self.ui.gadgetPane.addTopLevelItem(item)
        if not found:
            self.__selectedItem = None

    def remove_dups(self,update):
        used = []
        max = len(self.__allpool)
        min = 0
        for key, val in self.__allpool.copy().items():
            min += 1
            update(min,max)
            if val in used:
                self.__allpool.pop(key)
                continue
            used.append(val)

    def sort(self,pool):
        '''
        Sorting logic according to options done here. Some options will require a new gadget search be done in (update gs)
        before actual sorting can take place (ei depth)
        '''
        self.__allpool = pool

        # Duplicates
        if len(self.ui.lineEdit.text()) > 0:
            self.currentlyUnique = False
        if not self.duplicates:
            if not self.currentlyUnique:
                run_progress_dialog("Removing duplicates",False,self.remove_dups)
                pool = self.__allpool
                self.currentlyUnique = True
        else:
            self.currentlyUnique = False

        pool = self.__allpool
        temp = pool.copy()

        # Bad bytes sort
        if self.bad_bytes != []:
            for b in self.bad_bytes:
                for addr in list(pool.keys()):
                    if b in hex(addr):
                        if addr in pool:
                            pool.pop(addr)

        # Hard pnemonic block sort
        if self.block != []:
            for insn in self.block:
                for key,val in temp.items():
                    if insn in val:
                        if key in pool:
                            pool.pop(key)

        # Address range sort
        if self.address_range != []:
            for a in list(pool.keys()):
                if not (a > self.address_range[0] and a < self.address_range[1]):
                    if a in pool:
                        pool.pop(a)

        # Inst cnt
        if self.inst_cnt != 0:
            for key, val in temp.items():
                if len(val.split(';'))-1 > self.inst_cnt:
                    if key in pool:
                        pool.pop(key)

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
        globs = {"__builtins__": {}}
        try:
            ret = int(eval(value, globs, {}))
        except:
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
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        sys = self.gs.sys
        thumb = self.ui.thumbOpt.isChecked()
        fflush(self.bv)
        self.bv.session_data['RopView']['cache_coherent'] = False
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

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
        if re.match('0x[0-9a-f]*-0x[0-9a-f]*',self.ui.rangeEdit.text()) is not None:
            addr = self.ui.rangeEdit.text().split('-')
            try:
                self.address_range.append(int(addr[0],16))
                self.address_range.append(int(addr[1],16))
            except:
                self.address_range = []
                return
            self.update_and_sort()

    def prepareInstCnt(self):
        self.inst_cnt = int(self.ui.instCntSpinbox.text())
        if self.inst_cnt != 0:
            self.update_and_sort()

    def prepareRepeat(self):
        self.duplicates = self.ui.allOpt.isChecked()
        dep = self.gs.depth
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        sys = self.gs.sys
        thumb = self.ui.thumbOpt.isChecked()
        fflush(self.bv)
        self.bv.session_data['RopView']['cache_coherent'] = False
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

    def prepareROP(self):
        rop = self.ui.ropOpt.isChecked()
        dep = self.gs.depth
        jop = self.gs.jop
        cop = self.gs.cop
        sys = self.gs.sys
        thumb = self.ui.thumbOpt.isChecked()
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

    def prepareCOP(self):
        cop = self.ui.copOpt.isChecked()
        dep = self.gs.depth
        rop = self.gs.rop
        jop = self.gs.jop
        sys = self.gs.sys
        thumb = self.ui.thumbOpt.isChecked()
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

    def prepareJOP(self):
        jop = self.ui.jopOpt.isChecked()
        dep = self.gs.depth
        rop = self.gs.rop
        cop = self.gs.cop
        sys = self.gs.sys
        thumb = self.ui.thumbOpt.isChecked()
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

    def prepareThumb(self):
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        dep = self.gs.depth
        sys = self.gs.sys
        thumb = self.ui.thumbOpt.isChecked()
        fflush(self.bv)
        self.bv.session_data['RopView']['gadget_disasm'] = {}
        self.bv.session_data['RopView']['gadget_asm'] = {}
        self.bv.session_data['RopView']['cache_coherent'] = False
        self.bv.session_data['RopView']['thumb'] = thumb
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

    def preparesys(self):
        sys = self.ui.sysOpt.isChecked()
        dep = self.gs.depth
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        thumb = self.ui.thumbOpt.isChecked()
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)

    def export_gadgets(self):
        if self.bv.session_data['RopView']['dataframe'] is not None:
            df = self.bv.session_data['RopView']['dataframe'].copy()
            df.replace(REG_CONTROLLED,'Controlled',inplace=True)
            df.replace(REG_NOT_ANALYZED,'Unanalyzed',inplace=True)
            df.to_csv(get_save_filename_input("filename:", "csv", "gadgets.csv"), sep='\t')
        else:
            show_message_box("Dataframe uninitialized","Start a search to create dataframe")

    def flush(self):
        fflush(self.bv)
        show_message_box("Cache cleared","Gadget caches flushed")

    def gsearch(self):
        sys = self.gs.sys
        dep = self.gs.depth
        rop = self.gs.rop
        jop = self.gs.jop
        cop = self.gs.cop
        thumb = self.ui.thumbOpt.isChecked()
        self.repool(dep,rop,jop,cop,sys,thumb=thumb)
        

    def prepareDump(self):
        self.dump = self.ui.dumpOpt.isChecked()
        if self.dump:
            self.ui.gadgetPane.showColumn(1)
        else:
            self.ui.gadgetPane.hideColumn(1)
        self.update_and_sort()
        self.ui.gadgetPane.resizeColumnToContents(1)