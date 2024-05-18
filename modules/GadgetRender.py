from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem
from .GadgetSearch import GadgetSearch
from .constants import *
from binaryninja import log_info

class GadgetRender:

    def __init__(self, bv, ui):
        self.bad_bytes = []
        self.depth = 16
        self.block = []
        self.quality = 0
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

        self.gs = GadgetSearch(bv)
        self.pool_sorted = self.gs.gadget_pool.items()
        self.render_gadgets(self.pool_sorted)

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
                reg_label.setVisible(False)
                getattr(self.ui,"regedit_"+str(i)).setVisible(False)
            i += 1
        log_info(i,'stuff')

    def update_and_sort(self):
        pass
    
    def clear_gadgets(self):
        self.ui.statusLabel.setText("")
        self.ui.gadgetPane.clear()

    def render_gadgets(self,pool):
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

    def sort(self):
        if self.bad_bytes != []:
            pass
        