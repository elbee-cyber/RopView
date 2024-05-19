from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem
from .GadgetSearch import GadgetSearch
from .constants import *
from binaryninja import log_info

class GadgetRender:
    '''
    Responsible for doing gadget search, rendering to UI gadget search pane, 
    connecting option changes and updating the pane based on option changes.
    '''
    def __init__(self, bv, ui):
        '''
        Configure default options, initial gadgetsearch, display right registers into prestate options ui.
        '''
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
        '''
        self.clear_gadgets()
        # NOTE:
        # Sorted pool should be a deep copy and not effect the gs pool, the gs pool reference
        # should be maintained for future sorting.
        self.sort(pool)
        self.render_gadgets(pool)
    
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
        if self.bad_bytes != []:
            pass

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