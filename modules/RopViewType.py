from binaryninjaui import View, ViewType
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QScrollArea, QListWidgetItem
from binaryninja import run_progress_dialog, execute_on_main_thread_and_wait, show_message_box

from .ui.ui_mainwindow import Ui_Form
from .GadgetAnalysis import GadgetAnalysis
from .GadgetRender import GadgetRender
from .SearchFilter import SearchFilter
from .constants import arch, err_desc


class RopView(QScrollArea, View):
    '''
    UI initialization and initial view setup for search and analysis.
    '''

    def __init__(self, parent, binaryView):
        '''
        Sets up UI and performs initial gadget search
        :param parent: Super class of Qt UI object
        :param binaryView: Current binaryview
        '''

        # Session data
        binaryView.session_data['RopView'] = {}
        binaryView.session_data['RopView']['cache'] = {}
        binaryView.session_data['RopView']['gadget_disasm'] = {}
        binaryView.session_data['RopView']['gadget_asm'] = {}
        binaryView.session_data['RopView']['cache']['rop_disasm'] = {}
        binaryView.session_data['RopView']['cache']['rop_asm'] = {}
        binaryView.session_data['RopView']['cache']['jop_disasm'] = {}
        binaryView.session_data['RopView']['cache']['jop_asm'] = {}
        binaryView.session_data['RopView']['cache']['cop_disasm'] = {}
        binaryView.session_data['RopView']['cache']['cop_asm'] = {}
        binaryView.session_data['RopView']['cache']['sys_disasm'] = {}
        binaryView.session_data['RopView']['cache']['sys_asm'] = {}
        binaryView.session_data['RopView']['depth'] = 10
        binaryView.session_data['RopView']['cache']['analysis'] = {}
        binaryView.session_data['RopView']['presets'] = {}
        binaryView.session_data['RopView']['analysis_enabled'] = True
        binaryView.session_data['RopView']['cache_coherent'] = True
        binaryView.session_data['RopView']['thumb'] = False
        binaryView.session_data['RopView']['dataframe'] = None
        binaryView.session_data['RopView']['cf'] = None

        # Base UI
        QScrollArea.__init__(self, parent)
        View.__init__(self)
        View.setBinaryDataNavigable(self, False)
        self.setupView(self)
        self.binaryView = binaryView
        self.ui = Ui_Form()
        self.ui.setupUi(self)
        self.ui.gadgetPane.hideColumn(1)
        self.ui.gadgetPane.resizeColumnToContents(2)

        # Restore saved caches
        try:
            run_progress_dialog("Loading from cache",False,self.loadCache)
        except KeyError:
            pass

        # Support check
        if binaryView.arch.name not in arch or arch[binaryView.arch.name] == {}:
            show_message_box("Unsupported Architecture","{} is not yet supported!".format(binaryView.arch.name))
            self.ui.resultsLabel.setText("Unsupported file type: {}".format(binaryView.arch.name))
            self.ui.resultsLabel.setStyleSheet("QLabel { color : red; }")
            return

        # Gadget Pane
        self.renderer = GadgetRender(self.binaryView, self.ui)
        self.curr_prestate = self.renderer.buildPrestate()
        self.emu_queue = []

        # Preset load
        for preset, value in arch[binaryView.arch.name]['presets'].items():
            if preset not in binaryView.session_data['RopView']['presets']:
                binaryView.session_data['RopView']['presets'].update([(preset,value)])
        self.ui.keyView.itemSelectionChanged.connect(self.selectedPresetValue)
        self.updatePresetList()

        # Search
        self.searchfilter = None

        # Slot/signal, double clicking a gadget navigates to linear bv address
        self.ui.gadgetPane.itemDoubleClicked.connect(self.goto_address)

        # Render
        self.ui.lineEdit.returnPressed.connect(self.querySetup)

        # Add preset
        self.ui.presetButton.clicked.connect(self.addPreset)

        # Slot/signal, navigating gadget search pane populates analysis pane for selected gadget
        self.ui.gadgetPane.itemSelectionChanged.connect(self.startAnalysis)

        # Add text changed signals to analysis prestate options
        regedit = getattr(self.ui,"regedit",-1)
        regedit.textChanged.connect(self.updatePrestate)
        i = 2
        while regedit != -1:
            regedit = getattr(self.ui,"regedit_" + str(i),-1)
            if regedit == -1:
                break
            regedit.textChanged.connect(self.updatePrestate)
            i += 1

    def loadCache(self,update):
        curr = 0
        full = 10
        try:
            self.binaryView.session_data['RopView']['cache']['rop_disasm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.rop_disasm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['rop_asm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.rop_asm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['jop_disasm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.jop_disasm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['jop_asm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.jop_asm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['cop_disasm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.cop_disasm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['cop_asm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.cop_asm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['sys_disasm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.sys_disasm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['cache']['sys_asm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.sys_asm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['gadget_disasm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.gadget_disasm").items()})
            curr += 1
            update(curr,full)
            self.binaryView.session_data['RopView']['gadget_asm'].update({int(k):v for k,v in self.binaryView.query_metadata("RopView.gadget_asm").items()})
            self.binaryView.session_data['RopView']['presets'].update({str(k):v for k,v in self.binaryView.query_metadata("RopView.presets").items()})
        except Exception:
            return

    def goto_address(self, item, column):
        '''
        Slot to navigate to address in linear view for selected gadget
        :param item: Selected item
        :param column: Selected column
        '''
        # Get address of selected item
        addr = int(item.text(0),16)
        try:
            self.binaryView.navigate('Linear:ELF',addr)
        except Exception:
            pass

    def updatePresetList(self):
        pane = self.ui.keyView
        pane.clear()
        pane.addItems(list(self.binaryView.session_data['RopView']['presets'].keys()))

    def selectedPresetValue(self):
        pane = self.ui.defView
        pane.clear()
        pane.addItems([self.binaryView.session_data['RopView']['presets'][self.ui.keyView.currentItem().text()]])

    def addPreset(self):
        if len(self.ui.keyEdit.toPlainText()) > 0 and len(self.ui.defEdit.toPlainText()) > 0:
            self.binaryView.session_data['RopView']['presets'][self.ui.keyEdit.toPlainText()] = self.ui.defEdit.toPlainText()
            self.binaryView.store_metadata("RopView.presets",self.binaryView.session_data['RopView']['presets'])
            self.updatePresetList()
            self.ui.presetStatus.setText("Preset added!")
        else:
            self.ui.presetStatus.setText("Invalid preset (Bad key or definition)")

    def updatePrestate(self):
        '''
        Slot for when any prestate option changes values
        Changes current prestate for future analysis
        Reanalyzes currently selected gadget
        '''
        self.binaryView.session_data['RopView']['cache']['analysis'] = {}
        self.curr_prestate = self.renderer.buildPrestate()
        if len(self.ui.gadgetPane.selectedItems()) > 0:
            self.startAnalysis()

    def startAnalysis(self):
        # Prevent overspawn of emulations from scrolling
        if len(self.emu_queue) > 5:
            ga = self.emu_queue.pop(0)
            try:
                ga.uc_release(ga.uc)
                ga.uc.emu_stop()
                del ga
            except Exception:
                pass
        # To avoid crashes due to scrolling (and huge worker queues)
        execute_on_main_thread_and_wait(self.gadgetAnalysis)

    def querySetup(self):
        if len(self.binaryView.session_data['RopView']['gadget_disasm']) > 0 and self.searchfilter is None:
            self.searchfilter = SearchFilter(self.binaryView,self.ui,self.renderer)
            self.ui.semanticBox.setMaximum(len(self.binaryView.session_data['RopView']['gadget_disasm']))
            self.searchfilter.spawnQuery()

    def gadgetAnalysis(self):
        '''
        Gadget analysis, analysis pane UI and analysis case handling
        '''
        if not self.binaryView.session_data['RopView']['analysis_enabled']:
            return

        if len(self.ui.gadgetPane.selectedItems()) == 0 or self.binaryView.session_data['RopView']['gadget_disasm'] == {} or self.binaryView.session_data['RopView']['gadget_asm'] == {}:
            self.ui.detailPane.clear()
            return

        # Address of currently selected gadget
        addr = int(self.ui.gadgetPane.selectedItems()[0].text(0),16)
        # Mnemonic of currently selected gadget
        gadget_str = self.ui.gadgetPane.selectedItems()[0].text(2)

        # GadgetAnalysis
        if addr in self.binaryView.session_data['RopView']['cache']['analysis']:
            ga = self.binaryView.session_data['RopView']['cache']['analysis'][addr]
            effects = ga.results
        else:
            ga = GadgetAnalysis(self.binaryView, addr, gadget_str)
            # Add emu to queue
            self.emu_queue.append(ga)
            ga.set_prestate(self.curr_prestate)
            effects = ga.analyze()[0]
            self.binaryView.session_data['RopView']['cache']['analysis'][addr] = ga.saveState()
        self.renderAnalysisPane(effects,ga)

    def renderAnalysisPane(self,effects,ga):
        detailPane = self.ui.detailPane
        for i in range(0,detailPane.count()):
            detailPane.takeItem(0)

        labelFont = QFont(u"Hack",14)
        itemFont = QFont(u"Hack",12)

        # Before analysis
        beforeLabel = QListWidgetItem(detailPane)
        beforeLabel.setText("Before analysis:")
        beforeLabel.setFont(labelFont)
        detailPane.addItem(beforeLabel)

        if not ga.used_regs:
            item = QListWidgetItem(detailPane)
            item.setText("No registers to list (gadget doesn't clobber)")
            item.setFont(itemFont)
            detailPane.addItem(item)
        else:
            for key,value in ga.used_regs.items():
                item = QListWidgetItem(detailPane)
                if 'sp' in key:
                    item.setText(key + " = " + hex(value) + ' (emulator stack pointer)')
                else:
                    item.setText(key + " = " + hex(value))
                item.setFont(itemFont)
                detailPane.addItem(item)

        # Instructions
        i = 0
        for inst in ga.instructions:
            space = QListWidgetItem(detailPane)
            detailPane.addItem(space)
            # if inst == ga.instructions[-1]:
            # 	break
            if inst[0] == ' ':
                inst = inst[1:]
            itemLabel = QListWidgetItem(detailPane)
            itemLabel.setText(inst)
            itemLabel.setFont(labelFont)
            detailPane.addItem(itemLabel)
            try:
                for key,value in effects[i].items():
                    item = QListWidgetItem(detailPane)
                    item.setText(key + " -> " + str(value))
                    item.setFont(itemFont)
                    detailPane.addItem(item)
            # An index error will occur if an error ended GadgetAnalysis early
            except IndexError:
                detailPane.takeItem(detailPane.count() - 1)
                break
            i += 1

        # End state
        if len(ga.instructions) == len(effects):
            space = QListWidgetItem(detailPane)
            detailPane.addItem(space)
        afterLabel = QListWidgetItem(detailPane)
        afterLabel.setText("After analysis:")
        afterLabel.setFont(labelFont)
        detailPane.addItem(afterLabel)

        # Empty gadget
        if len(ga.prestate.items()) == 0:
            item = QListWidgetItem(detailPane)
            item.setText("Empty gadget")
            item.setFont(itemFont)
            detailPane.addItem(item)

        if ga.err != 0:
            item = QListWidgetItem(detailPane)
            item.setText("Analysis aborted")
            item.setFont(itemFont)
            itemBody = QListWidgetItem(detailPane)
            reason = err_desc[ga.err]
            if ga.last_access != []:
                try:
                    reason += ' (deref: {})'.format(hex(ga.last_access[0]))
                except Exception:
                    reason += ' (deref: {})'.format(ga.last_access[0])
            itemBody.setText("Reason: " + reason)
            itemBody.setFont(itemFont)
            detailPane.addItem(item)
            detailPane.addItem(itemBody)
            return

        if not ga.end_state:
            item = QListWidgetItem(detailPane)
            item.setText("No registers to list (gadget doesn't clobber)")
            item.setFont(itemFont)
            detailPane.addItem(item)
        else:
            for key,value in ga.end_state.items():
                item = QListWidgetItem(detailPane)
                try:
                    item.setText(key + " = " + hex(value))
                except TypeError:
                    if '0x' in key:
                        item.setText('*' + key + ' = ' + value)
                    else:
                        item.setText(key + " = " + value)
                item.setFont(itemFont)
                detailPane.addItem(item)

        if ga.err == 0 and ga.last_access != [] and ga.last_access[0] != 0:
            space = QListWidgetItem(detailPane)
            detailPane.addItem(space)

            item = QListWidgetItem(detailPane)
            ret_status = "Gadget returns execution to "
            if "Stack" in str(ga.last_access[0]):
                ret_status += "sp+" + str(ga.last_access[1])
            else:
                ret_status += hex(ga.last_access[0])
            item.setText(ret_status)
            item.setFont(itemFont)
            detailPane.addItem(item)

    def getCurrentOffset(self):
        return 0

    def getData(self):
        return self.binaryView


class RopViewType(ViewType):
    def __init__(self):
        super(RopViewType, self).__init__("RopView", "RopView")

    def create(self, binaryView, view_frame):
        return RopView(view_frame, binaryView)

    def getPriority(self, binaryView, filename):
        return 1
