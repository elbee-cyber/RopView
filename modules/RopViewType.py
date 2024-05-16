from binaryninja import binaryview
from binaryninjaui import View, ViewType
from PySide6.QtCore import Qt
from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem, QScrollArea, QListWidgetItem, QListWidget
from .ui.ui_mainwindow import Ui_Form
from .GadgetSearch import GadgetSearch
from .GadgetAnalysis import GadgetAnalysis
from binaryninja import *
from .constants import *

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
		# Base UI
		QScrollArea.__init__(self, parent)
		View.__init__(self)
		View.setBinaryDataNavigable(self, False)
		self.setupView(self)
		self.binaryView = binaryView
		self.ui = Ui_Form()
		self.ui.setupUi(self)
		
		# Gadget Pane
		self.gs = GadgetSearch(binaryView)
		gadgets = self.gs.gadget_pool.items()
		addr_color = QBrush(QColor(108, 193, 108, 255))
		disasm_color = QBrush(QColor(255, 255, 255, 255))
		font = QFont()
		font.setFamily(u"Hack")
		# Slot/signal, double clicking a gadget navigates to linear bv address
		self.ui.gadgetPane.itemDoubleClicked.connect(self.goto_address)
		# Add gadgets to gadget search pane
		self.ui.statusLabel.setText("Gadget count: "+str(len(gadgets)))
		for addr, text in gadgets:
			item = QTreeWidgetItem(self.ui.gadgetPane.topLevelItemCount())
			item.setText(0,hex(addr))
			item.setFont(1,font)
			item.setText(1,text)
			item.setForeground(0,addr_color)
			item.setForeground(1,disasm_color)
			self.ui.gadgetPane.addTopLevelItem(item)
		
		# Slot/signal, navigating gadget search pane populates analysis pane for selected gadget
		self.ui.gadgetPane.itemSelectionChanged.connect(self.gadgetAnalysis)

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
		except:
			pass
	
	def gadgetAnalysis(self):
		'''
		Gadget analysis, analysis pane UI and analysis case handling
		'''
		# Address of currently selected gadget
		addr = int(self.ui.gadgetPane.selectedItems()[0].text(0),16)
		# Mnemonic of currently selected gadget
		gadget_str = self.ui.gadgetPane.selectedItems()[0].text(1)

		# Create a new GadgetAnalysis from current context and selected gadget
		ga = GadgetAnalysis(self.binaryView.arch.name, addr, gadget_str, self.gs.gadget_pool_raw, self.gs.gadget_pool)
		details = ga.analyze()
		effects = details[0]
		end_state = ga.end_state.copy()

		# Handling done via caller in place of recursion because of weird unicorn issues
		# Handling for Case 1: Stack pivot
		errno = details[1]
		while details[1] == GA_ERR_STACKPIVOT:
			# Create new GadgetAnalysis based on remaining gadget after stack pivot with a precontext of the state before the stack pivot
			ga = GadgetAnalysis(self.binaryView.arch.name, -1, details[2], self.gs.gadget_pool_raw, self.gs.gadget_pool)
			ga.set_prestate(end_state)
			details = ga.analyze()
			effects = effects + details[0]
			ga.emulated[gadget_str] = effects
			ga.instructions = gadget_str.split(';')
			ga.end_state = end_state | ga.end_state.copy()
			ga.saved_end_states[gadget_str] = ga.end_state
		if errno == GA_ERR_STACKPIVOT:
			ga.saved_fails[gadget_str] = 0

		# Rename lower-access registers without spaces or brackets
		for key in list(ga.end_state.keys()):
			newkey = key.replace(' ','')
			newkey = newkey.replace('[','')
			ga.end_state[newkey] = ga.end_state.pop(key)
		for key in list(ga.prestate.keys()):
			newkey = key.replace(' ','')
			newkey = newkey.replace('[','')
			ga.prestate[newkey] = ga.prestate.pop(key)
		
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

		for key,value in ga.prestate.items():
			item = QListWidgetItem(detailPane)
			item.setText(key+" = "+hex(value))
			item.setFont(itemFont)
			detailPane.addItem(item)

		# Empty gadget
		if len(ga.prestate.items()) == 0:
			item = QListWidgetItem(detailPane)
			item.setText("Empty gadget")
			item.setFont(itemFont)
			detailPane.addItem(item)

		# Instructions
		i = 0
		for inst in ga.instructions:
			space = QListWidgetItem(detailPane)
			detailPane.addItem(space)
			if inst == ga.instructions[-2]:
				break
			if inst[0] == ' ':
				inst = inst[1:]
			itemLabel = QListWidgetItem(detailPane)
			itemLabel.setText(inst)
			itemLabel.setFont(labelFont)
			detailPane.addItem(itemLabel)
			try:
				for key,value in effects[i].items():
					item = QListWidgetItem(detailPane)
					item.setText(key+" -> "+str(value))
					item.setFont(itemFont)
					detailPane.addItem(item)
			# An index error will occur if an error ended GadgetAnalysis early
			except IndexError:
				detailPane.takeItem(detailPane.count()-1)
				break
			i += 1

		# End state
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
			detailPane.addItem(item)
			return

		for key,value in ga.end_state.items():
			item = QListWidgetItem(detailPane)
			try:
				item.setText(key+" = "+hex(value))
			except TypeError:
				item.setText(key+" = "+value)
			item.setFont(itemFont)
			detailPane.addItem(item)


	def getCurrentOffset(self):
		return 0

	def getData(self):
		return self.binaryView

class RopViewType(ViewType):
	def __init__(self):
		super(RopViewType, self).__init__("Untitled ROPTool View", "Untitled ROPTool View")

	def create(self, binaryView, view_frame):
		return RopView(view_frame, binaryView)

	def getPriority(self, binaryView, filename):
		return 1
