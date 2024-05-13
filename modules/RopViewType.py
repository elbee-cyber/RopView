from binaryninja import binaryview
from binaryninjaui import View, ViewType
from PySide6.QtCore import Qt, QCoreApplication
from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem, QScrollArea, QListWidgetItem, QListWidget
from .ui.ui_mainwindow import Ui_Form
from .GadgetSearch import GadgetSearch
from .GadgetAnalysis import GadgetAnalysis
from binaryninja import *
from .constants import *

# TODO pydoc

class RopView(QScrollArea, View):
	def __init__(self, parent, binaryView):
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
		self.ui.gadgetPane.itemDoubleClicked.connect(self.goto_address)
		#self.ui.gadgetPane.setSortingEnabled(True)
		self.ui.gadgetPane.setStyleSheet("QTreeWidget::item:selected {background : transparent;}")
		self.ui.statusLabel.setText("Gadget count: "+str(len(gadgets)))
		for addr, text in gadgets:
			item = QTreeWidgetItem(self.ui.gadgetPane.topLevelItemCount())
			item.setText(0,hex(addr))
			item.setFont(1,font)
			item.setText(1,text)
			item.setForeground(0,addr_color)
			item.setForeground(1,disasm_color)
			self.ui.gadgetPane.addTopLevelItem(item)
		
		# Details Pane (GadgetAnalysis)
		self.ui.gadgetPane.itemSelectionChanged.connect(self.gadgetAnalysis)

	def goto_address(self,item,column):
		addr = int(item.text(0),16)
		try:
			# In the future, do something to make this work with something besides ELFs
			self.binaryView.navigate('Linear:ELF',addr)
		except:
			pass
	
	def gadgetAnalysis(self):
		addr = int(self.ui.gadgetPane.selectedItems()[0].text(0),16)
		gadget_str = self.ui.gadgetPane.selectedItems()[0].text(1)
		ga = GadgetAnalysis(self.binaryView.arch.name, addr, gadget_str, self.gs.gadget_pool_raw, self.gs.gadget_pool)
		details = ga.analyze()
		effects = details[0]
		end_state = ga.end_state.copy()
		# Handling for Case 1: Stack pivot
		while details[1] == GA_ERR_STACKPIVOT:
			ga = GadgetAnalysis(self.binaryView.arch.name, -1, details[2], self.gs.gadget_pool_raw, self.gs.gadget_pool)
			ga.set_prestate(effects[-1])
			details = ga.analyze()
			effects = effects + details[0]
			ga.emulated[gadget_str] = effects
			ga.instructions = gadget_str.split(';')
			ga.end_state = end_state | ga.end_state.copy()
			ga.saved_end_states[gadget_str] = ga.end_state.copy()
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
			for key,value in effects[i].items():
				item = QListWidgetItem(detailPane)
				item.setText(key+" -> "+str(value))
				item.setFont(itemFont)
				detailPane.addItem(item)
			i += 1

		# End state
		afterLabel = QListWidgetItem(detailPane)
		afterLabel.setText("After analysis:")
		afterLabel.setFont(labelFont)
		detailPane.addItem(afterLabel)

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
