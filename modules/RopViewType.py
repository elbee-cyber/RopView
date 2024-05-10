from binaryninja import binaryview
from binaryninjaui import View, ViewType
from PySide6.QtCore import Qt, QCoreApplication
from PySide6.QtGui import *
from PySide6.QtWidgets import QTreeWidgetItem, QScrollArea
from .ui.ui_mainwindow import Ui_Form
from .GadgetSearch import GadgetSearch
from .GadgetAnalysis import GadgetAnalysis
import logging

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
		ga = GadgetAnalysis(addr,gadget_str,self.binaryView,self.gs.gadget_pool_raw)

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
