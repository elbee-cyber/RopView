from binaryninja import binaryview
from binaryninjaui import View, ViewType
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QScrollArea, QWidget, QGridLayout, QLineEdit, QComboBox, QCheckBox, QListWidget, QListWidgetItem, QLabel, QGroupBox, QHBoxLayout
from .ui.ui_mainwindow import Ui_Form
from .GadgetSearch import GadgetSearch
import logging

class RopView(QScrollArea, View):
	def __init__(self, parent, binaryView):
		QScrollArea.__init__(self, parent)
		View.__init__(self)
		View.setBinaryDataNavigable(self, False)
		self.setupView(self)
		self.binaryView = binaryView
		self.ui = Ui_Form()
		self.ui.setupUi(self)

		#gs = GadgetSearch(binaryView)
		#for addr, text in gs.gadget_pool.items():
		#	self.ui.listWidget_2.addItem(hex(addr)+" "+str(text))

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
