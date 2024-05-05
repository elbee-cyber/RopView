from binaryninja import binaryview
from binaryninjaui import View, ViewType
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QScrollArea, QWidget, QGridLayout, QLineEdit, QComboBox

class RopView(QScrollArea, View):
	def __init__(self, parent, binaryView):
		QScrollArea.__init__(self, parent)
		View.__init__(self)
		View.setBinaryDataNavigable(self, False)
		self.setupView(self)

		self.binaryView = binaryView
		container = QWidget(self)
		layout = QGridLayout()

		combo_box = QComboBox()
		combo_box.addItem("Gadget (pnemonic)")
		combo_box.addItem("Gadget (bytes)")
		combo_box.addItem("Search filter")
		combo_box.addItem("Effected register(s)")
		combo_box.addItem("Instruction")
		combo_box.setFixedHeight(40)

		searchBox = QLineEdit()
		font = searchBox.font()
		font.setPointSize(20)
		searchBox.setFont(font)
		searchBox.setClearButtonEnabled(True)
		searchBox.setFixedWidth(1000)
		searchBox.setFixedHeight(40)
		searchBox.setPlaceholderText("Pnemonics, bytes or search filter")

		layout.addWidget(combo_box,0,0)
		layout.addWidget(searchBox,0,1)
		container.setLayout(layout)
		self.setWidget(container)

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
