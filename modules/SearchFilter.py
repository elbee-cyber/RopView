from .constants import *
from .GadgetSearch import *

class SearchFilter:

    def __init__(self, bv, ui):
        self.ui = ui
        self.bv = bv
        self.ui.lineEdit.returnPressed.connect(self.parsefilter)

    def parsefilter(self):
        debug_notify("Checking")

    def getQuery(self):
        return self.ui.lineEdit.text()