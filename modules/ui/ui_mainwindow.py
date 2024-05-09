# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'mainwindow.ui'
##
## Created by: Qt User Interface Compiler version 6.7.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListView, QListWidget, QListWidgetItem,
    QPushButton, QSizePolicy, QSplitter, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

class Ui_Form(object):
    def setupUi(self, Form):
        if not Form.objectName():
            Form.setObjectName(u"Form")
        Form.resize(760, 502)
        Form.setFocusPolicy(Qt.NoFocus)
        self.verticalLayout = QVBoxLayout(Form)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.lineEdit = QLineEdit(Form)
        self.lineEdit.setObjectName(u"lineEdit")
        font = QFont()
        font.setFamilies([u"Ubuntu"])
        font.setPointSize(22)
        font.setItalic(False)
        self.lineEdit.setFont(font)
        self.lineEdit.setClearButtonEnabled(True)

        self.verticalLayout.addWidget(self.lineEdit)

        self.statusLabel = QLabel(Form)
        self.statusLabel.setObjectName(u"statusLabel")
        font1 = QFont()
        font1.setPointSize(9)
        self.statusLabel.setFont(font1)
        self.statusLabel.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.verticalLayout.addWidget(self.statusLabel)

        self.tabWidget = QTabWidget(Form)
        self.tabWidget.setObjectName(u"tabWidget")
        self.tabWidget.setEnabled(True)
        font2 = QFont()
        font2.setFamilies([u"Ubuntu"])
        self.tabWidget.setFont(font2)
        self.tabWidget.setAutoFillBackground(False)
        self.tabWidget.setStyleSheet(u"QTabWidget::pane { border: 0; }")
        self.tabWidget.setTabPosition(QTabWidget.North)
        self.tabWidget.setTabShape(QTabWidget.Rounded)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setMovable(False)
        self.tabWidget.setTabBarAutoHide(False)
        self.GadgetView = QWidget()
        self.GadgetView.setObjectName(u"GadgetView")
        self.horizontalLayout = QHBoxLayout(self.GadgetView)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.splitter = QSplitter(self.GadgetView)
        self.splitter.setObjectName(u"splitter")
        self.splitter.setOrientation(Qt.Horizontal)
        self.gadgetPane = QTreeWidget(self.splitter)
        self.gadgetPane.setObjectName(u"gadgetPane")
        self.gadgetPane.setEnabled(True)
        self.gadgetPane.setAutoFillBackground(False)
        self.gadgetPane.setStyleSheet(u"")
        self.gadgetPane.setEditTriggers(QAbstractItemView.AnyKeyPressed|QAbstractItemView.DoubleClicked)
        self.gadgetPane.setTabKeyNavigation(True)
        self.gadgetPane.setIndentation(0)
        self.gadgetPane.setRootIsDecorated(True)
        self.gadgetPane.setUniformRowHeights(False)
        self.gadgetPane.setItemsExpandable(False)
        self.gadgetPane.setSortingEnabled(False)
        self.gadgetPane.setHeaderHidden(True)
        self.splitter.addWidget(self.gadgetPane)
        self.detailPane = QListWidget(self.splitter)
        self.detailPane.setObjectName(u"detailPane")
        self.splitter.addWidget(self.detailPane)

        self.horizontalLayout.addWidget(self.splitter)

        self.tabWidget.addTab(self.GadgetView, "")
        self.ChainView = QWidget()
        self.ChainView.setObjectName(u"ChainView")
        self.gridLayout = QGridLayout(self.ChainView)
        self.gridLayout.setObjectName(u"gridLayout")
        self.ExportButton = QPushButton(self.ChainView)
        self.ExportButton.setObjectName(u"ExportButton")
        self.ExportButton.setFlat(False)

        self.gridLayout.addWidget(self.ExportButton, 2, 0, 1, 1)

        self.ExportType = QComboBox(self.ChainView)
        self.ExportType.addItem("")
        self.ExportType.addItem("")
        self.ExportType.setObjectName(u"ExportType")

        self.gridLayout.addWidget(self.ExportType, 1, 0, 1, 1)

        self.ChainWindow = QListView(self.ChainView)
        self.ChainWindow.setObjectName(u"ChainWindow")
        self.ChainWindow.setFrameShape(QFrame.NoFrame)
        self.ChainWindow.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.gridLayout.addWidget(self.ChainWindow, 0, 0, 1, 1)

        self.tabWidget.addTab(self.ChainView, "")
        self.OptionsView = QWidget()
        self.OptionsView.setObjectName(u"OptionsView")
        self.OptionsView.setAutoFillBackground(True)
        self.tabWidget.addTab(self.OptionsView, "")

        self.verticalLayout.addWidget(self.tabWidget)


        self.retranslateUi(Form)

        self.tabWidget.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(Form)
    # setupUi

    def retranslateUi(self, Form):
        Form.setWindowTitle(QCoreApplication.translate("Form", u"Form", None))
        self.lineEdit.setPlaceholderText(QCoreApplication.translate("Form", u"Search filter", None))
        self.statusLabel.setText("")
        ___qtreewidgetitem = self.gadgetPane.headerItem()
        ___qtreewidgetitem.setText(1, QCoreApplication.translate("Form", u"Gadget", None));
        ___qtreewidgetitem.setText(0, QCoreApplication.translate("Form", u"Location", None));
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.GadgetView), QCoreApplication.translate("Form", u"ROP View", None))
        self.ExportButton.setText(QCoreApplication.translate("Form", u"Export", None))
        self.ExportType.setItemText(0, QCoreApplication.translate("Form", u"pwntools", None))
        self.ExportType.setItemText(1, QCoreApplication.translate("Form", u"packed", None))

        self.tabWidget.setTabText(self.tabWidget.indexOf(self.ChainView), QCoreApplication.translate("Form", u"Chain Builder", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.OptionsView), QCoreApplication.translate("Form", u"Options", None))
    # retranslateUi

