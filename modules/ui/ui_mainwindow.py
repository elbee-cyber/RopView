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
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPushButton, QSizePolicy, QSpacerItem, QSpinBox,
    QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget)

class Ui_Form(object):
    def setupUi(self, Form):
        if not Form.objectName():
            Form.setObjectName(u"Form")
        Form.resize(1468, 769)
        Form.setFocusPolicy(Qt.NoFocus)
        self.verticalLayout_7 = QVBoxLayout(Form)
        self.verticalLayout_7.setObjectName(u"verticalLayout_7")
        self.verticalLayout = QVBoxLayout()
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

        self.horizontalLayout_5 = QHBoxLayout()
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.resultsLabel = QLabel(Form)
        self.resultsLabel.setObjectName(u"resultsLabel")
        font1 = QFont()
        font1.setPointSize(9)
        self.resultsLabel.setFont(font1)
        self.resultsLabel.setAlignment(Qt.AlignLeading|Qt.AlignLeft|Qt.AlignVCenter)

        self.horizontalLayout_5.addWidget(self.resultsLabel)

        self.statusLabel = QLabel(Form)
        self.statusLabel.setObjectName(u"statusLabel")
        self.statusLabel.setFont(font1)
        self.statusLabel.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_5.addWidget(self.statusLabel)


        self.verticalLayout.addLayout(self.horizontalLayout_5)

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
        self.tabWidget.setElideMode(Qt.ElideNone)
        self.tabWidget.setUsesScrollButtons(True)
        self.tabWidget.setDocumentMode(False)
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
        self.ChainView.setEnabled(False)
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

        self.ChainWindow = QListWidget(self.ChainView)
        QListWidgetItem(self.ChainWindow)
        self.ChainWindow.setObjectName(u"ChainWindow")
        self.ChainWindow.setFrameShape(QFrame.NoFrame)
        self.ChainWindow.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.gridLayout.addWidget(self.ChainWindow, 0, 0, 1, 1)

        self.tabWidget.addTab(self.ChainView, "")
        self.OptionsView = QWidget()
        self.OptionsView.setObjectName(u"OptionsView")
        self.OptionsView.setAutoFillBackground(True)
        self.verticalLayout_6 = QVBoxLayout(self.OptionsView)
        self.verticalLayout_6.setObjectName(u"verticalLayout_6")
        self.horizontalLayout_4 = QHBoxLayout()
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.verticalSpacer_2 = QSpacerItem(255, 508, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.horizontalLayout_4.addItem(self.verticalSpacer_2)

        self.verticalLayout_4 = QVBoxLayout()
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.horizontalSpacer_2 = QSpacerItem(756, 38, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.verticalLayout_4.addItem(self.horizontalSpacer_2)

        self.prestateOptions = QVBoxLayout()
        self.prestateOptions.setObjectName(u"prestateOptions")
        self.prestateOptions_2 = QVBoxLayout()
        self.prestateOptions_2.setObjectName(u"prestateOptions_2")
        self.prestateLabel = QLabel(self.OptionsView)
        self.prestateLabel.setObjectName(u"prestateLabel")
        font3 = QFont()
        font3.setPointSize(18)
        font3.setBold(True)
        self.prestateLabel.setFont(font3)
        self.prestateLabel.setAlignment(Qt.AlignCenter)

        self.prestateOptions_2.addWidget(self.prestateLabel)

        self.registers = QHBoxLayout()
        self.registers.setObjectName(u"registers")
        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.regOption = QHBoxLayout()
        self.regOption.setObjectName(u"regOption")
        self.reglabel = QLabel(self.OptionsView)
        self.reglabel.setObjectName(u"reglabel")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.reglabel.sizePolicy().hasHeightForWidth())
        self.reglabel.setSizePolicy(sizePolicy)
        font4 = QFont()
        font4.setPointSize(10)
        self.reglabel.setFont(font4)

        self.regOption.addWidget(self.reglabel)

        self.regedit = QLineEdit(self.OptionsView)
        self.regedit.setObjectName(u"regedit")
        sizePolicy.setHeightForWidth(self.regedit.sizePolicy().hasHeightForWidth())
        self.regedit.setSizePolicy(sizePolicy)
        self.regedit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption.addWidget(self.regedit)


        self.verticalLayout_2.addLayout(self.regOption)

        self.regOption_2 = QHBoxLayout()
        self.regOption_2.setObjectName(u"regOption_2")
        self.reglabel_2 = QLabel(self.OptionsView)
        self.reglabel_2.setObjectName(u"reglabel_2")
        sizePolicy.setHeightForWidth(self.reglabel_2.sizePolicy().hasHeightForWidth())
        self.reglabel_2.setSizePolicy(sizePolicy)
        self.reglabel_2.setFont(font4)

        self.regOption_2.addWidget(self.reglabel_2)

        self.regedit_2 = QLineEdit(self.OptionsView)
        self.regedit_2.setObjectName(u"regedit_2")
        sizePolicy.setHeightForWidth(self.regedit_2.sizePolicy().hasHeightForWidth())
        self.regedit_2.setSizePolicy(sizePolicy)
        self.regedit_2.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_2.addWidget(self.regedit_2)


        self.verticalLayout_2.addLayout(self.regOption_2)

        self.regOption_3 = QHBoxLayout()
        self.regOption_3.setObjectName(u"regOption_3")
        self.reglabel_3 = QLabel(self.OptionsView)
        self.reglabel_3.setObjectName(u"reglabel_3")
        sizePolicy.setHeightForWidth(self.reglabel_3.sizePolicy().hasHeightForWidth())
        self.reglabel_3.setSizePolicy(sizePolicy)
        self.reglabel_3.setFont(font4)

        self.regOption_3.addWidget(self.reglabel_3)

        self.regedit_3 = QLineEdit(self.OptionsView)
        self.regedit_3.setObjectName(u"regedit_3")
        sizePolicy.setHeightForWidth(self.regedit_3.sizePolicy().hasHeightForWidth())
        self.regedit_3.setSizePolicy(sizePolicy)
        self.regedit_3.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_3.addWidget(self.regedit_3)


        self.verticalLayout_2.addLayout(self.regOption_3)

        self.regOption_4 = QHBoxLayout()
        self.regOption_4.setObjectName(u"regOption_4")
        self.reglabel_4 = QLabel(self.OptionsView)
        self.reglabel_4.setObjectName(u"reglabel_4")
        sizePolicy.setHeightForWidth(self.reglabel_4.sizePolicy().hasHeightForWidth())
        self.reglabel_4.setSizePolicy(sizePolicy)
        self.reglabel_4.setFont(font4)

        self.regOption_4.addWidget(self.reglabel_4)

        self.regedit_4 = QLineEdit(self.OptionsView)
        self.regedit_4.setObjectName(u"regedit_4")
        sizePolicy.setHeightForWidth(self.regedit_4.sizePolicy().hasHeightForWidth())
        self.regedit_4.setSizePolicy(sizePolicy)
        self.regedit_4.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_4.addWidget(self.regedit_4)


        self.verticalLayout_2.addLayout(self.regOption_4)

        self.regOption_5 = QHBoxLayout()
        self.regOption_5.setObjectName(u"regOption_5")
        self.reglabel_5 = QLabel(self.OptionsView)
        self.reglabel_5.setObjectName(u"reglabel_5")
        sizePolicy.setHeightForWidth(self.reglabel_5.sizePolicy().hasHeightForWidth())
        self.reglabel_5.setSizePolicy(sizePolicy)
        self.reglabel_5.setFont(font4)

        self.regOption_5.addWidget(self.reglabel_5)

        self.regedit_5 = QLineEdit(self.OptionsView)
        self.regedit_5.setObjectName(u"regedit_5")
        sizePolicy.setHeightForWidth(self.regedit_5.sizePolicy().hasHeightForWidth())
        self.regedit_5.setSizePolicy(sizePolicy)
        self.regedit_5.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_5.addWidget(self.regedit_5)


        self.verticalLayout_2.addLayout(self.regOption_5)

        self.regOption_6 = QHBoxLayout()
        self.regOption_6.setObjectName(u"regOption_6")
        self.reglabel_6 = QLabel(self.OptionsView)
        self.reglabel_6.setObjectName(u"reglabel_6")
        sizePolicy.setHeightForWidth(self.reglabel_6.sizePolicy().hasHeightForWidth())
        self.reglabel_6.setSizePolicy(sizePolicy)
        self.reglabel_6.setFont(font4)

        self.regOption_6.addWidget(self.reglabel_6)

        self.regedit_6 = QLineEdit(self.OptionsView)
        self.regedit_6.setObjectName(u"regedit_6")
        sizePolicy.setHeightForWidth(self.regedit_6.sizePolicy().hasHeightForWidth())
        self.regedit_6.setSizePolicy(sizePolicy)
        self.regedit_6.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_6.addWidget(self.regedit_6)


        self.verticalLayout_2.addLayout(self.regOption_6)

        self.regOption_7 = QHBoxLayout()
        self.regOption_7.setObjectName(u"regOption_7")
        self.reglabel_7 = QLabel(self.OptionsView)
        self.reglabel_7.setObjectName(u"reglabel_7")
        sizePolicy.setHeightForWidth(self.reglabel_7.sizePolicy().hasHeightForWidth())
        self.reglabel_7.setSizePolicy(sizePolicy)
        self.reglabel_7.setFont(font4)

        self.regOption_7.addWidget(self.reglabel_7)

        self.regedit_7 = QLineEdit(self.OptionsView)
        self.regedit_7.setObjectName(u"regedit_7")
        sizePolicy.setHeightForWidth(self.regedit_7.sizePolicy().hasHeightForWidth())
        self.regedit_7.setSizePolicy(sizePolicy)
        self.regedit_7.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_7.addWidget(self.regedit_7)


        self.verticalLayout_2.addLayout(self.regOption_7)


        self.registers.addLayout(self.verticalLayout_2)

        self.verticalLayout_3 = QVBoxLayout()
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.regOption_8 = QHBoxLayout()
        self.regOption_8.setObjectName(u"regOption_8")
        self.reglabel_8 = QLabel(self.OptionsView)
        self.reglabel_8.setObjectName(u"reglabel_8")
        sizePolicy.setHeightForWidth(self.reglabel_8.sizePolicy().hasHeightForWidth())
        self.reglabel_8.setSizePolicy(sizePolicy)
        self.reglabel_8.setFont(font4)

        self.regOption_8.addWidget(self.reglabel_8)

        self.regedit_8 = QLineEdit(self.OptionsView)
        self.regedit_8.setObjectName(u"regedit_8")
        sizePolicy.setHeightForWidth(self.regedit_8.sizePolicy().hasHeightForWidth())
        self.regedit_8.setSizePolicy(sizePolicy)
        self.regedit_8.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_8.addWidget(self.regedit_8)


        self.verticalLayout_3.addLayout(self.regOption_8)

        self.regOption_9 = QHBoxLayout()
        self.regOption_9.setObjectName(u"regOption_9")
        self.reglabel_9 = QLabel(self.OptionsView)
        self.reglabel_9.setObjectName(u"reglabel_9")
        sizePolicy.setHeightForWidth(self.reglabel_9.sizePolicy().hasHeightForWidth())
        self.reglabel_9.setSizePolicy(sizePolicy)
        self.reglabel_9.setFont(font4)

        self.regOption_9.addWidget(self.reglabel_9)

        self.regedit_9 = QLineEdit(self.OptionsView)
        self.regedit_9.setObjectName(u"regedit_9")
        sizePolicy.setHeightForWidth(self.regedit_9.sizePolicy().hasHeightForWidth())
        self.regedit_9.setSizePolicy(sizePolicy)
        self.regedit_9.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_9.addWidget(self.regedit_9)


        self.verticalLayout_3.addLayout(self.regOption_9)

        self.regOption_10 = QHBoxLayout()
        self.regOption_10.setObjectName(u"regOption_10")
        self.reglabel_10 = QLabel(self.OptionsView)
        self.reglabel_10.setObjectName(u"reglabel_10")
        sizePolicy.setHeightForWidth(self.reglabel_10.sizePolicy().hasHeightForWidth())
        self.reglabel_10.setSizePolicy(sizePolicy)
        self.reglabel_10.setFont(font4)

        self.regOption_10.addWidget(self.reglabel_10)

        self.regedit_10 = QLineEdit(self.OptionsView)
        self.regedit_10.setObjectName(u"regedit_10")
        sizePolicy.setHeightForWidth(self.regedit_10.sizePolicy().hasHeightForWidth())
        self.regedit_10.setSizePolicy(sizePolicy)
        self.regedit_10.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_10.addWidget(self.regedit_10)


        self.verticalLayout_3.addLayout(self.regOption_10)

        self.regOption_11 = QHBoxLayout()
        self.regOption_11.setObjectName(u"regOption_11")
        self.reglabel_11 = QLabel(self.OptionsView)
        self.reglabel_11.setObjectName(u"reglabel_11")
        sizePolicy.setHeightForWidth(self.reglabel_11.sizePolicy().hasHeightForWidth())
        self.reglabel_11.setSizePolicy(sizePolicy)
        self.reglabel_11.setFont(font4)

        self.regOption_11.addWidget(self.reglabel_11)

        self.regedit_11 = QLineEdit(self.OptionsView)
        self.regedit_11.setObjectName(u"regedit_11")
        sizePolicy.setHeightForWidth(self.regedit_11.sizePolicy().hasHeightForWidth())
        self.regedit_11.setSizePolicy(sizePolicy)
        self.regedit_11.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_11.addWidget(self.regedit_11)


        self.verticalLayout_3.addLayout(self.regOption_11)

        self.regOption_12 = QHBoxLayout()
        self.regOption_12.setObjectName(u"regOption_12")
        self.reglabel_12 = QLabel(self.OptionsView)
        self.reglabel_12.setObjectName(u"reglabel_12")
        sizePolicy.setHeightForWidth(self.reglabel_12.sizePolicy().hasHeightForWidth())
        self.reglabel_12.setSizePolicy(sizePolicy)
        self.reglabel_12.setFont(font4)

        self.regOption_12.addWidget(self.reglabel_12)

        self.regedit_12 = QLineEdit(self.OptionsView)
        self.regedit_12.setObjectName(u"regedit_12")
        sizePolicy.setHeightForWidth(self.regedit_12.sizePolicy().hasHeightForWidth())
        self.regedit_12.setSizePolicy(sizePolicy)
        self.regedit_12.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_12.addWidget(self.regedit_12)


        self.verticalLayout_3.addLayout(self.regOption_12)

        self.regOption_13 = QHBoxLayout()
        self.regOption_13.setObjectName(u"regOption_13")
        self.reglabel_13 = QLabel(self.OptionsView)
        self.reglabel_13.setObjectName(u"reglabel_13")
        sizePolicy.setHeightForWidth(self.reglabel_13.sizePolicy().hasHeightForWidth())
        self.reglabel_13.setSizePolicy(sizePolicy)
        self.reglabel_13.setFont(font4)

        self.regOption_13.addWidget(self.reglabel_13)

        self.regedit_13 = QLineEdit(self.OptionsView)
        self.regedit_13.setObjectName(u"regedit_13")
        sizePolicy.setHeightForWidth(self.regedit_13.sizePolicy().hasHeightForWidth())
        self.regedit_13.setSizePolicy(sizePolicy)
        self.regedit_13.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_13.addWidget(self.regedit_13)


        self.verticalLayout_3.addLayout(self.regOption_13)

        self.regOption_14 = QHBoxLayout()
        self.regOption_14.setObjectName(u"regOption_14")
        self.reglabel_14 = QLabel(self.OptionsView)
        self.reglabel_14.setObjectName(u"reglabel_14")
        sizePolicy.setHeightForWidth(self.reglabel_14.sizePolicy().hasHeightForWidth())
        self.reglabel_14.setSizePolicy(sizePolicy)
        self.reglabel_14.setFont(font4)

        self.regOption_14.addWidget(self.reglabel_14)

        self.regedit_14 = QLineEdit(self.OptionsView)
        self.regedit_14.setObjectName(u"regedit_14")
        sizePolicy.setHeightForWidth(self.regedit_14.sizePolicy().hasHeightForWidth())
        self.regedit_14.setSizePolicy(sizePolicy)
        self.regedit_14.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_14.addWidget(self.regedit_14)


        self.verticalLayout_3.addLayout(self.regOption_14)


        self.registers.addLayout(self.verticalLayout_3)

        self.verticalLayout_5 = QVBoxLayout()
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.regOption_15 = QHBoxLayout()
        self.regOption_15.setObjectName(u"regOption_15")
        self.reglabel_15 = QLabel(self.OptionsView)
        self.reglabel_15.setObjectName(u"reglabel_15")
        sizePolicy.setHeightForWidth(self.reglabel_15.sizePolicy().hasHeightForWidth())
        self.reglabel_15.setSizePolicy(sizePolicy)
        self.reglabel_15.setFont(font4)

        self.regOption_15.addWidget(self.reglabel_15)

        self.regedit_15 = QLineEdit(self.OptionsView)
        self.regedit_15.setObjectName(u"regedit_15")
        sizePolicy.setHeightForWidth(self.regedit_15.sizePolicy().hasHeightForWidth())
        self.regedit_15.setSizePolicy(sizePolicy)
        self.regedit_15.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_15.addWidget(self.regedit_15)


        self.verticalLayout_5.addLayout(self.regOption_15)

        self.regOption_16 = QHBoxLayout()
        self.regOption_16.setObjectName(u"regOption_16")
        self.reglabel_16 = QLabel(self.OptionsView)
        self.reglabel_16.setObjectName(u"reglabel_16")
        sizePolicy.setHeightForWidth(self.reglabel_16.sizePolicy().hasHeightForWidth())
        self.reglabel_16.setSizePolicy(sizePolicy)
        self.reglabel_16.setFont(font4)

        self.regOption_16.addWidget(self.reglabel_16)

        self.regedit_16 = QLineEdit(self.OptionsView)
        self.regedit_16.setObjectName(u"regedit_16")
        sizePolicy.setHeightForWidth(self.regedit_16.sizePolicy().hasHeightForWidth())
        self.regedit_16.setSizePolicy(sizePolicy)
        self.regedit_16.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_16.addWidget(self.regedit_16)


        self.verticalLayout_5.addLayout(self.regOption_16)

        self.regOption_17 = QHBoxLayout()
        self.regOption_17.setObjectName(u"regOption_17")
        self.reglabel_17 = QLabel(self.OptionsView)
        self.reglabel_17.setObjectName(u"reglabel_17")
        sizePolicy.setHeightForWidth(self.reglabel_17.sizePolicy().hasHeightForWidth())
        self.reglabel_17.setSizePolicy(sizePolicy)
        self.reglabel_17.setFont(font4)

        self.regOption_17.addWidget(self.reglabel_17)

        self.regedit_17 = QLineEdit(self.OptionsView)
        self.regedit_17.setObjectName(u"regedit_17")
        sizePolicy.setHeightForWidth(self.regedit_17.sizePolicy().hasHeightForWidth())
        self.regedit_17.setSizePolicy(sizePolicy)
        self.regedit_17.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_17.addWidget(self.regedit_17)


        self.verticalLayout_5.addLayout(self.regOption_17)

        self.regOption_18 = QHBoxLayout()
        self.regOption_18.setObjectName(u"regOption_18")
        self.reglabel_18 = QLabel(self.OptionsView)
        self.reglabel_18.setObjectName(u"reglabel_18")
        sizePolicy.setHeightForWidth(self.reglabel_18.sizePolicy().hasHeightForWidth())
        self.reglabel_18.setSizePolicy(sizePolicy)
        self.reglabel_18.setFont(font4)

        self.regOption_18.addWidget(self.reglabel_18)

        self.regedit_18 = QLineEdit(self.OptionsView)
        self.regedit_18.setObjectName(u"regedit_18")
        sizePolicy.setHeightForWidth(self.regedit_18.sizePolicy().hasHeightForWidth())
        self.regedit_18.setSizePolicy(sizePolicy)
        self.regedit_18.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_18.addWidget(self.regedit_18)


        self.verticalLayout_5.addLayout(self.regOption_18)

        self.regOption_19 = QHBoxLayout()
        self.regOption_19.setObjectName(u"regOption_19")
        self.reglabel_19 = QLabel(self.OptionsView)
        self.reglabel_19.setObjectName(u"reglabel_19")
        sizePolicy.setHeightForWidth(self.reglabel_19.sizePolicy().hasHeightForWidth())
        self.reglabel_19.setSizePolicy(sizePolicy)
        self.reglabel_19.setFont(font4)

        self.regOption_19.addWidget(self.reglabel_19)

        self.regedit_19 = QLineEdit(self.OptionsView)
        self.regedit_19.setObjectName(u"regedit_19")
        sizePolicy.setHeightForWidth(self.regedit_19.sizePolicy().hasHeightForWidth())
        self.regedit_19.setSizePolicy(sizePolicy)
        self.regedit_19.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_19.addWidget(self.regedit_19)


        self.verticalLayout_5.addLayout(self.regOption_19)

        self.regOption_20 = QHBoxLayout()
        self.regOption_20.setObjectName(u"regOption_20")
        self.reglabel_20 = QLabel(self.OptionsView)
        self.reglabel_20.setObjectName(u"reglabel_20")
        sizePolicy.setHeightForWidth(self.reglabel_20.sizePolicy().hasHeightForWidth())
        self.reglabel_20.setSizePolicy(sizePolicy)
        self.reglabel_20.setFont(font4)

        self.regOption_20.addWidget(self.reglabel_20)

        self.regedit_20 = QLineEdit(self.OptionsView)
        self.regedit_20.setObjectName(u"regedit_20")
        sizePolicy.setHeightForWidth(self.regedit_20.sizePolicy().hasHeightForWidth())
        self.regedit_20.setSizePolicy(sizePolicy)
        self.regedit_20.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_20.addWidget(self.regedit_20)


        self.verticalLayout_5.addLayout(self.regOption_20)

        self.regOption_21 = QHBoxLayout()
        self.regOption_21.setObjectName(u"regOption_21")
        self.reglabel_21 = QLabel(self.OptionsView)
        self.reglabel_21.setObjectName(u"reglabel_21")
        sizePolicy.setHeightForWidth(self.reglabel_21.sizePolicy().hasHeightForWidth())
        self.reglabel_21.setSizePolicy(sizePolicy)
        self.reglabel_21.setFont(font4)

        self.regOption_21.addWidget(self.reglabel_21)

        self.regedit_21 = QLineEdit(self.OptionsView)
        self.regedit_21.setObjectName(u"regedit_21")
        sizePolicy.setHeightForWidth(self.regedit_21.sizePolicy().hasHeightForWidth())
        self.regedit_21.setSizePolicy(sizePolicy)
        self.regedit_21.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_21.addWidget(self.regedit_21)


        self.verticalLayout_5.addLayout(self.regOption_21)


        self.registers.addLayout(self.verticalLayout_5)


        self.prestateOptions_2.addLayout(self.registers)


        self.prestateOptions.addLayout(self.prestateOptions_2)


        self.verticalLayout_4.addLayout(self.prestateOptions)

        self.horizontalSpacer = QSpacerItem(638, 17, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.verticalLayout_4.addItem(self.horizontalSpacer)

        self.searchLabel = QLabel(self.OptionsView)
        self.searchLabel.setObjectName(u"searchLabel")
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.searchLabel.sizePolicy().hasHeightForWidth())
        self.searchLabel.setSizePolicy(sizePolicy1)
        self.searchLabel.setFont(font3)
        self.searchLabel.setLayoutDirection(Qt.LeftToRight)
        self.searchLabel.setLineWidth(1)
        self.searchLabel.setTextFormat(Qt.AutoText)
        self.searchLabel.setScaledContents(False)
        self.searchLabel.setAlignment(Qt.AlignCenter)

        self.verticalLayout_4.addWidget(self.searchLabel)

        self.options1 = QHBoxLayout()
        self.options1.setObjectName(u"options1")
        self.badbytesOpt = QHBoxLayout()
        self.badbytesOpt.setObjectName(u"badbytesOpt")
        self.label_3 = QLabel(self.OptionsView)
        self.label_3.setObjectName(u"label_3")
        self.label_3.setFont(font4)
        self.label_3.setAlignment(Qt.AlignCenter)

        self.badbytesOpt.addWidget(self.label_3)

        self.badBytesEdit = QLineEdit(self.OptionsView)
        self.badBytesEdit.setObjectName(u"badBytesEdit")
        self.badBytesEdit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.badbytesOpt.addWidget(self.badBytesEdit)


        self.options1.addLayout(self.badbytesOpt)

        self.depthOpt = QHBoxLayout()
        self.depthOpt.setObjectName(u"depthOpt")
        self.label = QLabel(self.OptionsView)
        self.label.setObjectName(u"label")
        self.label.setFont(font4)
        self.label.setAlignment(Qt.AlignCenter)

        self.depthOpt.addWidget(self.label)

        self.depthBox = QSpinBox(self.OptionsView)
        self.depthBox.setObjectName(u"depthBox")
        self.depthBox.setMinimum(1)
        self.depthBox.setValue(10)

        self.depthOpt.addWidget(self.depthBox)


        self.options1.addLayout(self.depthOpt)

        self.blockOpt = QHBoxLayout()
        self.blockOpt.setObjectName(u"blockOpt")
        self.label_2 = QLabel(self.OptionsView)
        self.label_2.setObjectName(u"label_2")
        self.label_2.setFont(font4)
        self.label_2.setAlignment(Qt.AlignCenter)

        self.blockOpt.addWidget(self.label_2)

        self.blockEdit = QLineEdit(self.OptionsView)
        self.blockEdit.setObjectName(u"blockEdit")
        self.blockEdit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.blockOpt.addWidget(self.blockEdit)


        self.options1.addLayout(self.blockOpt)


        self.verticalLayout_4.addLayout(self.options1)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.clearCacheButton = QPushButton(self.OptionsView)
        self.clearCacheButton.setObjectName(u"clearCacheButton")
        sizePolicy.setHeightForWidth(self.clearCacheButton.sizePolicy().hasHeightForWidth())
        self.clearCacheButton.setSizePolicy(sizePolicy)
        self.clearCacheButton.setAutoExclusive(False)

        self.horizontalLayout_3.addWidget(self.clearCacheButton)

        self.reloadButton = QPushButton(self.OptionsView)
        self.reloadButton.setObjectName(u"reloadButton")
        sizePolicy.setHeightForWidth(self.reloadButton.sizePolicy().hasHeightForWidth())
        self.reloadButton.setSizePolicy(sizePolicy)
        self.reloadButton.setAutoExclusive(False)

        self.horizontalLayout_3.addWidget(self.reloadButton)

        self.rangeLabel = QLabel(self.OptionsView)
        self.rangeLabel.setObjectName(u"rangeLabel")
        self.rangeLabel.setFont(font4)
        self.rangeLabel.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_3.addWidget(self.rangeLabel)

        self.rangeEdit = QLineEdit(self.OptionsView)
        self.rangeEdit.setObjectName(u"rangeEdit")
        self.rangeEdit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_3.addWidget(self.rangeEdit)

        self.label_4 = QLabel(self.OptionsView)
        self.label_4.setObjectName(u"label_4")

        self.horizontalLayout_3.addWidget(self.label_4)

        self.semanticBox = QSpinBox(self.OptionsView)
        self.semanticBox.setObjectName(u"semanticBox")
        self.semanticBox.setMaximum(2000)
        self.semanticBox.setValue(500)

        self.horizontalLayout_3.addWidget(self.semanticBox)

        self.instcntLabel = QLabel(self.OptionsView)
        self.instcntLabel.setObjectName(u"instcntLabel")
        self.instcntLabel.setFont(font4)
        self.instcntLabel.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_3.addWidget(self.instcntLabel)

        self.instCntSpinbox = QSpinBox(self.OptionsView)
        self.instCntSpinbox.setObjectName(u"instCntSpinbox")
        self.instCntSpinbox.setValue(0)

        self.horizontalLayout_3.addWidget(self.instCntSpinbox)


        self.verticalLayout_4.addLayout(self.horizontalLayout_3)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.ropOpt = QCheckBox(self.OptionsView)
        self.ropOpt.setObjectName(u"ropOpt")
        self.ropOpt.setChecked(True)

        self.horizontalLayout_2.addWidget(self.ropOpt)

        self.jopOpt = QCheckBox(self.OptionsView)
        self.jopOpt.setObjectName(u"jopOpt")
        self.jopOpt.setChecked(False)

        self.horizontalLayout_2.addWidget(self.jopOpt)

        self.copOpt = QCheckBox(self.OptionsView)
        self.copOpt.setObjectName(u"copOpt")
        self.copOpt.setChecked(False)

        self.horizontalLayout_2.addWidget(self.copOpt)

        self.sysOpt = QCheckBox(self.OptionsView)
        self.sysOpt.setObjectName(u"sysOpt")
        self.sysOpt.setChecked(True)

        self.horizontalLayout_2.addWidget(self.sysOpt)

        self.allOpt = QCheckBox(self.OptionsView)
        self.allOpt.setObjectName(u"allOpt")

        self.horizontalLayout_2.addWidget(self.allOpt)

        self.dumpOpt = QCheckBox(self.OptionsView)
        self.dumpOpt.setObjectName(u"dumpOpt")

        self.horizontalLayout_2.addWidget(self.dumpOpt)

        self.exportButton = QPushButton(self.OptionsView)
        self.exportButton.setObjectName(u"exportButton")

        self.horizontalLayout_2.addWidget(self.exportButton)


        self.verticalLayout_4.addLayout(self.horizontalLayout_2)

        self.horizontalSpacer_3 = QSpacerItem(756, 17, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.verticalLayout_4.addItem(self.horizontalSpacer_3)


        self.horizontalLayout_4.addLayout(self.verticalLayout_4)

        self.verticalSpacer = QSpacerItem(255, 508, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.horizontalLayout_4.addItem(self.verticalSpacer)


        self.verticalLayout_6.addLayout(self.horizontalLayout_4)

        self.tabWidget.addTab(self.OptionsView, "")

        self.verticalLayout.addWidget(self.tabWidget)


        self.verticalLayout_7.addLayout(self.verticalLayout)


        self.retranslateUi(Form)

        self.tabWidget.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(Form)
    # setupUi

    def retranslateUi(self, Form):
        Form.setWindowTitle(QCoreApplication.translate("Form", u"Form", None))
        self.lineEdit.setPlaceholderText(QCoreApplication.translate("Form", u"Search filter", None))
        self.resultsLabel.setText("")
        self.statusLabel.setText("")
        ___qtreewidgetitem = self.gadgetPane.headerItem()
        ___qtreewidgetitem.setText(2, QCoreApplication.translate("Form", u"Gadget", None));
        ___qtreewidgetitem.setText(1, QCoreApplication.translate("Form", u"asm", None));
        ___qtreewidgetitem.setText(0, QCoreApplication.translate("Form", u"Location", None));
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.GadgetView), QCoreApplication.translate("Form", u"ROP View", None))
        self.ExportButton.setText(QCoreApplication.translate("Form", u"Export", None))
        self.ExportType.setItemText(0, QCoreApplication.translate("Form", u"pwntools", None))
        self.ExportType.setItemText(1, QCoreApplication.translate("Form", u"packed", None))


        __sortingEnabled = self.ChainWindow.isSortingEnabled()
        self.ChainWindow.setSortingEnabled(False)
        ___qlistwidgetitem = self.ChainWindow.item(0)
        ___qlistwidgetitem.setText(QCoreApplication.translate("Form", u"Feature not yet available", None));
        self.ChainWindow.setSortingEnabled(__sortingEnabled)

        self.tabWidget.setTabText(self.tabWidget.indexOf(self.ChainView), QCoreApplication.translate("Form", u"Chain Builder", None))
        self.prestateLabel.setText(QCoreApplication.translate("Form", u"Analysis Prestate", None))
        self.reglabel.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_2.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_2.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_3.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_3.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_4.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_4.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_5.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_5.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_6.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_6.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_7.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_7.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_8.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_8.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_9.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_9.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_10.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_10.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_11.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_11.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_12.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_12.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_13.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_13.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_14.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_14.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_15.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_15.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_16.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_16.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_17.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_17.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_18.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_18.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_19.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_19.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_20.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_20.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_21.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_21.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.searchLabel.setText(QCoreApplication.translate("Form", u"Gadget Search Options", None))
#if QT_CONFIG(tooltip)
        self.label_3.setToolTip(QCoreApplication.translate("Form", u"Bytes to exclude from gadget addresses.", None))
#endif // QT_CONFIG(tooltip)
        self.label_3.setText(QCoreApplication.translate("Form", u"Bad bytes:", None))
#if QT_CONFIG(tooltip)
        self.badBytesEdit.setToolTip(QCoreApplication.translate("Form", u"Bytes to exclude from gadget addresses.", None))
#endif // QT_CONFIG(tooltip)
        self.badBytesEdit.setPlaceholderText(QCoreApplication.translate("Form", u"0xc0,0xf0,...", None))
#if QT_CONFIG(tooltip)
        self.label.setToolTip(QCoreApplication.translate("Form", u"How many bytes to go back from when looking for gadgets.", None))
#endif // QT_CONFIG(tooltip)
        self.label.setText(QCoreApplication.translate("Form", u"Depth:", None))
#if QT_CONFIG(tooltip)
        self.depthBox.setToolTip(QCoreApplication.translate("Form", u"How many bytes to go back from when looking for gadgets.", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.label_2.setToolTip(QCoreApplication.translate("Form", u"mnemonics to block, comma seperated.", None))
#endif // QT_CONFIG(tooltip)
        self.label_2.setText(QCoreApplication.translate("Form", u"Block:", None))
#if QT_CONFIG(tooltip)
        self.blockEdit.setToolTip(QCoreApplication.translate("Form", u"mnemonics to block, comma seperated.", None))
#endif // QT_CONFIG(tooltip)
        self.blockEdit.setText("")
        self.blockEdit.setPlaceholderText(QCoreApplication.translate("Form", u"dec ax,inc ax,...", None))
#if QT_CONFIG(tooltip)
        self.clearCacheButton.setToolTip(QCoreApplication.translate("Form", u"Clear gadget and analysis cache.", None))
#endif // QT_CONFIG(tooltip)
        self.clearCacheButton.setText(QCoreApplication.translate("Form", u"Clear cache", None))
#if QT_CONFIG(tooltip)
        self.reloadButton.setToolTip(QCoreApplication.translate("Form", u"Start new gadget search", None))
#endif // QT_CONFIG(tooltip)
        self.reloadButton.setText(QCoreApplication.translate("Form", u"Reload", None))
#if QT_CONFIG(tooltip)
        self.rangeLabel.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets in an address range.", None))
#endif // QT_CONFIG(tooltip)
        self.rangeLabel.setText(QCoreApplication.translate("Form", u"Address range:", None))
#if QT_CONFIG(tooltip)
        self.rangeEdit.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets in an address range.", None))
#endif // QT_CONFIG(tooltip)
        self.rangeEdit.setPlaceholderText(QCoreApplication.translate("Form", u"0x??????-0x?????", None))
#if QT_CONFIG(tooltip)
        self.label_4.setToolTip(QCoreApplication.translate("Form", u"The depth semantic search uses to limit exhaustion", None))
#endif // QT_CONFIG(tooltip)
        self.label_4.setText(QCoreApplication.translate("Form", u"Semantic depth:", None))
#if QT_CONFIG(tooltip)
        self.semanticBox.setToolTip(QCoreApplication.translate("Form", u"The depth semantic search uses to limit exhaustion", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.instcntLabel.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets with n instructions. (Disabled when 0)", None))
#endif // QT_CONFIG(tooltip)
        self.instcntLabel.setText(QCoreApplication.translate("Form", u"Instruction count:", None))
#if QT_CONFIG(tooltip)
        self.instCntSpinbox.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets with n instructions. (Disabled when 0)", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.ropOpt.setToolTip(QCoreApplication.translate("Form", u"Disable ROP search.", None))
#endif // QT_CONFIG(tooltip)
        self.ropOpt.setText(QCoreApplication.translate("Form", u"ROP", None))
#if QT_CONFIG(tooltip)
        self.jopOpt.setToolTip(QCoreApplication.translate("Form", u"Disable JOP search.", None))
#endif // QT_CONFIG(tooltip)
        self.jopOpt.setText(QCoreApplication.translate("Form", u"JOP", None))
#if QT_CONFIG(tooltip)
        self.copOpt.setToolTip(QCoreApplication.translate("Form", u"Disable COP search.", None))
#endif // QT_CONFIG(tooltip)
        self.copOpt.setText(QCoreApplication.translate("Form", u"COP", None))
#if QT_CONFIG(tooltip)
        self.sysOpt.setToolTip(QCoreApplication.translate("Form", u"Disable SYS search", None))
#endif // QT_CONFIG(tooltip)
        self.sysOpt.setText(QCoreApplication.translate("Form", u"SYS", None))
#if QT_CONFIG(tooltip)
        self.allOpt.setToolTip(QCoreApplication.translate("Form", u"Include duplicate gadgets.", None))
#endif // QT_CONFIG(tooltip)
        self.allOpt.setText(QCoreApplication.translate("Form", u"Duplicates", None))
#if QT_CONFIG(tooltip)
        self.dumpOpt.setToolTip(QCoreApplication.translate("Form", u"Output the gadget bytes.", None))
#endif // QT_CONFIG(tooltip)
        self.dumpOpt.setText(QCoreApplication.translate("Form", u"Dump", None))
#if QT_CONFIG(tooltip)
        self.exportButton.setToolTip(QCoreApplication.translate("Form", u"Export gadgets dataframe to csv for data analysis", None))
#endif // QT_CONFIG(tooltip)
        self.exportButton.setText(QCoreApplication.translate("Form", u"Export gadgets", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.OptionsView), QCoreApplication.translate("Form", u"Options", None))
    # retranslateUi

