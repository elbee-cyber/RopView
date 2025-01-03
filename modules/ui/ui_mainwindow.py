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
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QHBoxLayout,
    QHeaderView, QLabel, QLayout, QLineEdit,
    QListView, QListWidget, QListWidgetItem, QPushButton,
    QSizePolicy, QSpacerItem, QSpinBox, QSplitter,
    QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget)

class Ui_Form(object):
    def setupUi(self, Form):
        if not Form.objectName():
            Form.setObjectName(u"Form")
        Form.resize(918, 410)
        Form.setFocusPolicy(Qt.NoFocus)
        self.verticalLayout_6 = QVBoxLayout(Form)
        self.verticalLayout_6.setObjectName(u"verticalLayout_6")
        self.tabWidget = QTabWidget(Form)
        self.tabWidget.setObjectName(u"tabWidget")
        self.tabWidget.setEnabled(True)
        font = QFont()
        font.setFamilies([u"Ubuntu"])
        self.tabWidget.setFont(font)
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
        self.verticalLayout_7 = QVBoxLayout(self.GadgetView)
        self.verticalLayout_7.setObjectName(u"verticalLayout_7")
        self.lineEdit = QLineEdit(self.GadgetView)
        self.lineEdit.setObjectName(u"lineEdit")
        font1 = QFont()
        font1.setFamilies([u"Ubuntu"])
        font1.setPointSize(22)
        font1.setItalic(False)
        self.lineEdit.setFont(font1)
        self.lineEdit.setClearButtonEnabled(True)

        self.verticalLayout_7.addWidget(self.lineEdit)

        self.searchBox = QHBoxLayout()
        self.searchBox.setSpacing(6)
        self.searchBox.setObjectName(u"searchBox")
        self.searchBox.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.resultsLabel = QLabel(self.GadgetView)
        self.resultsLabel.setObjectName(u"resultsLabel")
        self.resultsLabel.setMaximumSize(QSize(16777215, 20))
        font2 = QFont()
        font2.setPointSize(9)
        self.resultsLabel.setFont(font2)
        self.resultsLabel.setAlignment(Qt.AlignLeading|Qt.AlignLeft|Qt.AlignVCenter)

        self.searchBox.addWidget(self.resultsLabel)

        self.statusLabel = QLabel(self.GadgetView)
        self.statusLabel.setObjectName(u"statusLabel")
        self.statusLabel.setMaximumSize(QSize(16777215, 20))
        self.statusLabel.setFont(font2)
        self.statusLabel.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.searchBox.addWidget(self.statusLabel)


        self.verticalLayout_7.addLayout(self.searchBox)

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

        self.verticalLayout_7.addWidget(self.splitter)

        self.verticalLayout_7.setStretch(0, 1)
        self.verticalLayout_7.setStretch(2, 1)
        self.tabWidget.addTab(self.GadgetView, "")
        self.PrestateView = QWidget()
        self.PrestateView.setObjectName(u"PrestateView")
        self.PrestateView.setAutoFillBackground(True)
        self.verticalLayout_9 = QVBoxLayout(self.PrestateView)
        self.verticalLayout_9.setObjectName(u"verticalLayout_9")
        self.prestateLabel = QLabel(self.PrestateView)
        self.prestateLabel.setObjectName(u"prestateLabel")
        font3 = QFont()
        font3.setPointSize(18)
        font3.setBold(True)
        self.prestateLabel.setFont(font3)
        self.prestateLabel.setAlignment(Qt.AlignCenter)

        self.verticalLayout_9.addWidget(self.prestateLabel)

        self.horizontalLayout_6 = QHBoxLayout()
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.regOption = QHBoxLayout()
        self.regOption.setObjectName(u"regOption")
        self.reglabel = QLabel(self.PrestateView)
        self.reglabel.setObjectName(u"reglabel")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.reglabel.sizePolicy().hasHeightForWidth())
        self.reglabel.setSizePolicy(sizePolicy)
        font4 = QFont()
        font4.setPointSize(10)
        self.reglabel.setFont(font4)
        self.reglabel.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption.addWidget(self.reglabel)

        self.regedit = QLineEdit(self.PrestateView)
        self.regedit.setObjectName(u"regedit")
        sizePolicy.setHeightForWidth(self.regedit.sizePolicy().hasHeightForWidth())
        self.regedit.setSizePolicy(sizePolicy)
        self.regedit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption.addWidget(self.regedit)


        self.verticalLayout_2.addLayout(self.regOption)

        self.regOption_2 = QHBoxLayout()
        self.regOption_2.setObjectName(u"regOption_2")
        self.reglabel_2 = QLabel(self.PrestateView)
        self.reglabel_2.setObjectName(u"reglabel_2")
        sizePolicy.setHeightForWidth(self.reglabel_2.sizePolicy().hasHeightForWidth())
        self.reglabel_2.setSizePolicy(sizePolicy)
        self.reglabel_2.setFont(font4)
        self.reglabel_2.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_2.addWidget(self.reglabel_2)

        self.regedit_2 = QLineEdit(self.PrestateView)
        self.regedit_2.setObjectName(u"regedit_2")
        sizePolicy.setHeightForWidth(self.regedit_2.sizePolicy().hasHeightForWidth())
        self.regedit_2.setSizePolicy(sizePolicy)
        self.regedit_2.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_2.addWidget(self.regedit_2)


        self.verticalLayout_2.addLayout(self.regOption_2)

        self.regOption_3 = QHBoxLayout()
        self.regOption_3.setObjectName(u"regOption_3")
        self.reglabel_3 = QLabel(self.PrestateView)
        self.reglabel_3.setObjectName(u"reglabel_3")
        sizePolicy.setHeightForWidth(self.reglabel_3.sizePolicy().hasHeightForWidth())
        self.reglabel_3.setSizePolicy(sizePolicy)
        self.reglabel_3.setFont(font4)
        self.reglabel_3.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_3.addWidget(self.reglabel_3)

        self.regedit_3 = QLineEdit(self.PrestateView)
        self.regedit_3.setObjectName(u"regedit_3")
        sizePolicy.setHeightForWidth(self.regedit_3.sizePolicy().hasHeightForWidth())
        self.regedit_3.setSizePolicy(sizePolicy)
        self.regedit_3.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_3.addWidget(self.regedit_3)


        self.verticalLayout_2.addLayout(self.regOption_3)

        self.regOption_4 = QHBoxLayout()
        self.regOption_4.setObjectName(u"regOption_4")
        self.reglabel_4 = QLabel(self.PrestateView)
        self.reglabel_4.setObjectName(u"reglabel_4")
        sizePolicy.setHeightForWidth(self.reglabel_4.sizePolicy().hasHeightForWidth())
        self.reglabel_4.setSizePolicy(sizePolicy)
        self.reglabel_4.setFont(font4)
        self.reglabel_4.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_4.addWidget(self.reglabel_4)

        self.regedit_4 = QLineEdit(self.PrestateView)
        self.regedit_4.setObjectName(u"regedit_4")
        sizePolicy.setHeightForWidth(self.regedit_4.sizePolicy().hasHeightForWidth())
        self.regedit_4.setSizePolicy(sizePolicy)
        self.regedit_4.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_4.addWidget(self.regedit_4)


        self.verticalLayout_2.addLayout(self.regOption_4)

        self.regOption_5 = QHBoxLayout()
        self.regOption_5.setObjectName(u"regOption_5")
        self.reglabel_5 = QLabel(self.PrestateView)
        self.reglabel_5.setObjectName(u"reglabel_5")
        sizePolicy.setHeightForWidth(self.reglabel_5.sizePolicy().hasHeightForWidth())
        self.reglabel_5.setSizePolicy(sizePolicy)
        self.reglabel_5.setFont(font4)
        self.reglabel_5.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_5.addWidget(self.reglabel_5)

        self.regedit_5 = QLineEdit(self.PrestateView)
        self.regedit_5.setObjectName(u"regedit_5")
        sizePolicy.setHeightForWidth(self.regedit_5.sizePolicy().hasHeightForWidth())
        self.regedit_5.setSizePolicy(sizePolicy)
        self.regedit_5.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_5.addWidget(self.regedit_5)


        self.verticalLayout_2.addLayout(self.regOption_5)

        self.regOption_6 = QHBoxLayout()
        self.regOption_6.setObjectName(u"regOption_6")
        self.reglabel_6 = QLabel(self.PrestateView)
        self.reglabel_6.setObjectName(u"reglabel_6")
        sizePolicy.setHeightForWidth(self.reglabel_6.sizePolicy().hasHeightForWidth())
        self.reglabel_6.setSizePolicy(sizePolicy)
        self.reglabel_6.setFont(font4)
        self.reglabel_6.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_6.addWidget(self.reglabel_6)

        self.regedit_6 = QLineEdit(self.PrestateView)
        self.regedit_6.setObjectName(u"regedit_6")
        sizePolicy.setHeightForWidth(self.regedit_6.sizePolicy().hasHeightForWidth())
        self.regedit_6.setSizePolicy(sizePolicy)
        self.regedit_6.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_6.addWidget(self.regedit_6)


        self.verticalLayout_2.addLayout(self.regOption_6)

        self.regOption_7 = QHBoxLayout()
        self.regOption_7.setObjectName(u"regOption_7")
        self.reglabel_7 = QLabel(self.PrestateView)
        self.reglabel_7.setObjectName(u"reglabel_7")
        sizePolicy.setHeightForWidth(self.reglabel_7.sizePolicy().hasHeightForWidth())
        self.reglabel_7.setSizePolicy(sizePolicy)
        self.reglabel_7.setFont(font4)
        self.reglabel_7.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_7.addWidget(self.reglabel_7)

        self.regedit_7 = QLineEdit(self.PrestateView)
        self.regedit_7.setObjectName(u"regedit_7")
        sizePolicy.setHeightForWidth(self.regedit_7.sizePolicy().hasHeightForWidth())
        self.regedit_7.setSizePolicy(sizePolicy)
        self.regedit_7.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_7.addWidget(self.regedit_7)


        self.verticalLayout_2.addLayout(self.regOption_7)

        self.regOption_8 = QHBoxLayout()
        self.regOption_8.setObjectName(u"regOption_8")
        self.reglabel_8 = QLabel(self.PrestateView)
        self.reglabel_8.setObjectName(u"reglabel_8")
        sizePolicy.setHeightForWidth(self.reglabel_8.sizePolicy().hasHeightForWidth())
        self.reglabel_8.setSizePolicy(sizePolicy)
        self.reglabel_8.setFont(font4)
        self.reglabel_8.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_8.addWidget(self.reglabel_8)

        self.regedit_8 = QLineEdit(self.PrestateView)
        self.regedit_8.setObjectName(u"regedit_8")
        sizePolicy.setHeightForWidth(self.regedit_8.sizePolicy().hasHeightForWidth())
        self.regedit_8.setSizePolicy(sizePolicy)
        self.regedit_8.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_8.addWidget(self.regedit_8)


        self.verticalLayout_2.addLayout(self.regOption_8)


        self.horizontalLayout_6.addLayout(self.verticalLayout_2)

        self.verticalLayout_3 = QVBoxLayout()
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.regOption_9 = QHBoxLayout()
        self.regOption_9.setObjectName(u"regOption_9")
        self.reglabel_9 = QLabel(self.PrestateView)
        self.reglabel_9.setObjectName(u"reglabel_9")
        sizePolicy.setHeightForWidth(self.reglabel_9.sizePolicy().hasHeightForWidth())
        self.reglabel_9.setSizePolicy(sizePolicy)
        self.reglabel_9.setFont(font4)
        self.reglabel_9.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_9.addWidget(self.reglabel_9)

        self.regedit_9 = QLineEdit(self.PrestateView)
        self.regedit_9.setObjectName(u"regedit_9")
        sizePolicy.setHeightForWidth(self.regedit_9.sizePolicy().hasHeightForWidth())
        self.regedit_9.setSizePolicy(sizePolicy)
        self.regedit_9.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_9.addWidget(self.regedit_9)


        self.verticalLayout_3.addLayout(self.regOption_9)

        self.regOption_10 = QHBoxLayout()
        self.regOption_10.setObjectName(u"regOption_10")
        self.reglabel_10 = QLabel(self.PrestateView)
        self.reglabel_10.setObjectName(u"reglabel_10")
        sizePolicy.setHeightForWidth(self.reglabel_10.sizePolicy().hasHeightForWidth())
        self.reglabel_10.setSizePolicy(sizePolicy)
        self.reglabel_10.setFont(font4)
        self.reglabel_10.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_10.addWidget(self.reglabel_10)

        self.regedit_10 = QLineEdit(self.PrestateView)
        self.regedit_10.setObjectName(u"regedit_10")
        sizePolicy.setHeightForWidth(self.regedit_10.sizePolicy().hasHeightForWidth())
        self.regedit_10.setSizePolicy(sizePolicy)
        self.regedit_10.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_10.addWidget(self.regedit_10)


        self.verticalLayout_3.addLayout(self.regOption_10)

        self.regOption_11 = QHBoxLayout()
        self.regOption_11.setObjectName(u"regOption_11")
        self.reglabel_11 = QLabel(self.PrestateView)
        self.reglabel_11.setObjectName(u"reglabel_11")
        sizePolicy.setHeightForWidth(self.reglabel_11.sizePolicy().hasHeightForWidth())
        self.reglabel_11.setSizePolicy(sizePolicy)
        self.reglabel_11.setFont(font4)
        self.reglabel_11.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_11.addWidget(self.reglabel_11)

        self.regedit_11 = QLineEdit(self.PrestateView)
        self.regedit_11.setObjectName(u"regedit_11")
        sizePolicy.setHeightForWidth(self.regedit_11.sizePolicy().hasHeightForWidth())
        self.regedit_11.setSizePolicy(sizePolicy)
        self.regedit_11.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_11.addWidget(self.regedit_11)


        self.verticalLayout_3.addLayout(self.regOption_11)

        self.regOption_12 = QHBoxLayout()
        self.regOption_12.setObjectName(u"regOption_12")
        self.reglabel_12 = QLabel(self.PrestateView)
        self.reglabel_12.setObjectName(u"reglabel_12")
        sizePolicy.setHeightForWidth(self.reglabel_12.sizePolicy().hasHeightForWidth())
        self.reglabel_12.setSizePolicy(sizePolicy)
        self.reglabel_12.setFont(font4)
        self.reglabel_12.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_12.addWidget(self.reglabel_12)

        self.regedit_12 = QLineEdit(self.PrestateView)
        self.regedit_12.setObjectName(u"regedit_12")
        sizePolicy.setHeightForWidth(self.regedit_12.sizePolicy().hasHeightForWidth())
        self.regedit_12.setSizePolicy(sizePolicy)
        self.regedit_12.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_12.addWidget(self.regedit_12)


        self.verticalLayout_3.addLayout(self.regOption_12)

        self.regOption_13 = QHBoxLayout()
        self.regOption_13.setObjectName(u"regOption_13")
        self.reglabel_13 = QLabel(self.PrestateView)
        self.reglabel_13.setObjectName(u"reglabel_13")
        sizePolicy.setHeightForWidth(self.reglabel_13.sizePolicy().hasHeightForWidth())
        self.reglabel_13.setSizePolicy(sizePolicy)
        self.reglabel_13.setFont(font4)
        self.reglabel_13.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_13.addWidget(self.reglabel_13)

        self.regedit_13 = QLineEdit(self.PrestateView)
        self.regedit_13.setObjectName(u"regedit_13")
        sizePolicy.setHeightForWidth(self.regedit_13.sizePolicy().hasHeightForWidth())
        self.regedit_13.setSizePolicy(sizePolicy)
        self.regedit_13.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_13.addWidget(self.regedit_13)


        self.verticalLayout_3.addLayout(self.regOption_13)

        self.regOption_14 = QHBoxLayout()
        self.regOption_14.setObjectName(u"regOption_14")
        self.reglabel_14 = QLabel(self.PrestateView)
        self.reglabel_14.setObjectName(u"reglabel_14")
        sizePolicy.setHeightForWidth(self.reglabel_14.sizePolicy().hasHeightForWidth())
        self.reglabel_14.setSizePolicy(sizePolicy)
        self.reglabel_14.setFont(font4)
        self.reglabel_14.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_14.addWidget(self.reglabel_14)

        self.regedit_14 = QLineEdit(self.PrestateView)
        self.regedit_14.setObjectName(u"regedit_14")
        sizePolicy.setHeightForWidth(self.regedit_14.sizePolicy().hasHeightForWidth())
        self.regedit_14.setSizePolicy(sizePolicy)
        self.regedit_14.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_14.addWidget(self.regedit_14)


        self.verticalLayout_3.addLayout(self.regOption_14)

        self.regOption_15 = QHBoxLayout()
        self.regOption_15.setObjectName(u"regOption_15")
        self.reglabel_15 = QLabel(self.PrestateView)
        self.reglabel_15.setObjectName(u"reglabel_15")
        sizePolicy.setHeightForWidth(self.reglabel_15.sizePolicy().hasHeightForWidth())
        self.reglabel_15.setSizePolicy(sizePolicy)
        self.reglabel_15.setFont(font4)
        self.reglabel_15.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_15.addWidget(self.reglabel_15)

        self.regedit_15 = QLineEdit(self.PrestateView)
        self.regedit_15.setObjectName(u"regedit_15")
        sizePolicy.setHeightForWidth(self.regedit_15.sizePolicy().hasHeightForWidth())
        self.regedit_15.setSizePolicy(sizePolicy)
        self.regedit_15.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_15.addWidget(self.regedit_15)


        self.verticalLayout_3.addLayout(self.regOption_15)

        self.regOption_16 = QHBoxLayout()
        self.regOption_16.setObjectName(u"regOption_16")
        self.reglabel_16 = QLabel(self.PrestateView)
        self.reglabel_16.setObjectName(u"reglabel_16")
        sizePolicy.setHeightForWidth(self.reglabel_16.sizePolicy().hasHeightForWidth())
        self.reglabel_16.setSizePolicy(sizePolicy)
        self.reglabel_16.setFont(font4)
        self.reglabel_16.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_16.addWidget(self.reglabel_16)

        self.regedit_16 = QLineEdit(self.PrestateView)
        self.regedit_16.setObjectName(u"regedit_16")
        sizePolicy.setHeightForWidth(self.regedit_16.sizePolicy().hasHeightForWidth())
        self.regedit_16.setSizePolicy(sizePolicy)
        self.regedit_16.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_16.addWidget(self.regedit_16)


        self.verticalLayout_3.addLayout(self.regOption_16)


        self.horizontalLayout_6.addLayout(self.verticalLayout_3)

        self.verticalLayout_4 = QVBoxLayout()
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.regOption_17 = QHBoxLayout()
        self.regOption_17.setObjectName(u"regOption_17")
        self.reglabel_17 = QLabel(self.PrestateView)
        self.reglabel_17.setObjectName(u"reglabel_17")
        sizePolicy.setHeightForWidth(self.reglabel_17.sizePolicy().hasHeightForWidth())
        self.reglabel_17.setSizePolicy(sizePolicy)
        self.reglabel_17.setFont(font4)
        self.reglabel_17.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_17.addWidget(self.reglabel_17)

        self.regedit_17 = QLineEdit(self.PrestateView)
        self.regedit_17.setObjectName(u"regedit_17")
        sizePolicy.setHeightForWidth(self.regedit_17.sizePolicy().hasHeightForWidth())
        self.regedit_17.setSizePolicy(sizePolicy)
        self.regedit_17.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_17.addWidget(self.regedit_17)


        self.verticalLayout_4.addLayout(self.regOption_17)

        self.regOption_18 = QHBoxLayout()
        self.regOption_18.setObjectName(u"regOption_18")
        self.reglabel_18 = QLabel(self.PrestateView)
        self.reglabel_18.setObjectName(u"reglabel_18")
        sizePolicy.setHeightForWidth(self.reglabel_18.sizePolicy().hasHeightForWidth())
        self.reglabel_18.setSizePolicy(sizePolicy)
        self.reglabel_18.setFont(font4)
        self.reglabel_18.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_18.addWidget(self.reglabel_18)

        self.regedit_18 = QLineEdit(self.PrestateView)
        self.regedit_18.setObjectName(u"regedit_18")
        sizePolicy.setHeightForWidth(self.regedit_18.sizePolicy().hasHeightForWidth())
        self.regedit_18.setSizePolicy(sizePolicy)
        self.regedit_18.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_18.addWidget(self.regedit_18)


        self.verticalLayout_4.addLayout(self.regOption_18)

        self.regOption_19 = QHBoxLayout()
        self.regOption_19.setObjectName(u"regOption_19")
        self.reglabel_19 = QLabel(self.PrestateView)
        self.reglabel_19.setObjectName(u"reglabel_19")
        sizePolicy.setHeightForWidth(self.reglabel_19.sizePolicy().hasHeightForWidth())
        self.reglabel_19.setSizePolicy(sizePolicy)
        self.reglabel_19.setFont(font4)
        self.reglabel_19.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_19.addWidget(self.reglabel_19)

        self.regedit_19 = QLineEdit(self.PrestateView)
        self.regedit_19.setObjectName(u"regedit_19")
        sizePolicy.setHeightForWidth(self.regedit_19.sizePolicy().hasHeightForWidth())
        self.regedit_19.setSizePolicy(sizePolicy)
        self.regedit_19.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_19.addWidget(self.regedit_19)


        self.verticalLayout_4.addLayout(self.regOption_19)

        self.regOption_20 = QHBoxLayout()
        self.regOption_20.setObjectName(u"regOption_20")
        self.reglabel_20 = QLabel(self.PrestateView)
        self.reglabel_20.setObjectName(u"reglabel_20")
        sizePolicy.setHeightForWidth(self.reglabel_20.sizePolicy().hasHeightForWidth())
        self.reglabel_20.setSizePolicy(sizePolicy)
        self.reglabel_20.setFont(font4)
        self.reglabel_20.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_20.addWidget(self.reglabel_20)

        self.regedit_20 = QLineEdit(self.PrestateView)
        self.regedit_20.setObjectName(u"regedit_20")
        sizePolicy.setHeightForWidth(self.regedit_20.sizePolicy().hasHeightForWidth())
        self.regedit_20.setSizePolicy(sizePolicy)
        self.regedit_20.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_20.addWidget(self.regedit_20)


        self.verticalLayout_4.addLayout(self.regOption_20)

        self.regOption_21 = QHBoxLayout()
        self.regOption_21.setObjectName(u"regOption_21")
        self.reglabel_21 = QLabel(self.PrestateView)
        self.reglabel_21.setObjectName(u"reglabel_21")
        sizePolicy.setHeightForWidth(self.reglabel_21.sizePolicy().hasHeightForWidth())
        self.reglabel_21.setSizePolicy(sizePolicy)
        self.reglabel_21.setFont(font4)
        self.reglabel_21.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_21.addWidget(self.reglabel_21)

        self.regedit_21 = QLineEdit(self.PrestateView)
        self.regedit_21.setObjectName(u"regedit_21")
        sizePolicy.setHeightForWidth(self.regedit_21.sizePolicy().hasHeightForWidth())
        self.regedit_21.setSizePolicy(sizePolicy)
        self.regedit_21.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_21.addWidget(self.regedit_21)


        self.verticalLayout_4.addLayout(self.regOption_21)

        self.regOption_22 = QHBoxLayout()
        self.regOption_22.setObjectName(u"regOption_22")
        self.reglabel_22 = QLabel(self.PrestateView)
        self.reglabel_22.setObjectName(u"reglabel_22")
        sizePolicy.setHeightForWidth(self.reglabel_22.sizePolicy().hasHeightForWidth())
        self.reglabel_22.setSizePolicy(sizePolicy)
        self.reglabel_22.setFont(font4)
        self.reglabel_22.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_22.addWidget(self.reglabel_22)

        self.regedit_22 = QLineEdit(self.PrestateView)
        self.regedit_22.setObjectName(u"regedit_22")
        sizePolicy.setHeightForWidth(self.regedit_22.sizePolicy().hasHeightForWidth())
        self.regedit_22.setSizePolicy(sizePolicy)
        self.regedit_22.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_22.addWidget(self.regedit_22)


        self.verticalLayout_4.addLayout(self.regOption_22)

        self.regOption_23 = QHBoxLayout()
        self.regOption_23.setObjectName(u"regOption_23")
        self.reglabel_23 = QLabel(self.PrestateView)
        self.reglabel_23.setObjectName(u"reglabel_23")
        sizePolicy.setHeightForWidth(self.reglabel_23.sizePolicy().hasHeightForWidth())
        self.reglabel_23.setSizePolicy(sizePolicy)
        self.reglabel_23.setFont(font4)
        self.reglabel_23.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_23.addWidget(self.reglabel_23)

        self.regedit_23 = QLineEdit(self.PrestateView)
        self.regedit_23.setObjectName(u"regedit_23")
        sizePolicy.setHeightForWidth(self.regedit_23.sizePolicy().hasHeightForWidth())
        self.regedit_23.setSizePolicy(sizePolicy)
        self.regedit_23.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_23.addWidget(self.regedit_23)


        self.verticalLayout_4.addLayout(self.regOption_23)

        self.regOption_24 = QHBoxLayout()
        self.regOption_24.setObjectName(u"regOption_24")
        self.reglabel_24 = QLabel(self.PrestateView)
        self.reglabel_24.setObjectName(u"reglabel_24")
        sizePolicy.setHeightForWidth(self.reglabel_24.sizePolicy().hasHeightForWidth())
        self.reglabel_24.setSizePolicy(sizePolicy)
        self.reglabel_24.setFont(font4)
        self.reglabel_24.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_24.addWidget(self.reglabel_24)

        self.regedit_24 = QLineEdit(self.PrestateView)
        self.regedit_24.setObjectName(u"regedit_24")
        sizePolicy.setHeightForWidth(self.regedit_24.sizePolicy().hasHeightForWidth())
        self.regedit_24.setSizePolicy(sizePolicy)
        self.regedit_24.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_24.addWidget(self.regedit_24)


        self.verticalLayout_4.addLayout(self.regOption_24)


        self.horizontalLayout_6.addLayout(self.verticalLayout_4)

        self.verticalLayout_5 = QVBoxLayout()
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.regOption_25 = QHBoxLayout()
        self.regOption_25.setObjectName(u"regOption_25")
        self.reglabel_25 = QLabel(self.PrestateView)
        self.reglabel_25.setObjectName(u"reglabel_25")
        sizePolicy.setHeightForWidth(self.reglabel_25.sizePolicy().hasHeightForWidth())
        self.reglabel_25.setSizePolicy(sizePolicy)
        self.reglabel_25.setFont(font4)
        self.reglabel_25.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_25.addWidget(self.reglabel_25)

        self.regedit_25 = QLineEdit(self.PrestateView)
        self.regedit_25.setObjectName(u"regedit_25")
        sizePolicy.setHeightForWidth(self.regedit_25.sizePolicy().hasHeightForWidth())
        self.regedit_25.setSizePolicy(sizePolicy)
        self.regedit_25.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_25.addWidget(self.regedit_25)


        self.verticalLayout_5.addLayout(self.regOption_25)

        self.regOption_26 = QHBoxLayout()
        self.regOption_26.setObjectName(u"regOption_26")
        self.reglabel_26 = QLabel(self.PrestateView)
        self.reglabel_26.setObjectName(u"reglabel_26")
        sizePolicy.setHeightForWidth(self.reglabel_26.sizePolicy().hasHeightForWidth())
        self.reglabel_26.setSizePolicy(sizePolicy)
        self.reglabel_26.setFont(font4)
        self.reglabel_26.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_26.addWidget(self.reglabel_26)

        self.regedit_26 = QLineEdit(self.PrestateView)
        self.regedit_26.setObjectName(u"regedit_26")
        sizePolicy.setHeightForWidth(self.regedit_26.sizePolicy().hasHeightForWidth())
        self.regedit_26.setSizePolicy(sizePolicy)
        self.regedit_26.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_26.addWidget(self.regedit_26)


        self.verticalLayout_5.addLayout(self.regOption_26)

        self.regOption_27 = QHBoxLayout()
        self.regOption_27.setObjectName(u"regOption_27")
        self.reglabel_27 = QLabel(self.PrestateView)
        self.reglabel_27.setObjectName(u"reglabel_27")
        sizePolicy.setHeightForWidth(self.reglabel_27.sizePolicy().hasHeightForWidth())
        self.reglabel_27.setSizePolicy(sizePolicy)
        self.reglabel_27.setFont(font4)
        self.reglabel_27.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_27.addWidget(self.reglabel_27)

        self.regedit_27 = QLineEdit(self.PrestateView)
        self.regedit_27.setObjectName(u"regedit_27")
        sizePolicy.setHeightForWidth(self.regedit_27.sizePolicy().hasHeightForWidth())
        self.regedit_27.setSizePolicy(sizePolicy)
        self.regedit_27.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_27.addWidget(self.regedit_27)


        self.verticalLayout_5.addLayout(self.regOption_27)

        self.regOption_28 = QHBoxLayout()
        self.regOption_28.setObjectName(u"regOption_28")
        self.reglabel_28 = QLabel(self.PrestateView)
        self.reglabel_28.setObjectName(u"reglabel_28")
        sizePolicy.setHeightForWidth(self.reglabel_28.sizePolicy().hasHeightForWidth())
        self.reglabel_28.setSizePolicy(sizePolicy)
        self.reglabel_28.setFont(font4)
        self.reglabel_28.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_28.addWidget(self.reglabel_28)

        self.regedit_28 = QLineEdit(self.PrestateView)
        self.regedit_28.setObjectName(u"regedit_28")
        sizePolicy.setHeightForWidth(self.regedit_28.sizePolicy().hasHeightForWidth())
        self.regedit_28.setSizePolicy(sizePolicy)
        self.regedit_28.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_28.addWidget(self.regedit_28)


        self.verticalLayout_5.addLayout(self.regOption_28)

        self.regOption_29 = QHBoxLayout()
        self.regOption_29.setObjectName(u"regOption_29")
        self.reglabel_29 = QLabel(self.PrestateView)
        self.reglabel_29.setObjectName(u"reglabel_29")
        sizePolicy.setHeightForWidth(self.reglabel_29.sizePolicy().hasHeightForWidth())
        self.reglabel_29.setSizePolicy(sizePolicy)
        self.reglabel_29.setFont(font4)
        self.reglabel_29.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_29.addWidget(self.reglabel_29)

        self.regedit_29 = QLineEdit(self.PrestateView)
        self.regedit_29.setObjectName(u"regedit_29")
        sizePolicy.setHeightForWidth(self.regedit_29.sizePolicy().hasHeightForWidth())
        self.regedit_29.setSizePolicy(sizePolicy)
        self.regedit_29.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_29.addWidget(self.regedit_29)


        self.verticalLayout_5.addLayout(self.regOption_29)

        self.regOption_30 = QHBoxLayout()
        self.regOption_30.setObjectName(u"regOption_30")
        self.reglabel_30 = QLabel(self.PrestateView)
        self.reglabel_30.setObjectName(u"reglabel_30")
        sizePolicy.setHeightForWidth(self.reglabel_30.sizePolicy().hasHeightForWidth())
        self.reglabel_30.setSizePolicy(sizePolicy)
        self.reglabel_30.setFont(font4)
        self.reglabel_30.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_30.addWidget(self.reglabel_30)

        self.regedit_30 = QLineEdit(self.PrestateView)
        self.regedit_30.setObjectName(u"regedit_30")
        sizePolicy.setHeightForWidth(self.regedit_30.sizePolicy().hasHeightForWidth())
        self.regedit_30.setSizePolicy(sizePolicy)
        self.regedit_30.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_30.addWidget(self.regedit_30)


        self.verticalLayout_5.addLayout(self.regOption_30)

        self.regOption_31 = QHBoxLayout()
        self.regOption_31.setObjectName(u"regOption_31")
        self.reglabel_31 = QLabel(self.PrestateView)
        self.reglabel_31.setObjectName(u"reglabel_31")
        sizePolicy.setHeightForWidth(self.reglabel_31.sizePolicy().hasHeightForWidth())
        self.reglabel_31.setSizePolicy(sizePolicy)
        self.reglabel_31.setFont(font4)
        self.reglabel_31.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_31.addWidget(self.reglabel_31)

        self.regedit_31 = QLineEdit(self.PrestateView)
        self.regedit_31.setObjectName(u"regedit_31")
        sizePolicy.setHeightForWidth(self.regedit_31.sizePolicy().hasHeightForWidth())
        self.regedit_31.setSizePolicy(sizePolicy)
        self.regedit_31.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_31.addWidget(self.regedit_31)


        self.verticalLayout_5.addLayout(self.regOption_31)

        self.regOption_32 = QHBoxLayout()
        self.regOption_32.setObjectName(u"regOption_32")
        self.reglabel_32 = QLabel(self.PrestateView)
        self.reglabel_32.setObjectName(u"reglabel_32")
        sizePolicy.setHeightForWidth(self.reglabel_32.sizePolicy().hasHeightForWidth())
        self.reglabel_32.setSizePolicy(sizePolicy)
        self.reglabel_32.setFont(font4)
        self.reglabel_32.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_32.addWidget(self.reglabel_32)

        self.regedit_32 = QLineEdit(self.PrestateView)
        self.regedit_32.setObjectName(u"regedit_32")
        sizePolicy.setHeightForWidth(self.regedit_32.sizePolicy().hasHeightForWidth())
        self.regedit_32.setSizePolicy(sizePolicy)
        self.regedit_32.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.regOption_32.addWidget(self.regedit_32)


        self.verticalLayout_5.addLayout(self.regOption_32)


        self.horizontalLayout_6.addLayout(self.verticalLayout_5)


        self.verticalLayout_9.addLayout(self.horizontalLayout_6)

        self.corefileBox = QHBoxLayout()
        self.corefileBox.setObjectName(u"corefileBox")
        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.corefileBox.addItem(self.verticalSpacer)

        self.corefileButton = QPushButton(self.PrestateView)
        self.corefileButton.setObjectName(u"corefileButton")

        self.corefileBox.addWidget(self.corefileButton)

        self.verticalSpacer_2 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.corefileBox.addItem(self.verticalSpacer_2)


        self.verticalLayout_9.addLayout(self.corefileBox)

        self.horizontalSpacer = QSpacerItem(879, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.verticalLayout_9.addItem(self.horizontalSpacer)

        self.tabWidget.addTab(self.PrestateView, "")
        self.PresetView = QWidget()
        self.PresetView.setObjectName(u"PresetView")
        self.verticalLayout = QVBoxLayout(self.PresetView)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.splitter_3 = QSplitter(self.PresetView)
        self.splitter_3.setObjectName(u"splitter_3")
        self.splitter_3.setOrientation(Qt.Horizontal)
        self.layoutWidget = QWidget(self.splitter_3)
        self.layoutWidget.setObjectName(u"layoutWidget")
        self.addPresets = QVBoxLayout(self.layoutWidget)
        self.addPresets.setObjectName(u"addPresets")
        self.addPresets.setContentsMargins(0, 0, 0, 0)
        self.keyLabel = QLabel(self.layoutWidget)
        self.keyLabel.setObjectName(u"keyLabel")
        font5 = QFont()
        font5.setPointSize(18)
        self.keyLabel.setFont(font5)
        self.keyLabel.setScaledContents(False)
        self.keyLabel.setAlignment(Qt.AlignCenter)

        self.addPresets.addWidget(self.keyLabel)

        self.keyEdit = QTextEdit(self.layoutWidget)
        self.keyEdit.setObjectName(u"keyEdit")

        self.addPresets.addWidget(self.keyEdit)

        self.defLabel = QLabel(self.layoutWidget)
        self.defLabel.setObjectName(u"defLabel")
        font6 = QFont()
        font6.setPointSize(11)
        self.defLabel.setFont(font6)
        self.defLabel.setAlignment(Qt.AlignCenter)

        self.addPresets.addWidget(self.defLabel)

        self.defEdit = QTextEdit(self.layoutWidget)
        self.defEdit.setObjectName(u"defEdit")

        self.addPresets.addWidget(self.defEdit)

        self.presetButton = QPushButton(self.layoutWidget)
        self.presetButton.setObjectName(u"presetButton")

        self.addPresets.addWidget(self.presetButton)

        self.presetStatus = QLabel(self.layoutWidget)
        self.presetStatus.setObjectName(u"presetStatus")

        self.addPresets.addWidget(self.presetStatus)

        self.splitter_3.addWidget(self.layoutWidget)
        self.layoutWidget1 = QWidget(self.splitter_3)
        self.layoutWidget1.setObjectName(u"layoutWidget1")
        self.currentPresets = QVBoxLayout(self.layoutWidget1)
        self.currentPresets.setObjectName(u"currentPresets")
        self.currentPresets.setContentsMargins(0, 0, 0, 0)
        self.currentLabel = QLabel(self.layoutWidget1)
        self.currentLabel.setObjectName(u"currentLabel")
        self.currentLabel.setFont(font5)
        self.currentLabel.setLayoutDirection(Qt.LeftToRight)
        self.currentLabel.setTextFormat(Qt.AutoText)
        self.currentLabel.setScaledContents(False)
        self.currentLabel.setAlignment(Qt.AlignCenter)
        self.currentLabel.setWordWrap(False)

        self.currentPresets.addWidget(self.currentLabel)

        self.splitter_2 = QSplitter(self.layoutWidget1)
        self.splitter_2.setObjectName(u"splitter_2")
        self.splitter_2.setOrientation(Qt.Vertical)
        self.keyView = QListView(self.splitter_2)
        self.keyView.setObjectName(u"keyView")
        self.splitter_2.addWidget(self.keyView)
        self.defView = QListView(self.splitter_2)
        self.defView.setObjectName(u"defView")
        self.splitter_2.addWidget(self.defView)

        self.currentPresets.addWidget(self.splitter_2)

        self.splitter_3.addWidget(self.layoutWidget1)

        self.verticalLayout.addWidget(self.splitter_3)

        self.tabWidget.addTab(self.PresetView, "")
        self.OptionsView = QWidget()
        self.OptionsView.setObjectName(u"OptionsView")
        self.verticalLayout_8 = QVBoxLayout(self.OptionsView)
        self.verticalLayout_8.setObjectName(u"verticalLayout_8")
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

        self.verticalLayout_8.addWidget(self.searchLabel)

        self.options1_2 = QHBoxLayout()
        self.options1_2.setObjectName(u"options1_2")
        self.badbytesOpt_2 = QHBoxLayout()
        self.badbytesOpt_2.setObjectName(u"badbytesOpt_2")
        self.label_6 = QLabel(self.OptionsView)
        self.label_6.setObjectName(u"label_6")
        self.label_6.setFont(font4)
        self.label_6.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.badbytesOpt_2.addWidget(self.label_6)

        self.badBytesEdit = QLineEdit(self.OptionsView)
        self.badBytesEdit.setObjectName(u"badBytesEdit")
        self.badBytesEdit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)
        self.badBytesEdit.setClearButtonEnabled(False)

        self.badbytesOpt_2.addWidget(self.badBytesEdit)


        self.options1_2.addLayout(self.badbytesOpt_2)

        self.depthOpt_2 = QHBoxLayout()
        self.depthOpt_2.setObjectName(u"depthOpt_2")

        self.options1_2.addLayout(self.depthOpt_2)

        self.blockOpt_2 = QHBoxLayout()
        self.blockOpt_2.setObjectName(u"blockOpt_2")

        self.options1_2.addLayout(self.blockOpt_2)


        self.verticalLayout_8.addLayout(self.options1_2)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.rangeLabel = QLabel(self.OptionsView)
        self.rangeLabel.setObjectName(u"rangeLabel")
        self.rangeLabel.setFont(font4)
        self.rangeLabel.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_3.addWidget(self.rangeLabel)

        self.rangeEdit = QLineEdit(self.OptionsView)
        self.rangeEdit.setObjectName(u"rangeEdit")
        self.rangeEdit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_3.addWidget(self.rangeEdit)


        self.verticalLayout_8.addLayout(self.horizontalLayout_3)

        self.horizontalLayout_4 = QHBoxLayout()
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.label_8 = QLabel(self.OptionsView)
        self.label_8.setObjectName(u"label_8")
        self.label_8.setFont(font4)
        self.label_8.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_4.addWidget(self.label_8)

        self.blockEdit = QLineEdit(self.OptionsView)
        self.blockEdit.setObjectName(u"blockEdit")
        self.blockEdit.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_4.addWidget(self.blockEdit)


        self.verticalLayout_8.addLayout(self.horizontalLayout_4)

        self.horizontalLayout_5 = QHBoxLayout()
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.instcntLabel = QLabel(self.OptionsView)
        self.instcntLabel.setObjectName(u"instcntLabel")
        self.instcntLabel.setFont(font4)
        self.instcntLabel.setLayoutDirection(Qt.LeftToRight)
        self.instcntLabel.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_5.addWidget(self.instcntLabel)

        self.instCntSpinbox = QSpinBox(self.OptionsView)
        self.instCntSpinbox.setObjectName(u"instCntSpinbox")
        self.instCntSpinbox.setValue(0)

        self.horizontalLayout_5.addWidget(self.instCntSpinbox)

        self.label_7 = QLabel(self.OptionsView)
        self.label_7.setObjectName(u"label_7")
        self.label_7.setFont(font4)
        self.label_7.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_5.addWidget(self.label_7)

        self.depthBox = QSpinBox(self.OptionsView)
        self.depthBox.setObjectName(u"depthBox")
        self.depthBox.setKeyboardTracking(True)
        self.depthBox.setMinimum(1)
        self.depthBox.setValue(10)

        self.horizontalLayout_5.addWidget(self.depthBox)

        self.label_4 = QLabel(self.OptionsView)
        self.label_4.setObjectName(u"label_4")
        self.label_4.setAlignment(Qt.AlignRight|Qt.AlignTrailing|Qt.AlignVCenter)

        self.horizontalLayout_5.addWidget(self.label_4)

        self.semanticBox = QSpinBox(self.OptionsView)
        self.semanticBox.setObjectName(u"semanticBox")
        self.semanticBox.setMaximum(1000)
        self.semanticBox.setValue(500)

        self.horizontalLayout_5.addWidget(self.semanticBox)


        self.verticalLayout_8.addLayout(self.horizontalLayout_5)

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

        self.thumbOpt = QCheckBox(self.OptionsView)
        self.thumbOpt.setObjectName(u"thumbOpt")

        self.horizontalLayout_2.addWidget(self.thumbOpt)


        self.verticalLayout_8.addLayout(self.horizontalLayout_2)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.reloadButton = QPushButton(self.OptionsView)
        self.reloadButton.setObjectName(u"reloadButton")
        sizePolicy.setHeightForWidth(self.reloadButton.sizePolicy().hasHeightForWidth())
        self.reloadButton.setSizePolicy(sizePolicy)
        self.reloadButton.setAutoExclusive(False)

        self.horizontalLayout.addWidget(self.reloadButton)

        self.clearCacheButton = QPushButton(self.OptionsView)
        self.clearCacheButton.setObjectName(u"clearCacheButton")
        sizePolicy.setHeightForWidth(self.clearCacheButton.sizePolicy().hasHeightForWidth())
        self.clearCacheButton.setSizePolicy(sizePolicy)
        self.clearCacheButton.setAutoExclusive(False)

        self.horizontalLayout.addWidget(self.clearCacheButton)

        self.exportButton = QPushButton(self.OptionsView)
        self.exportButton.setObjectName(u"exportButton")

        self.horizontalLayout.addWidget(self.exportButton)


        self.verticalLayout_8.addLayout(self.horizontalLayout)

        self.optionsStatus = QLabel(self.OptionsView)
        self.optionsStatus.setObjectName(u"optionsStatus")

        self.verticalLayout_8.addWidget(self.optionsStatus)

        self.horizontalSpacer_2 = QSpacerItem(879, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.verticalLayout_8.addItem(self.horizontalSpacer_2)

        self.tabWidget.addTab(self.OptionsView, "")

        self.verticalLayout_6.addWidget(self.tabWidget)


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
        self.reglabel_22.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_22.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_23.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_23.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_24.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_24.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_25.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_25.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_26.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_26.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_27.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_27.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_28.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_28.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_29.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_29.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_30.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_30.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_31.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_31.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.reglabel_32.setText(QCoreApplication.translate("Form", u"empty", None))
        self.regedit_32.setPlaceholderText(QCoreApplication.translate("Form", u"0x0", None))
        self.corefileButton.setText(QCoreApplication.translate("Form", u"Import Corefile", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrestateView), QCoreApplication.translate("Form", u"Prestates", None))
        self.keyLabel.setText(QCoreApplication.translate("Form", u"Create", None))
        self.keyEdit.setPlaceholderText(QCoreApplication.translate("Form", u"cet", None))
        self.defLabel.setText(QCoreApplication.translate("Form", u"translates to:", None))
        self.defEdit.setMarkdown("")
        self.defEdit.setPlaceholderText(QCoreApplication.translate("Form", u"disasm.str.contains(\"endbr64\") and inst_cnt < 10", None))
        self.presetButton.setText(QCoreApplication.translate("Form", u"Add", None))
        self.presetStatus.setText("")
        self.currentLabel.setText(QCoreApplication.translate("Form", u"Current Presets", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PresetView), QCoreApplication.translate("Form", u"Presets", None))
        self.searchLabel.setText(QCoreApplication.translate("Form", u"Gadget Search Options", None))
#if QT_CONFIG(tooltip)
        self.label_6.setToolTip(QCoreApplication.translate("Form", u"Bytes to exclude from gadget addresses.", None))
#endif // QT_CONFIG(tooltip)
        self.label_6.setText(QCoreApplication.translate("Form", u"Bad bytes:", None))
#if QT_CONFIG(tooltip)
        self.badBytesEdit.setToolTip(QCoreApplication.translate("Form", u"Bytes to exclude from gadget addresses.", None))
#endif // QT_CONFIG(tooltip)
        self.badBytesEdit.setPlaceholderText(QCoreApplication.translate("Form", u"0xc0,0xf0,...", None))
#if QT_CONFIG(tooltip)
        self.rangeLabel.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets in an address range.", None))
#endif // QT_CONFIG(tooltip)
        self.rangeLabel.setText(QCoreApplication.translate("Form", u"Address range:", None))
#if QT_CONFIG(tooltip)
        self.rangeEdit.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets in an address range.", None))
#endif // QT_CONFIG(tooltip)
        self.rangeEdit.setPlaceholderText(QCoreApplication.translate("Form", u"0x??????-0x?????", None))
#if QT_CONFIG(tooltip)
        self.label_8.setToolTip(QCoreApplication.translate("Form", u"mnemonics to block, comma seperated.", None))
#endif // QT_CONFIG(tooltip)
        self.label_8.setText(QCoreApplication.translate("Form", u"Block:", None))
#if QT_CONFIG(tooltip)
        self.blockEdit.setToolTip(QCoreApplication.translate("Form", u"mnemonics to block, comma seperated.", None))
#endif // QT_CONFIG(tooltip)
        self.blockEdit.setText("")
        self.blockEdit.setPlaceholderText(QCoreApplication.translate("Form", u"dec ax,inc ax,...", None))
#if QT_CONFIG(tooltip)
        self.instcntLabel.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets with n instructions. (Disabled when 0)", None))
#endif // QT_CONFIG(tooltip)
        self.instcntLabel.setText(QCoreApplication.translate("Form", u"Instruction count:", None))
#if QT_CONFIG(tooltip)
        self.instCntSpinbox.setToolTip(QCoreApplication.translate("Form", u"Only include gadgets with n instructions. (Disabled when 0)", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.label_7.setToolTip(QCoreApplication.translate("Form", u"How many bytes to go back from when looking for gadgets.", None))
#endif // QT_CONFIG(tooltip)
        self.label_7.setText(QCoreApplication.translate("Form", u"Depth:", None))
#if QT_CONFIG(tooltip)
        self.depthBox.setToolTip(QCoreApplication.translate("Form", u"How many bytes to go back from when looking for gadgets.", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.label_4.setToolTip(QCoreApplication.translate("Form", u"The depth semantic search uses to limit exhaustion", None))
#endif // QT_CONFIG(tooltip)
        self.label_4.setText(QCoreApplication.translate("Form", u"Semantic depth:", None))
#if QT_CONFIG(tooltip)
        self.semanticBox.setToolTip(QCoreApplication.translate("Form", u"The depth semantic search uses to limit exhaustion", None))
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
        self.thumbOpt.setToolTip(QCoreApplication.translate("Form", u"Search in thumb mode.", None))
#endif // QT_CONFIG(tooltip)
        self.thumbOpt.setText(QCoreApplication.translate("Form", u"Thumb", None))
#if QT_CONFIG(tooltip)
        self.reloadButton.setToolTip(QCoreApplication.translate("Form", u"Start new gadget search", None))
#endif // QT_CONFIG(tooltip)
        self.reloadButton.setText(QCoreApplication.translate("Form", u"Reload", None))
#if QT_CONFIG(tooltip)
        self.clearCacheButton.setToolTip(QCoreApplication.translate("Form", u"Clear gadget and analysis cache.", None))
#endif // QT_CONFIG(tooltip)
        self.clearCacheButton.setText(QCoreApplication.translate("Form", u"Clear cache", None))
#if QT_CONFIG(tooltip)
        self.exportButton.setToolTip(QCoreApplication.translate("Form", u"Export gadgets dataframe to csv for data analysis", None))
#endif // QT_CONFIG(tooltip)
        self.exportButton.setText(QCoreApplication.translate("Form", u"Export gadgets", None))
        self.optionsStatus.setText("")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.OptionsView), QCoreApplication.translate("Form", u"Options", None))
    # retranslateUi

