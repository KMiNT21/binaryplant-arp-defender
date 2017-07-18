__author__ = 'KMiNT21'
product_name = 'ARP Defender'
company_name = 'BinaryPlant'
full_product_name = 'BinaryPlant ARP Defender'
app_logo_icon = 'res\\logo.ico'
icon_protected = 'res\\protected.ico'
icon_alert = 'res\\alert.png'
hkey = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
settings_start_minimized = 'settings_start_minimized'
settings_auto_protect = 'settings_auto_protect'
timer_in_sec = 15


# INFO: get_arp_table() = list of records like [boolStaticFlag, 'IP', 'MAC']



import sys, os, subprocess, re, ctypes
from PyQt5 import QtGui, QtCore, uic
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMainWindow, QTableWidgetItem, QTreeWidgetItem
from PyQt5.QtCore import QSettings, QTimer
from functools import partial
#from PyQt5.QtCore import pyqtSignal
#from PyQt5.uic import loadUi
import win32gui
import win32con
import win32api
import pywintypes
import traceback


def get_arp_table():
    res = subprocess.check_output('arp -a', shell=True).decode("utf-8") #.rstrip())
    str_regex_ip = '(?:[0-9]{1,3}\.){3}[0-9]{1,3}|$'
    str_regex_ip_multicast = '2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}'
    str_regex_mac_addr = '([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})|$'
    str_regex_static_flag = 'static'
    find_ip_addr = lambda x: re.findall(str_regex_ip, x)[0]
    find_mac_addr = lambda x: re.findall(str_regex_mac_addr, x)[0]
    find_flag_ip_multicast  = lambda x: bool(re.search(str_regex_ip_multicast, x))
    find_flag_static = lambda x: bool(re.search(str_regex_static_flag, x))
    #parse_output_line = lambda x: [find_ip_addr(x), find_flag_ip_multicast(x), find_mac_addr(x), find_flag_static(x)]
    parse_output_line = lambda x: [find_flag_static(x), find_ip_addr(x), find_mac_addr(x), find_flag_ip_multicast(x)]
    #table = list(filter(None, list(map(parse_output_line, res.splitlines()))))
    #table = list(map(parse_output_line, res.splitlines()))
    table = [parse_output_line(x) for x in res.splitlines()]
    filter_good = lambda x: x[1] and x[2] and not x[3]
    table = list(filter(filter_good, table))
    # remove useless column 'multicast' and skip broadcast mac-record
    table = [[rec[0], rec[1], rec[2]] for rec in table if rec[2].lower().replace(':','-') != 'ff-ff-ff-ff-ff-ff']
    return table # [boolStaticFlag, IP, MAC]

# example:[  [False, '192.168.76.254', '00-50-56-e2-8c-19', False], .....]


def get_default_gateway_ip():
    res = subprocess.check_output('ipconfig', shell=True, universal_newlines=True) # alter: "netsh interface ipv4 show config"
    str_regex_default_gw = 'Default Gateway[^\d]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|$'
    find_default_gws = lambda x: re.findall(str_regex_default_gw, x)[0]
    gateway_entries = map(find_default_gws, res.splitlines())
    gateway = next(filter(None, gateway_entries), '')
    return gateway

def get_default_gateway_interface_name():
    res = subprocess.check_output('ipconfig', shell=True).decode('cp866')
    str_regex_interface_name = 'Ethernet adapter ([^:]*):|$'
    str_regex_default_gw = 'Default Gateway[^\d]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|$'
    for line in res.splitlines():
        if re.findall(str_regex_interface_name, line)[0]:
            last_interface_name = re.findall(str_regex_interface_name, line)[0]
        if re.findall(str_regex_default_gw, line)[0]:
            #print(last_interface_name)
            return last_interface_name
    return '' # if error


def find_ip_record(ip, table):
    this_ip = lambda x: x[1] == ip
    record = filter(this_ip, table)
    default_record = [False, ip, '']
    return next(record, default_record)


find_gw_mac   = lambda : find_ip_record(get_default_gateway_ip(), get_arp_table())[2]
is_gw_static = lambda : find_ip_record(get_default_gateway_ip(), get_arp_table())[0]


def add_static_record(ip, mac, if_name):
    # 1) Command:
    #     arp.exe -s IP MAC with IF_ADDR  doesn't work (I have no idea why)
    #     so, we have to use netsh.exe and must find network interface name (i.e. in 'ipconfig' output)
    # 2) Rights elevation
    #     working with powershell for elevation fails with encoding problems when IF_NAME non English
    #     cmd = "Powershell Start-Process 'netsh.exe' -ArgumentList 'interface ipv4 add neighbors \"%s\" \"%s\" \"%s\" store=active' -Verb runAs" % (if_name, ip, mac)
    #     so, we have to use elevation by ShellExecuteW:
    #     ShellExecuteW(None, "runas", simple_exe, simple_params, None, 1)
    exe_file = "netsh.exe"
    exe_params = "interface ipv4 add neighbors \"%s\" \"%s\" \"%s\" store=active" % (if_name, ip, mac)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_file, exe_params, None, 1)

set_gw_static = lambda : add_static_record(get_default_gateway_ip(), find_gw_mac(), get_default_gateway_interface_name())

def remove_static_record(ip):
    cmd = "Powershell Start-Process -WindowStyle hidden 'arp.exe' -ArgumentList '-d %s' -Verb runAs" % ip
    print('Removing STATIC record...')
    print(cmd)
    subprocess.Popen(cmd)
set_gw_dynamic = lambda : remove_static_record(get_default_gateway_ip())


########################################################################################################################
class BarpApp(QApplication):
    def __init__(self, agrv):
        super(BarpApp, self).__init__(agrv)
        self.tray = QSystemTrayIcon()
        self.tray.activated.connect(self.tray_clicks)
        self.menu = QMenu('Menu')
        self.menu.addAction('S&how Main Window', self.showSettings)
        self.menu.addSeparator()
        self.menu.addAction('E&xit', self.quit)
        self.tray.setIcon(QtGui.QIcon(app_logo_icon))
        self.tray.setToolTip(product_name)
        self.tray.setContextMenu(self.menu)
        self.settings_window = BarpMainWindow()
        self.setWindowIcon(QtGui.QIcon(app_logo_icon))
        self.myappid = '.'.join([company_name, product_name])
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(self.myappid) # to have own taskbar window
    def quit(self):
        self.tray.hide()
        super(BarpApp, self).quit()
    def tray_clicks(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.showSettings()
    def showTrayMenu(self):
        self.tray.show()
    def showSettings(self):
        self.settings_window.show()


########################################################################################################################
class BarpMainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(BarpMainWindow, self).__init__()
        self.path = os.path.dirname(os.path.abspath(__file__))
        self.ui_file = os.path.join(self.path, 'barp-win.ui')
        uic.loadUi(self.ui_file, self)
        timer = QTimer(self)
        timer.timeout.connect(self.onTimer)
        timer.start(1000 * timer_in_sec)
        self.label_gwIp.setText(get_default_gateway_ip())
        self.label_gwIp.setToolTip(get_default_gateway_interface_name())
        self.label_gwMac.setText(find_gw_mac())
        self.label_gwMac.setToolTip(get_default_gateway_interface_name())
        try: self.lineEdit_Timer.setText(str(timer_in_sec)) #TODO: un'try' when decided about lineEdit_Timer
        except: pass
        self.table = []
        self.updateTableWidget(self.table)
        self.buttonClearHistory()
        self.pushButton_Protect.setEnabled(bool(find_gw_mac()))
        # connect buttons
        self.pushButton_Protect.clicked.connect(self.toggleProtectionState)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reload_checkboxes)
        self.pushButton_Exit.clicked.connect(QtCore.QCoreApplication.instance().quit)
        self.pushButton_Update.clicked.connect(self.onTimer)
        self.pushButton_ClearHistory.clicked.connect(self.buttonClearHistory)
        # first init checkboxes from setting
        self.reload_checkboxes()
        # fist init tables
        self.onTimer()
        self.oldWndProc = win32gui.SetWindowLong(self.winId(), win32con.GWL_WNDPROC, self.localWndProc)
        if QSettings(company_name, product_name).value(settings_auto_protect, type=bool) and not is_gw_static:
            QTimer.singleShot(5000, set_gw_static)

    def accept(self):
        QSettings(company_name, product_name).setValue(settings_start_minimized, self.checkBox_StartMinimized.isChecked())
        QSettings(company_name, product_name).setValue(settings_auto_protect, self.checkBox_AutoProtect.isChecked())
        if self.checkBox_AutoRun.isChecked():
            QSettings(hkey, QSettings.NativeFormat).setValue(product_name, (sys.argv[0]))
        else:
            QSettings(hkey, QSettings.NativeFormat).remove(product_name)
        self.hide()

    def reload_checkboxes(self):
        self.checkBox_StartMinimized.setChecked(QSettings(company_name, product_name).value(settings_start_minimized, type=bool))
        self.checkBox_AutoProtect.setChecked(QSettings(company_name, product_name).value(settings_auto_protect, type=bool))
        self.checkBox_AutoRun.setChecked(QSettings(hkey, QSettings.NativeFormat).contains(product_name))
        self.hide()

    def update_history_dic(self, table, prev_history):
        history = prev_history.copy() # just to make function "clean"
        for flag_static, ip, mac in table:
            if ip not in history.keys():
                #print('New IP')
                history[ip] = list([mac])
            if mac not in history[ip]:
                #print('New MAC')
                history[ip].append(mac)
        return history

    def buttonClearHistory(self):
        self.history = self.update_history_dic(self.table, {})
        self.updateHistoryWidget(self.history)

    def updateTableWidget(self, arp_table):
        wt = self.tableWidget_Table
        wt.clear()
        wt.setRowCount(0)
        wt.setHorizontalHeaderLabels(['Type', 'IP', 'MAC'])
        formatted_cell = lambda cell: cell.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter) or cell
        for flag_static, ip, mac in arp_table:
            row_count = wt.rowCount()
            wt.insertRow(row_count)
            wt.setItem(row_count, 0, formatted_cell(QTableWidgetItem(('s' if flag_static  else ''))))
            wt.setItem(row_count, 1, formatted_cell(QTableWidgetItem(ip)))
            wt.setItem(row_count, 2, formatted_cell(QTableWidgetItem(mac)))

        wt.resizeColumnsToContents()
        wt.horizontalHeader().setStretchLastSection(True)
        #print(getGwIp())
        #print(protection_enabled)

    def updateHistoryWidget(self, history_dic):
        self.treeWidget_History.clear()
        for ip in history_dic:
            ip_line = QTreeWidgetItem([ip])
            [ip_line.addChild(QTreeWidgetItem([mac])) for mac in history_dic[ip]]
            self.treeWidget_History.addTopLevelItem(ip_line)
            ip_line.setExpanded(len(history_dic[ip]) > 1)

    def toggleProtectionState(self):
        #cmd = "Powershell Start-Process -WindowStyle hidden 'arp.exe' -ArgumentList "
        #cmd += ("'-d %s' -Verb runAs" %get_default_gateway_ip() if is_gw_static() else "'-s %s %s' -Verb runAs" % (get_default_gateway_ip(), find_gw_mac()))
        #subprocess.Popen(cmd)
        set_gw_dynamic() if is_gw_static() else set_gw_static()
        QTimer.singleShot(1000, self.onTimer)
        QTimer.singleShot(2000, self.onTimer)
        QTimer.singleShot(3000, self.onTimer)
        QTimer.singleShot(5000, self.onTimer)
        return


    def onTimer(self):
        if self.table == get_arp_table():
            return
        # Something new found in ARP Table
        self.table = get_arp_table()
        self.updateTableWidget(self.table)
        self.history = self.update_history_dic(self.table, self.history)
        self.updateHistoryWidget(self.history)
        # refresh BUTTON
        if is_gw_static():
            self.pushButton_Protect.setText('Protected. Click to remove statiс record')
            self.pushButton_Protect.setIcon(QtGui.QIcon(icon_protected))
            self.groupBox_gw.setStyleSheet('color: rgb(0, 100, 0);')
        else:
            self.pushButton_Protect.setText('Unprotected. Click to protect!')
            self.pushButton_Protect.setIcon(QtGui.QIcon(icon_alert))
            self.groupBox_gw.setStyleSheet('color: rgb(175, 39, 29);')


    def show(self):
        screen_center = lambda x: QApplication.desktop().screen().rect().center()- x.rect().center()
        self.move(screen_center(self))
        self.activateWindow()
        super(BarpMainWindow, self).show()

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def localWndProc(self, hWnd, msg, wParam, lParam):
        if msg == win32con.WM_POWERBROADCAST and wParam == win32con.PBT_APMRESUMESUSPEND:
            if QSettings(company_name, product_name).value(settings_auto_protect, type=bool) and not is_gw_static:
                QTimer.singleShot(5000, set_gw_static)
        return win32gui.CallWindowProc(self.oldWndProc, hWnd, msg, wParam, lParam)


if __name__ == '__main__':
    app = BarpApp(sys.argv)
    app.showTrayMenu()
    if not QSettings(company_name, product_name).value(settings_start_minimized, type=bool):
        app.showSettings()
    sys.exit(app.exec_())
