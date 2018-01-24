import sys
import os
import subprocess
import re
import ctypes
import win32gui
import win32con
import win32event
import pywintypes
import win32api
import winerror
import inspect

from PyQt5 import QtGui, QtCore, uic
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMainWindow, QTableWidgetItem, QTreeWidgetItem
from PyQt5.QtCore import QSettings, QTimer


PRODUCT_NAME = 'ARP Defender'
COMPANY_NAME = 'BinaryPlant'
FULL_PRODUCT_NAME = 'BinaryPlant ARP Defender'
HKEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
SETTINGS_START_MINIMIZED = 'settings_start_minimized'
SETTINGS_AUTO_PROTECT = 'settings_auto_protect'
TIMER_IN_SEC = 60

APP_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.realpath(os.path.abspath(os.path.split(inspect.getfile(inspect.currentframe()))[0]))
APP_LOGO_ICON = os.path.join(APP_DIR, 'res', 'logo.ico')
ICON_PROTECTED = os.path.join(APP_DIR, 'res', 'protected.ico')
ICON_ALERT = os.path.join(APP_DIR, 'res', 'alert.png')
UI_FILENAME = os.path.join(APP_DIR, 'barp-win.ui')


def get_arp_table():  # INFO: get_arp_table() = list of records like [boolStaticFlag, 'IP', 'MAC']
    res = subprocess.check_output('arp -a', shell=True).decode("utf-8")
    str_regex_ip = '(?:[0-9]{1,3}\.){3}[0-9]{1,3}|$'
    str_regex_ip_multicast = '2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}'
    str_regex_mac_addr = '([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})|$'
    str_regex_static_flag = 'static'
    find_ip_addr = lambda x: re.findall(str_regex_ip, x)[0]
    find_mac_addr = lambda x: re.findall(str_regex_mac_addr, x)[0]
    find_flag_ip_multicast = lambda x: bool(re.search(str_regex_ip_multicast, x))
    find_flag_static = lambda x: bool(re.search(str_regex_static_flag, x))
    parse_output_line = lambda x: [find_flag_static(x), find_ip_addr(x), find_mac_addr(x), find_flag_ip_multicast(x)]
    table = [parse_output_line(x) for x in res.splitlines()]
    filter_good = lambda x: x[1] and x[2] and not x[3]
    table = list(filter(filter_good, table))
    # remove useless column 'multicast' and skip broadcast mac-record
    table = [[rec[0], rec[1], rec[2]] for rec in table if rec[2].lower().replace(':', '-') != 'ff-ff-ff-ff-ff-ff']
    return table  # [boolStaticFlag, IP, MAC]
    # example:[  [False, '192.168.76.254', '00-50-56-e2-8c-19', False], .....]


def get_default_gateway_ip():
    res = subprocess.check_output('ipconfig', shell=True, universal_newlines=True)  # alter: "netsh interface ipv4 show config"
    str_regex_default_gw = 'Default Gateway[^\d]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|$'
    find_default_gws = lambda x: re.findall(str_regex_default_gw, x)[0]
    gateway_entries = map(find_default_gws, res.splitlines())
    gateway = next(filter(None, gateway_entries), '')
    return gateway


def get_default_gateway_interface_name():
    try:
        res = subprocess.check_output('ipconfig', shell=True).decode('cp866')
        str_regex_interface_name = ' adapter ([^:]*):|$'
        str_regex_default_gw = 'Default Gateway[^\d]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|$'
        last_interface_name = ''
        for line in res.splitlines():
            if re.findall(str_regex_interface_name, line)[0]:
                last_interface_name = re.findall(str_regex_interface_name, line)[0]
            if re.findall(str_regex_default_gw, line)[0]:
                # print(last_interface_name)
                return last_interface_name
    except:
        pass
    return ''  # if error


def find_ip_record(ip, table):
    this_ip = lambda x: x[1] == ip
    record = filter(this_ip, table)
    default_record = [False, ip, '']
    return next(record, default_record)

find_gw_mac = lambda: find_ip_record(get_default_gateway_ip(), get_arp_table())[2]
is_gw_static = lambda: find_ip_record(get_default_gateway_ip(), get_arp_table())[0]


def add_static_record(ip, mac, if_name):
    if not ip or not mac or not if_name:
        return
    # 1) Command:
    #     arp.exe -s IP MAC with IF_ADDR  doesn't work (I have no idea why)
    #     so, we have to use netsh.exe and must find network interface name (i.e. in 'ipconfig' output)
    # 2) Rights elevation
    #     working with powershell for elevation fails with encoding problems when IF_NAME non English
    #     ("Powershell Start-Process -WindowStyle hidden 'netsh.exe' -ArgumentList 'interface ipv4 add neighbors \"%s\" \"%s\" \"%s\" store=active' -Verb runAs" % (if_name, ip, mac))
    #     so, we have to use elevation by ShellExecuteW:
    #     ShellExecuteW(None, "runas", simple_exe, simple_params, None, 1)
    exe_file = "netsh.exe"
    exe_params = "interface ipv4 add neighbors \"%s\" \"%s\" \"%s\" store=active" % (if_name, ip, mac)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_file, exe_params, None, 1)

set_gw_static = lambda: add_static_record(get_default_gateway_ip(), find_gw_mac(), get_default_gateway_interface_name())


def remove_static_record(ip):
    cmd = "Powershell Start-Process -WindowStyle hidden 'arp.exe' -ArgumentList '-d %s' -Verb runAs" % ip
    subprocess.Popen(cmd)

set_gw_dynamic = lambda: remove_static_record(get_default_gateway_ip())


########################################################################################################################
class BarpApp(QApplication):

    def __init__(self, agrv):
        super(BarpApp, self).__init__(agrv)
        self.tray = QSystemTrayIcon()
        self.tray.activated.connect(self.tray_clicks)
        self.menu = QMenu('Menu')
        self.menu.addAction('S&how Main Window', self.show_settings)
        self.menu.addSeparator()
        self.menu.addAction('E&xit', self.quit)
        self.tray.setIcon(QtGui.QIcon(APP_LOGO_ICON))
        self.tray.setToolTip(PRODUCT_NAME)
        self.tray.setContextMenu(self.menu)
        self.settings_window = BarpMainWindow()
        self.setWindowIcon(QtGui.QIcon(APP_LOGO_ICON))
        self.myappid = '.'.join([COMPANY_NAME, PRODUCT_NAME])
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(self.myappid)  # to have own taskbar window

    def quit(self):
        self.tray.hide()
        super(BarpApp, self).quit()

    def tray_clicks(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_settings()

    def show_tray_menu(self):
        self.tray.show()

    def show_settings(self):
        self.settings_window.show()


########################################################################################################################
class BarpMainWindow(QMainWindow):

    def __init__(self):
        super(BarpMainWindow, self).__init__()
        self.ui_file = UI_FILENAME
        uic.loadUi(self.ui_file, self)
        timer = QTimer(self)
        timer.timeout.connect(self.on_timer)
        timer.start(1000 * TIMER_IN_SEC)
        self.lineEdit_Timer.setText(str(TIMER_IN_SEC))
        self.table = []
        self.update_table_widget(self.table)
        self.button_clear_history()
        # connect buttons
        self.pushButton_Protect.clicked.connect(self.toggle_protection_state)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reload_checkboxes)
        self.pushButton_Exit.clicked.connect(QtCore.QCoreApplication.instance().quit)
        self.pushButton_Update.clicked.connect(self.on_timer)
        self.pushButton_ClearHistory.clicked.connect(self.button_clear_history)
        # first init checkboxes from setting
        self.reload_checkboxes()
        self.on_timer()  # fist init table and interface widgets
        # hook WndProc for receiving wake-up event
        self.oldWndProc = win32gui.SetWindowLong(self.winId(), win32con.GWL_WNDPROC, self.localWndProc)

    def accept(self):
        QSettings(COMPANY_NAME, PRODUCT_NAME).setValue(SETTINGS_START_MINIMIZED, self.checkBox_StartMinimized.isChecked())
        QSettings(COMPANY_NAME, PRODUCT_NAME).setValue(SETTINGS_AUTO_PROTECT, self.checkBox_AutoProtect.isChecked())
        if self.checkBox_AutoRun.isChecked():
            QSettings(HKEY, QSettings.NativeFormat).setValue(PRODUCT_NAME, (sys.argv[0]))
        else:
            QSettings(HKEY, QSettings.NativeFormat).remove(PRODUCT_NAME)
        self.hide()

    def reload_checkboxes(self):
        self.checkBox_StartMinimized.setChecked(QSettings(COMPANY_NAME, PRODUCT_NAME).value(SETTINGS_START_MINIMIZED, type=bool))
        self.checkBox_AutoProtect.setChecked(QSettings(COMPANY_NAME, PRODUCT_NAME).value(SETTINGS_AUTO_PROTECT, type=bool))
        self.checkBox_AutoRun.setChecked(QSettings(HKEY, QSettings.NativeFormat).contains(PRODUCT_NAME))
        self.hide()

    def update_history_dic(self, table, prev_history):
        history = prev_history.copy()  # to make function "clean"
        for flag_static, ip, mac in table:
            if ip not in history.keys():
                # print('New IP')
                history[ip] = list([mac])
            if mac not in history[ip]:
                # print('New MAC')
                history[ip].append(mac)
        return history

    def button_clear_history(self):
        self.history = self.update_history_dic(self.table, {})
        self.update_history_widget(self.history)

    def update_table_widget(self, arp_table):
        wt = self.tableWidget_Table
        wt.clear()
        wt.setRowCount(0)
        wt.setHorizontalHeaderLabels(['Type', 'IP', 'MAC'])
        formatted_cell = lambda cell: cell.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter) or cell
        for flag_static, ip, mac in arp_table:
            row_count = wt.rowCount()
            wt.insertRow(row_count)
            wt.setItem(row_count, 0, formatted_cell(QTableWidgetItem(('s' if flag_static else ''))))
            wt.setItem(row_count, 1, formatted_cell(QTableWidgetItem(ip)))
            wt.setItem(row_count, 2, formatted_cell(QTableWidgetItem(mac)))
        wt.resizeColumnsToContents()
        wt.horizontalHeader().setStretchLastSection(True)

    def update_history_widget(self, history_dic):
        self.treeWidget_History.clear()
        for ip in history_dic:
            ip_line = QTreeWidgetItem([ip])
            [ip_line.addChild(QTreeWidgetItem([mac])) for mac in history_dic[ip]]
            self.treeWidget_History.addTopLevelItem(ip_line)
            ip_line.setExpanded(len(history_dic[ip]) > 1)

    def toggle_protection_state(self):
        set_gw_dynamic() if is_gw_static() else set_gw_static()
        QTimer.singleShot(1000, self.on_timer)  # to boost interface
        QTimer.singleShot(2000, self.on_timer)  # to boost interface
        QTimer.singleShot(3000, self.on_timer)  # to boost interface
        QTimer.singleShot(5000, self.on_timer)  # to boost interface
        return

    def on_timer(self):
        if self.table == get_arp_table():
            return
        # Something new found in ARP Table (or first start)
        self.table = get_arp_table()
        self.label_gwIp.setText(get_default_gateway_ip())
        self.label_gwIp.setToolTip(get_default_gateway_interface_name())
        self.label_gwMac.setText(find_gw_mac())
        self.label_gwMac.setToolTip(get_default_gateway_interface_name())
        if find_gw_mac():
            self.pushButton_Protect.setEnabled(True)
            if is_gw_static():
                self.pushButton_Protect.setText('Protected. Click to remove statiс record')
                self.pushButton_Protect.setIcon(QtGui.QIcon(ICON_PROTECTED))
                self.groupBox_gw.setStyleSheet('color: rgb(0, 100, 0);')
            else:
                self.pushButton_Protect.setText('Unprotected. Click to protect!')
                self.pushButton_Protect.setIcon(QtGui.QIcon(ICON_ALERT))
                self.groupBox_gw.setStyleSheet('color: rgb(175, 39, 29);')
                if QSettings(COMPANY_NAME, PRODUCT_NAME).value(SETTINGS_AUTO_PROTECT, type=bool):
                    set_gw_static()
                    QTimer.singleShot(5000, self.on_timer)

        else:  # if gateway MAC not found
            self.pushButton_Protect.setEnabled(False)
            self.pushButton_Protect.setText('Can not find gateway MAC address')
            self.pushButton_Protect.setIcon(QtGui.QIcon())  # remove icon
        self.update_table_widget(self.table)
        self.history = self.update_history_dic(self.table, self.history)
        self.update_history_widget(self.history)

    def show(self):
        screen_center = lambda x: QApplication.desktop().screen().rect().center() - x.rect().center()
        self.move(screen_center(self))
        self.activateWindow()
        super(BarpMainWindow, self).show()

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def localWndProc(self, hWnd, msg, wParam, lParam):  # win32 API
        if msg == win32con.WM_POWERBROADCAST and wParam == win32con.PBT_APMRESUMESUSPEND:
            if QSettings(COMPANY_NAME, PRODUCT_NAME).value(SETTINGS_AUTO_PROTECT, type=bool) and not is_gw_static():
                QTimer.singleShot(5000, set_gw_static)
        return win32gui.CallWindowProc(self.oldWndProc, hWnd, msg, wParam, lParam)


if __name__ == '__main__':
    # only for Windows - do not allow second instance
    hMutex = win32event.CreateMutex(None, pywintypes.TRUE, PRODUCT_NAME)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        sys.exit()
    app = BarpApp(sys.argv)
    app.show_tray_menu()
    if not QSettings(COMPANY_NAME, PRODUCT_NAME).value(SETTINGS_START_MINIMIZED, type=bool):
        app.show_settings()
    if QSettings(COMPANY_NAME, PRODUCT_NAME).value(SETTINGS_AUTO_PROTECT, type=bool) and not is_gw_static():
        QTimer.singleShot(5000, set_gw_static)
        QTimer.singleShot(8000, app.settings_window.on_timer)

    sys.exit(app.exec_())
