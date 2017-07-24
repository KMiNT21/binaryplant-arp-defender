from cx_Freeze import setup, Executable
base = None
buildOptions = dict(packages = [], excludes = [])
import sys
base = 'Win32GUI' if sys.platform=='win32' else None
#shortcut_table = [
#    ("DesktopShortcut",        # Shortcut
#     "DesktopFolder",          # Directory_
#     "DTI Playlist",           # Name
#     "TARGETDIR",              # Component_
#     "[TARGETDIR]barpdef.exe",# Target
#     None,                     # Arguments
#     None,                     # Description
#     None,                     # Hotkey
#     None,                     # Icon
#     None,                     # IconIndex
#     None,                     # ShowCmd
#     'TARGETDIR'               # WkDir
#     )
#    ]
#msi_data = {"Shortcut": shortcut_table}
#bdist_msi_options = {'data': msi_data}

executables = [
    Executable('barpdef.py', shortcutName="BinaryPlant ARP Defender", shortcutDir="DesktopFolder", icon="res\\logo.ico", base=base)
]

buildOptions = dict(
    packages = [],
    excludes = [],
#    includes = ["atexit"],
    #include_files = ["barp-win.ui", "LICENSE", "README.md", "res\\protected.ico", "res\\logo.ico", "res\\clear.ico", "res\\refresh.ico", "res\\alert.png"]
    include_files = ["barp-win.ui", "LICENSE", "README.md", "res"]
)
setup(
    name = "BinaryPlant ARP Defender",
    options = dict(build_exe = buildOptions),
    version = "1.0.0",
    description = 'Visit http://binaryplant.com',
    executables = executables
)

