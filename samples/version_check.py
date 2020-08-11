#! /usr/bin/env python3
# Toolkit-Python

import ctypes
ctypes.cdll.LoadLibrary('libiqr_toolkit.dylib')
toolkit = ctypes.CDLL('libiqr_toolkit.dylib')
if toolkit.iqr_VersionCheck(2, 1) == 0:
    print('Version 2.1 of the Toolkit!')
