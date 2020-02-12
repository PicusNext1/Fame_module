# -*- coding: utf-8 -*-
import hashlib
import numbers
import os
import time
import binascii
import array
import magic
import sys
import math


from fame.core.module import ProcessingModule, ModuleInitializationError

reload(sys)
sys.setdefaultencoding("utf8")

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

class PEScanner(ProcessingModule):
    name = '静态分析'
    description = 'PE file extract'

    
    def initialize(self):
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, 'Missing dependency: pefile')

        return True
    
    def each_with_type(self, target, target_type):
        self.results = {}
        pe = pefile.PE(target)
        ret = []
        ret2 = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                ret.append(imp.name)
        
            self.results['DIRECTORY_ENTRY_IMPORT'] = ret
            
            return True

        self.log("debug", 'no report found')
        return False
