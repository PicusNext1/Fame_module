import hashlib
import numbers
import os
import time
import binascii
import array
import magic
import math


from fame.core.module import ProcessingModule, ModuleInitializationError

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

class PEScanner(ProcessingModule):
    name = 'PE file extract'
    description = 'PE file extract'

    config = [
        {
            'type': 'string',
            'description': 'PE file extract',
        }
    ]
    def initialize(self):
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, 'Missing dependency: pefile')

        return True
    
    def each_with_type(self, target, target_type):
        self.results = {}
        pe = pefile.PE(target)
        with open(target, 'rb') as f:
            file = f.read()
            self.results['filename'] = target
            self.results['Size'] = os.path.getsize(target)
            
            return True

        self.log("debug", 'no report found')
        return False
