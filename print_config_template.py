#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
this_path = os.path.split(sys.modules['__main__'].__file__)[0]
sys.path.insert(0, this_path + '/lib') 

import multiapt.defaultconfig

all = multiapt.defaultconfig.__dict__.keys()
all.sort()

print '# -*- coding: utf-8 -*-'
print '#'
print '# All available configuration parameters, and their default values.'
print '#'

for k in all:
	if k[:1] == '_': continue
	print '# %s = %s' % (k, repr(multiapt.defaultconfig.__dict__[k]))

