import os
import sys
me = os.path.basename(sys.modules['__main__'].__file__)
m = __import__('pypjua.clients.' + me, fromlist=['main'])
m.main()
