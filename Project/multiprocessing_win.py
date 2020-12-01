# copy from https://github.com/pyinstaller/pyinstaller/wiki/Recipe-Multiprocessing
# pyinstaller打包含有多进程模块multiprocessing的程序时，需要添加的额外代码

import os  
import sys  
import multiprocessing  
  

try:  
    
    if sys.platform.startswith('win'):  
        import multiprocessing.popen_spawn_win32 as forking  
    else:  
        import multiprocessing.popen_fork as forking  
except ImportError:  
    import multiprocessing.popen_fork as forking  
  
if sys.platform.startswith('win'):  
    
    class _Popen(forking.Popen):  
        def __init__(self, *args, **kw):  
            if hasattr(sys, 'frozen'):  
                
                
                os.putenv('_MEIPASS2', sys._MEIPASS)  
            try:  
                super(_Popen, self).__init__(*args, **kw)  
            finally:  
                if hasattr(sys, 'frozen'):  
                    
                    
                    
                    
                    if hasattr(os, 'unsetenv'):  
                        os.unsetenv('_MEIPASS2')  
                    else:  
                        os.putenv('_MEIPASS2', '')  
    
    forking.Popen = _Popen  