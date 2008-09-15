import os

if os.name == 'posix':
    # for some reason relative path doesn't work here, e.g.
    # if I change it to 'share/pypjua', `setup.py install_data` command will
    # copy wav files into /usr/share/pypjua/, but `setup.py install` will not. why?
    data_files_dir = '/usr/share/pypjua'
else:
    data_files_dir = None
