import os
import sys

from setupconfig import data_files_dir

application_dir = os.path.dirname(sys.argv[0])

if os.path.basename(application_dir) == 'bin' and data_files_dir is not None:
    data_files_dir = os.path.join(os.path.dirname(application_dir), data_files_dir)
else:
    data_files_dir = application_dir

def get_path(filename):
    return os.path.join(data_files_dir, filename)
