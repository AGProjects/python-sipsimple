import os
import sys

data_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[0]))), 'share', 'sipclient')

def get_path(filename):
    return os.path.realpath(os.path.join(data_directory, filename))
