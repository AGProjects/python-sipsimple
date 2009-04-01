# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from sipsimple.applications.test import XMLApplicationTest


class PIDFTest(XMLApplicationTest):
    _test_module = 'presdm'


if __name__ == '__main__':
    PIDFTest.execute()
