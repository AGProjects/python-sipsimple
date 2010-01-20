# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from sipsimple.payloads.test import XMLApplicationTest


class PresRulesTest(XMLApplicationTest):
    _test_module = 'presrules'

if __name__ == '__main__':
    PresRulesTest.execute()
