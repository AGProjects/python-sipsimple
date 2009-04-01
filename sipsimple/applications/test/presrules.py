# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from sipsimple.applications.test import XMLApplicationTest
from sipsimple.applications.presrules import PresRules


class PresRulesTest(XMLApplicationTest):
    _test_module = 'presrules'

if __name__ == '__main__':
    PresRulesTest.execute()
