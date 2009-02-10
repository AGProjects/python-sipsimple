from sipsimple.applications.test import XMLApplicationTest
from sipsimple.applications.policy import *
from sipsimple.applications.presrules import *


class PresRulesTest(XMLApplicationTest):
    _test_module = 'presrules'

if __name__ == '__main__':
    PresRulesTest.execute()
