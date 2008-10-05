from pypjua.applications.test import XMLApplicationTest
from pypjua.applications.policy import *
from pypjua.applications.presrules import *


class PresRulesTest(XMLApplicationTest):
    _test_module = 'presrules'

if __name__ == '__main__':
    PresRulesTest.execute()
