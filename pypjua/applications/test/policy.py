from pypjua.applications.test import XMLApplicationTest
from pypjua.applications.policy import *


class CommonPolicyTest(XMLApplicationTest):
    _test_module = 'policy'

if __name__ == '__main__':
    CommonPolicyTest.execute()
