from sipsimple.applications.test import XMLApplicationTest


class CommonPolicyTest(XMLApplicationTest):
    _test_module = 'policy'

if __name__ == '__main__':
    CommonPolicyTest.execute()
