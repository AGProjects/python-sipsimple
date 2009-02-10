from sipsimple.applications.test import XMLApplicationTest
from sipsimple.applications.pidf import PIDF


class PIDFTest(XMLApplicationTest):
    _test_module = 'pidf'


if __name__ == '__main__':
    PIDFTest.execute()
