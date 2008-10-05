from pypjua.applications.test import XMLApplicationTest
from pypjua.applications.pidf import PIDF


class PIDFTest(XMLApplicationTest):
    _test_module = 'pidf'


if __name__ == '__main__':
    PIDFTest.execute()
