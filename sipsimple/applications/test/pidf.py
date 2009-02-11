from sipsimple.applications.test import XMLApplicationTest
from sipsimple.applications.presence import PIDF


class PIDFTest(XMLApplicationTest):
    _test_module = 'presence.presdm'


if __name__ == '__main__':
    PIDFTest.execute()
