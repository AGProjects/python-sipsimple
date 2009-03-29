from sipsimple.applications.test import XMLApplicationTest


class PIDFTest(XMLApplicationTest):
    _test_module = 'presdm'


if __name__ == '__main__':
    PIDFTest.execute()
