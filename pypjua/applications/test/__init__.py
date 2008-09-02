import sys
import unittest
import doctest

class XMLApplicationTest(unittest.TestCase):
    @classmethod
    def suite(cls):
        suite = unittest.TestSuite()

        test_module = 'pypjua.applications.%s' % cls._test_module

        # prepare context
        globs = {}
        globs.update(globals())
        globs.update(sys.modules[test_module].__dict__)
        globs.update(sys.modules[cls.__module__].__dict__)
        
        # add doctest of the module
        suite.addTest(doctest.DocTestSuite(test_module, globs=globs))
        # and itself
        suite.addTest(unittest.makeSuite(cls))
        
        return suite

    @classmethod
    def execute(cls):
        # run the tests
        runner = unittest.TextTestRunner()
        runner.run(cls.suite())
