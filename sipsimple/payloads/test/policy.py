# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from sipsimple.payloads.test import XMLApplicationTest


class CommonPolicyTest(XMLApplicationTest):
    _test_module = 'policy'

if __name__ == '__main__':
    CommonPolicyTest.execute()
