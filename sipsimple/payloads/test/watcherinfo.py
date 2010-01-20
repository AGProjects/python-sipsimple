# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from sipsimple.payloads.test import XMLApplicationTest


class WatcherInfoTest(XMLApplicationTest):
    _test_module = 'watcherinfo'

if __name__ == '__main__':
    WatcherInfoTest.execute()
