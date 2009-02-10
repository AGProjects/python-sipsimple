from sipsimple.applications.test import XMLApplicationTest
from sipsimple.applications.watcherinfo import NeedFullUpdateError, Watcher, WatcherList, WatcherInfo


class WatcherInfoTest(XMLApplicationTest):
    _test_module = 'watcherinfo'

if __name__ == '__main__':
    WatcherInfoTest.execute()
