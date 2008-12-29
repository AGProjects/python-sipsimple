class Proxy(object):

    def __init__(self, obj):
        self.__dict__['_obj'] = obj

    def __getattr__(self, item):
        if item == '_obj':
            return self.__dict__.get('_obj')
        return self._obj.__getattr__(item)

    def __setattr__(self, item, value):
        assert item != '_obj'
        return self._obj.__setattr__(item, value)

    def __delattr__(self, item):
        return self._obj.__delattr__(item)


class wrapdict(Proxy):
    """
    >>> "%(code)s %(reason)s" % wrapdict({'code': 200, 'comment': 'OK'})
    "200 'reason' n/a"
    """

    def __getitem__(self, item):
        try:
            return self._obj.__getitem__(item)
        except KeyError:
            return '%r n/a' % item
