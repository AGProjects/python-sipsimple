import sys
import traceback

__all__ = ['HookedList',
           'TypedList']

class HookedList(list):
    """List that allows to setup hooks on element insertion/removal"""

    def _before_insert(self, value):
        """Called for every value that is about to be inserted into the list.
        The returned value will be inserted into the list"""
        return value

    def _before_remove(self, value):
        """Called for every value that is about to be removed from the list.

        Must not throw!
        """

    def __init__(self, iterable = []):
        self[0:0] = iterable

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, list.__repr__(self))

    def __setitem__(self, key, value_or_lst):
        if isinstance(key, slice):
            self._insert_list(value_or_lst, list.__setitem__, [self, key])
        else:
            value = self._before_insert(value_or_lst)
            return list.__setitem__(self, key, value)

    def __setslice__(self, i, j, sequence):
        self._insert_list(sequence, list.__setslice__, [self, i, j])

    def _insert_list(self, sequence, func, args):
        values = []
        count = 0
        try:
            for value in sequence:
                values.append(self._before_insert(value))
                count += 1
            args.append(values)
            return func(*args)
        except:
            exc = sys.exc_info()
            for value in sequence[:count]:
                try:
                    self._before_remove(value)
                except:
                    traceback.print_exc()
            raise exc[0], exc[1], exc[2]

    def __delitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.start, key.stop, key.step
            if start is None:
                start = 0
            if stop is None:
                stop = len(self)
            if step is None:
                step = 1
            for k in xrange(start, stop, step):
                try:
                    self._before_remove(self[k])
                except:
                    traceback.print_exc()
        else:
            try:
                self._before_remove(self[key])
            except:
                pass
        return list.__delitem__(self, key)

    def __delslice__(self, i, j):
        for k in xrange(i, j):
            try:
                self._before_remove(self[k])
            except:
                traceback.print_exc()
        return list.__delslice__(self, i, j)

    def append(self, item):
        l = len(self)
        self[l:l] = [item]

    def extend(self, lst):
        l = len(self)
        self[l:l] = lst

    def insert(self, i, x):
        self[i:i] = [x]

    def pop(self, i = -1):
        x = self[i];
        del self[i];
        return x

    def remove(self, x):
        del self[self.index(x)]


class TypedList(HookedList):

    _items_types_ = tuple()

    def _before_insert(self, value):
        if not isinstance(value, self._items_types_):
            raise TypeError('value must be %s' % self._format_types_str())
        return value

    def _format_types_str(self):
        return ','.join([x.__name__ for x in self._items_types_])


def _test():
    """

    >>> h = NoisyList([1,2,3])
    inserting 1
    inserting 2
    inserting 3

    >>> h[1] = 'hello'
    inserting 'hello'

    >>> h[1:2] = [4,5]
    inserting 4
    inserting 5

    >>> h[1:4:2] = ['x', 'y']
    inserting 'x'
    inserting 'y'
    
    >>> h.append('append()')
    inserting 'append()'

    >>> h.extend(['extend()'])
    inserting 'extend()'

    >>> h.insert(3, 'insert()')
    inserting 'insert()'

    >>> h
    NoisyList([1, 'x', 5, 'insert()', 'y', 'append()', 'extend()'])

    >>> del h[1]
    removing 'x'

    >>> del h[1:2]
    removing 5

    >>> del h[1:4:2]
    removing 'insert()'
    removing 'append()'

    >>> h.remove(1)
    removing 1

    >>> assert 'extend()' == h.pop()
    removing 'extend()'

    >>> h = NonzeroList([3])
    >>> h[1:1] = [40, 50, 0, 60]
    Traceback (most recent call last):
     ...
    AssertionError
    >>> h.log
    [3, 40, 50, [40], [50]]


    >>> h = StringList()
    >>> h.append('a')
    >>> h.append(5)
    Traceback (most recent call last):
     ...
    TypeError: value must be str
    >>> h
    StringList(['a'])
    >>> h.extend(['b', 'c', 6])
    Traceback (most recent call last):
     ...
    TypeError: value must be str
    >>> h
    StringList(['a'])

    """

    class NoisyList(HookedList):
        def _before_insert(self, value):
            print 'inserting', `value`
            return value

        def _before_remove(self, value):
            print 'removing', `value`

    class NonzeroList(HookedList):
        log = []

        def _before_insert(self, value):
            assert value != 0
            self.log.append(value)
            return value

        def _before_remove(self, value):
            self.log.append([value])

    class StringList(TypedList):
        _items_types_ = (str, )

    import doctest
    doctest.testmod(extraglobs = locals())


if __name__=='__main__':
    _test()

