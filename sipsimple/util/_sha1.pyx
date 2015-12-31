# Copyright (C) 2015 AG Projects. See LICENSE for details.
#

__all__ = ['sha1']


from libc.stddef cimport size_t
from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.string cimport memcpy
from cpython.buffer cimport PyObject_CheckBuffer, PyObject_GetBuffer, PyBuffer_Release
from cpython.string cimport PyString_FromStringAndSize, PyString_AS_STRING
from cpython.unicode cimport PyUnicode_Check


cdef extern from "_sha1.h":
    enum:
        SHA1_BLOCK_SIZE  = 64
        SHA1_DIGEST_SIZE = 20

    ctypedef struct sha1_context:
        uint32_t state[SHA1_DIGEST_SIZE/4]  # state variables
        uint64_t count                      # 64-bit block count
        uint8_t  block[SHA1_BLOCK_SIZE]     # data block buffer
        uint32_t index                      # index into buffer

    cdef void sha1_init(sha1_context *context)
    cdef void sha1_update(sha1_context *context, const uint8_t *data, size_t length)
    cdef void sha1_digest(sha1_context *context, uint8_t *digest)


cdef class sha1(object):
    cdef sha1_context context

    def __cinit__(self, *args, **kw):
        sha1_init(&self.context)

    def __init__(self, data=''):
        self.update(data)

    property block_size:
        def __get__(self):
            return SHA1_BLOCK_SIZE

    property digest_size:
        def __get__(self):
            return SHA1_DIGEST_SIZE

    def __reduce__(self):
        state_variables = [self.context.state[i] for i in range(sizeof(self.context.state)/4)]
        block = PyString_FromStringAndSize(<char*>self.context.block, self.context.index)
        return self.__class__, (), (state_variables, self.context.count, block)

    def __setstate__(self, state):
        state_variables, count, block = state
        for i, number in enumerate(state_variables):
            self.context.state[i] = number
        self.context.count = count
        self.context.index = len(block)
        memcpy(self.context.block, PyString_AS_STRING(block), self.context.index)

    def copy(self):
        cdef sha1 instance = self.__class__()
        instance.context = self.context
        return instance

    def update(self, data):
        cdef Py_buffer view

        if PyObject_CheckBuffer(data):
            PyObject_GetBuffer(data, &view, 0)
            if view.ndim > 1:
                raise BufferError('Buffer must be single dimension')
            sha1_update(&self.context, <uint8_t*>view.buf, view.len)
            PyBuffer_Release(&view)
        elif PyUnicode_Check(data):
            raise TypeError('Unicode-objects must be encoded before hashing')
        else:
            raise TypeError('object supporting the buffer API required')

    def digest(self):
        cdef sha1_context context_copy
        cdef uint8_t digest[SHA1_DIGEST_SIZE]

        context_copy = self.context
        sha1_digest(&context_copy, digest)
        return PyString_FromStringAndSize(<char*>digest, SHA1_DIGEST_SIZE)

    def hexdigest(self):
        return self.digest().encode('hex')

