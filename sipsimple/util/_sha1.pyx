
import codecs

from libc.stdint cimport uint8_t
from libc.string cimport memcpy
from cpython.buffer cimport PyObject_CheckBuffer, PyObject_GetBuffer, PyBuffer_Release
from cpython.string cimport PyString_FromStringAndSize, PyString_AS_STRING
from cpython.unicode cimport PyUnicode_Check


cdef extern from "sha1_impl.h":
    ctypedef struct SHA1_CTX:
        pass

    enum:
        SHA1_BLOCK_SIZE
        SHA1_DIGEST_SIZE

    cdef void SHA1_Init(SHA1_CTX* context)
    cdef void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len)
    cdef void SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE])


cdef class sha1(object):
    cdef SHA1_CTX context

    def __cinit__(self, *args, **kw):
        SHA1_Init(&self.context)

    def __init__(self, data=''):
        self.update(data)

    property block_size:
        def __get__(self):
            return SHA1_BLOCK_SIZE

    property digest_size:
        def __get__(self):
            return SHA1_DIGEST_SIZE

    def __reduce__(self):
        return (self.__class__, (), PyString_FromStringAndSize(<char*>&self.context, sizeof(SHA1_CTX)))

    def __setstate__(self, state):
        if len(state) != sizeof(SHA1_CTX):
            raise ValueError("incompatible state")
        memcpy(&self.context, PyString_AS_STRING(state), sizeof(SHA1_CTX))

    def copy(self):
        cdef sha1 instance = self.__class__()
        memcpy(&instance.context, &self.context, sizeof(SHA1_CTX))
        return instance

    def update(self, data):
        cdef Py_buffer view

        if PyObject_CheckBuffer(data):
            PyObject_GetBuffer(data, &view, 0)
            if view.ndim > 1:
                raise BufferError('Buffer must be single dimension')
            SHA1_Update(&self.context, <uint8_t*>view.buf, view.len)
            PyBuffer_Release(&view)
        elif PyUnicode_Check(data):
            raise TypeError('Unicode-objects must be encoded before hashing')
        else:
            raise TypeError('object supporting the buffer API required')

    def digest(self):
        cdef SHA1_CTX context_clone
        cdef uint8_t digest[SHA1_DIGEST_SIZE]

        memcpy(&context_clone, &self.context, sizeof(SHA1_CTX))
        SHA1_Final(&context_clone, digest)
        return PyString_FromStringAndSize(<char*>digest, SHA1_DIGEST_SIZE)

    def hexdigest(self):
        return codecs.encode(self.digest(), 'hex')

