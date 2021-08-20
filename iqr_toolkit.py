#!/usr/bin/env python3
#
# ISARA Radiate Quantum-safe Toolkit module
#
# https://github.com/isaracorp/Toolkit-Python
#
# Python 3 bindings for the ISARA toolkit.
#
# See the LICENSE file for details:
#
# Copyright (C) 2020-2021, ISARA Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  https://github.com/isaracorp/Toolkit-Python/blob/develop/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes
import sys


if sys.platform == 'darwin':
    _iqr_shared_library_name = 'libiqr_toolkit.dylib'
elif sys.platform == 'linux':
    _iqr_shared_library_name = 'libiqr_toolkit.so'
elif sys.platform == 'windows':  # TODO: Check that.
    _iqr_shared_library_name = 'libiqr_toolkit.dll'

ctypes.cdll.LoadLibrary(_iqr_shared_library_name)
_iqr_toolkit = ctypes.CDLL(_iqr_shared_library_name)

if _iqr_toolkit.iqr_VersionCheck(3, 0) != 0:
    raise RuntimeWarning('iqr_toolkit was expecting version 3.0.')


# ----------------------------------------------------------------------------------------------------------------------------------
# ChaCha20 symmetric cipher: iqr_chacha20.h
# ----------------------------------------------------------------------------------------------------------------------------------

class ChaCha20:
    ''' ChaCha20 symmetric cipher.
    '''

    IQR_CHACHA20_KEY_SIZE = 32  # ChaCha20 keys must be exactly 32 bytes.
    IQR_CHACHA20_NONCE_SIZE = 12  # The nonce for ChaCha20 must be exactly 12 bytes.

    _iqr_toolkit.iqr_ChaCha20Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_size_t,  # key
                                                 ctypes.c_char_p, ctypes.c_size_t,  # nonce
                                                 ctypes.c_uint32,  # counter
                                                 ctypes.c_char_p, ctypes.c_size_t,  # plaintext
                                                 ctypes.c_char_p, ctypes.c_size_t]  # ciphertext
    _iqr_toolkit.iqr_ChaCha20Encrypt.restype = ctypes.c_uint64

    @staticmethod
    def Encrypt(key, nonce, counter, plaintext):
        ''' Encrypt the given plaintext using the key, nonce, and counter.

        Returns ciphertext.
        '''
        cipher = ctypes.create_string_buffer(len(plaintext))

        retval = _iqr_toolkit.iqr_ChaCha20Encrypt(key, len(key),
                                                  nonce, len(nonce),
                                                  counter,
                                                  plaintext, len(plaintext),
                                                  cipher, ctypes.sizeof(cipher))

        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ChaCha20Encrypt() failed: {0}'.format(Retval.StrError(retval)))

        return cipher.raw

    @staticmethod
    def Decrypt(key, nonce, counter, ciphertext):
        ''' Decrypt the given ciphertext using the key, nonce, and counter.

        Returns plaintext.
        '''
        return iqr_ChaCha20.Encrypt(key, nonce, counter, ciphertext)


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit return values: iqr_retval.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Retval:
    ''' ISARA toolkit standard return values.

    For signature schemes, IQR_EINVDATA indicates a corrupted signature
    buffer.

    When validating a signature, IQR_EINVSIGNATURE indicates that the signature,
    public key, and message don't match. This could mean that the message has
    been modified, or that the signature has been tampered with, possibly by an
    adversary.
    '''

    IQR_OK = 0  # Success, function completed successfully.

    # General error values.
    IQR_ENULLPTR = -1001  # A NULL pointer was passed in where a valid pointer was expected.
    IQR_ENOMEM = -1002  # Memory allocation failed.
    IQR_ENOTINIT = -1003  # The specified structure is not initialized.
    IQR_EINVBUFSIZE = -1004  # The provided buffer has an invalid size.
    IQR_EBADVALUE = -1005  # The parameter value is not valid.
    IQR_EOUTOFRANGE = -1006  # The parameter value is out of range.
    IQR_EVALUENOTSUPP = -1007  # The parameter value is valid but not supported.
    IQR_EINVOBJECT = -1008  # The object is invalid.
    IQR_EINVCALLBACKS = -1009  # The provided callback pointers are invalid.
    IQR_ENOTREGISTERED = -1010  # Callbacks to an algorithm were not registered prior to use.
    IQR_EINVDATA = -1011  # The provided data is invalid.
    IQR_EINVPTR = -1012  # Output pointer parameters must be initialized to NULL prior to function call.
    IQR_EPTROVERLAP = -1013  # Input and output pointers must not be overlapping buffers.
    IQR_ELIBRARYMISMATCH = -1014  # Library version does not match header version.
    IQR_EINVSTRATEGY = -1015  # The chosen tree strategy cannot be used for this function.
    IQR_EVERSIONMISMATCH = -1016  # The object version does not match the library version.

    # Algorithm error values.
    IQR_EINVALGOSTATE = -2001  # The algorithm state is invalid.
    IQR_EINVHASHALGO = -2002  # The provided hashing algorithm is not valid for this key type.

    # Key error values.
    IQR_EINVPUBLICKEY = -3001  # The public key is invalid.
    IQR_EINVPRIVATEKEY = -3002  # The private key is invalid.
    IQR_EINVSYMKEY = -3003  # The symmetric key is invalid.
    IQR_EKEYPAIRMISMATCH = -3004  # The public key is not derived from the private key.
    IQR_EINVSIGNATURE = -3006  # The signature of the message is invalid.
    IQR_ESTATEDEPLETED = -3007  # The state cannot be used to create more signatures.

    # Random Number Generator error values.
    IQR_ENOTSEEDED = -4001  # The Random Number Generator has not been seeded.
    IQR_ERESEED = -4002  # The Random Number Generator must be reseeded.

    # Crypto error values.
    IQR_EDECRYPTIONFAILED = -5001  # The decryption algorithm failed to decrypt the ciphertext.

    _iqr_toolkit.iqr_StrError.argtypes = [ctypes.c_size_t]
    _iqr_toolkit.iqr_StrError.restype = ctypes.c_char_p

    @staticmethod
    def StrError(error_value):
        ''' Return a string representation of the given iqr_retval value.
        '''
        return _iqr_toolkit.iqr_StrError(error_value).decode('utf-8')


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit return values: iqr_version.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Version:
    ''' ISARA toolkit version information.
    '''

    IQR_VERSION_MAJOR = 2  # Major version number.
    IQR_VERSION_MINOR = 1  # Minor version number.

    IQR_VERSION_STRING = "ISARA Radiate Quantum-Safe Library 3.0"

    _iqr_toolkit.iqr_VersionCheck.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    _iqr_toolkit.iqr_VersionCheck.restype = ctypes.c_int32

    _iqr_toolkit.iqr_VersionGetBuildTarget.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
    _iqr_toolkit.iqr_VersionGetBuildTarget.restype = ctypes.c_uint64

    _iqr_toolkit.iqr_VersionGetBuildHash.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
    _iqr_toolkit.iqr_VersionGetBuildHash.restype = ctypes.c_uint64

    @staticmethod
    def Check(major_version, minor_version):
        ''' Does the library's version match major_version.minor_version?
        '''
        return _iqr_toolkit.iqr_VersionCheck(major_version, minor_version)

    @staticmethod
    def GetBuildTarget():
        ''' Get the library build information.
        '''
        target = ctypes.c_char_p(0)  # NULL
        retval = _iqr_toolkit.iqr_VersionGetBuildTarget(ctypes.byref(target))

        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_VersionGetBuildTarget() failed: {0}'.format(Retval.StrError(retval)))

        return target.value.decode('utf-8')

    @staticmethod
    def GetBuildHash():
        ''' Get the library build hash.
        '''
        build = ctypes.c_char_p(0)  # NULL
        retval = _iqr_toolkit.iqr_VersionGetBuildHash(ctypes.byref(build))

        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_VersionGetBuildHash() failed: {0}'.format(Retval.StrError(retval)))

        return build.value.decode('utf-8')
