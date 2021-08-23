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

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_ChaCha20Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_size_t,  # key
                                                 ctypes.c_void_p, ctypes.c_size_t,  # nonce
                                                 ctypes.c_uint32,  # counter
                                                 ctypes.c_void_p, ctypes.c_size_t,  # plaintext
                                                 ctypes.c_void_p, ctypes.c_size_t]  # ciphertext
    _iqr_toolkit.iqr_ChaCha20Encrypt.restype = ctypes.c_int64

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
        return ChaCha20.Encrypt(key, nonce, counter, ciphertext)


def test_chacha20():
    ''' Run a simple ChaCha20 test.
    '''
    # Absolutely do not ever create a key and nonce like this.
    chacha_key = b'#' * ChaCha20.IQR_CHACHA20_KEY_SIZE
    chacha_nonce = b'*' * ChaCha20.IQR_CHACHA20_NONCE_SIZE
    chacha_msg = b'ChaCha20 is working.'
    chacha_encrypted = ChaCha20.Encrypt(chacha_key, chacha_nonce, 1, chacha_msg)
    print('{0}'.format(ChaCha20.Decrypt(chacha_key, chacha_nonce, 1, chacha_encrypted)))


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit Context: iqr_context.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Context:
    ''' Toolkit Context object.
    '''

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_CreateContext.argtypes = [ctypes.POINTER(ctypes.c_void_p)]  # Context
    _iqr_toolkit.iqr_CreateContext.restype = ctypes.c_int64

    _iqr_toolkit.iqr_DestroyContext.argtypes = [ctypes.POINTER(ctypes.c_void_p)]  # Context
    _iqr_toolkit.iqr_DestroyContext.restype = ctypes.c_int64

    @staticmethod
    def Create():
        ''' Create and initialize a Context object.

        The caller must free the returned ctx using DestroyContext().
        '''
        ctx = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_CreateContext(ctypes.byref(ctx))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_CreateContext() failed: {0}'.format(Retval.StrError(retval)))

        return ctx

    @staticmethod
    def Destroy(ctx):
        ''' Clear and deallocate a Context object.
        '''
        retval = _iqr_toolkit.iqr_DestroyContext(ctypes.byref(ctx))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DestroyContext() failed: {0}'.format(Retval.StrError(retval)))


# ----------------------------------------------------------------------------------------------------------------------------------
# Classic McEliece KEM: iqr_classicmceliece.h
# ----------------------------------------------------------------------------------------------------------------------------------
class ClassicMcEliece:
    ''' Classic McEliece KEM.
    '''

    IQR_CLASSICMCELIECE_SHARED_KEY_SIZE = 32  # The size of the shared key produced by ClassicMcEliece in bytes.

    IQR_CLASSICMCELIECE_6 = _iqr_toolkit.IQR_CLASSICMCELIECE_6  # 6960119 variant (256 bit classical security).
    IQR_CLASSICMCELIECE_8 = _iqr_toolkit.IQR_CLASSICMCELIECE_8  # 8192128 variant (256 bit classical security).

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_ClassicMcElieceCreateParams.argtypes = [ctypes.c_void_p,  # Context
                                                             ctypes.c_void_p,  # RNG
                                                             ctypes.POINTER(ctypes.c_void_p)]  # params
    _iqr_toolkit.iqr_ClassicMcElieceCreateParams.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceDestroyParams.argtypes = [ctypes.POINTER(ctypes.c_void_p)]  # params
    _iqr_toolkit.iqr_ClassicMcElieceDestroyParams.restype = ctypes.c_int64

    _iqr_toolkit.iqr_ClassicMcElieceGetPublicKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_ClassicMcElieceGetPublicKeySize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceGetPrivateKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_ClassicMcElieceGetPrivateKeySize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceGetCiphertextSize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_ClassicMcElieceGetCiphertextSize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceGetSharedKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_ClassicMcElieceGetSharedKeySize.restype = ctypes.c_int64

    _iqr_toolkit.iqr_ClassicMcElieceCreateKeyPair.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                              ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_ClassicMcElieceCreateKeyPair.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceDestroyPublicKey.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_ClassicMcElieceDestroyPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceDestroyPrivateKey.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_ClassicMcElieceDestroyPrivateKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceExportPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_ClassicMcElieceExportPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceExportPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_ClassicMcElieceExportPrivateKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceImportPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                                ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_ClassicMcElieceImportPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceImportPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                                 ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_ClassicMcElieceImportPrivateKey.restype = ctypes.c_int64

    _iqr_toolkit.iqr_ClassicMcElieceEncapsulate.argtypes = [ctypes.c_void_p,  # Public Key
                                                            ctypes.c_void_p,  # RNG
                                                            ctypes.c_void_p, ctypes.c_size_t,  # Ciphertext
                                                            ctypes.c_void_p, ctypes.c_size_t]  # Shared Key
    _iqr_toolkit.iqr_ClassicMcElieceEncapsulate.restype = ctypes.c_int64
    _iqr_toolkit.iqr_ClassicMcElieceDecapsulate.argtypes = [ctypes.c_void_p,  # Private Key
                                                            ctypes.c_void_p, ctypes.c_size_t,  # Ciphertext
                                                            ctypes.c_void_p, ctypes.c_size_t]  # Shared Key
    _iqr_toolkit.iqr_ClassicMcElieceDecapsulate.restype = ctypes.c_int64

    @staticmethod
    def CreateParams(ctx, variant):
        ''' Create a parameter object for the ClassicMcEliece cryptographic system.
        '''
        params = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_ClassicMcElieceCreateParams(ctx, variant, ctypes.byref(params))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceCreateParams() failed: {0}'.format(Retval.StrError(retval)))

        return params

    @staticmethod
    def DestroyParams(params):
        ''' Clear and deallocate a ClassicMcEliece parameter object.
        '''
        retval = _iqr_toolkit.iqr_ClassicMcElieceDestroyParams(ctypes.byref(params))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceDestroyParams() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def CreateKeyPair(params, rng):
        pub_key = ctypes.c_void_p(0)
        priv_key = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_ClassicMcElieceCreateKeyPair(params, rng, ctypes.byref(pub_key), ctypes.byref(priv_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceCreateKeyPair() failed: {0}'.format(Retval.StrError(retval)))

        return pub_key, priv_key

    @staticmethod
    def DestroyPublicKey(pub_key):
        ''' Clear and deallocate a ClassicMcEliece public key object.
        '''
        retval = _iqr_toolkit.iqr_ClassicMcElieceDestroyPublicKey(ctypes.byref(pub_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceDestroyPublicKey() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def DestroyPrivateKey(pub_key):
        ''' Clear and deallocate a ClassicMcEliece private object.
        '''
        retval = _iqr_toolkit.iqr_ClassicMcElieceDestroyPrivateKey(ctypes.byref(pub_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceDestroyPrivateKey() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def ExportPublicKey(params, pub_key):
        ''' Export a ClassicMcEliece public key object to bytes.
        '''
        pub_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceGetPublicKeySize(params, ctypes.byref(pub_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceGetPublicKeySize() failed: {0}'.format(Retval.StrError(retval)))

        pub_data = ctypes.create_string_buffer(pub_size.value)

        retval = _iqr_toolkit.iqr_ClassicMcElieceExportPublicKey(pub_key, pub_data, pub_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceExportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return pub_data.raw

    @staticmethod
    def ExportPrivateKey(params, priv_key):
        ''' Export a ClassicMcEliece private key object to bytes.
        '''
        priv_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceGetPrivateKeySize(params, ctypes.byref(priv_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceGetPrivateKeySize() failed: {0}'.format(Retval.StrError(retval)))

        priv_data = ctypes.create_string_buffer(priv_size.value)

        retval = _iqr_toolkit.iqr_ClassicMcElieceExportPrivateKey(priv_key, priv_data, priv_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceExportPrivateKey() failed: {0}'.format(Retval.StrError(retval)))

        return priv_data.raw

    @staticmethod
    def ImportPublicKey(params, pub_data):
        ''' Import a ClassicMcEliece public key from bytes.
        '''
        pub = ctypes.c_void_p(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceImportPublicKey(params, pub_data, len(pub_data), ctypes.byref(pub))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceImportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return pub

    @staticmethod
    def ImportPrivateKey(params, priv_data):
        ''' Import a ClassicMcEliece private key from bytes.
        '''
        priv = ctypes.c_void_p(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceImportPrivateKey(params, priv_data, len(priv_data), ctypes.byref(priv))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceImportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return priv

    @staticmethod
    def Encapsulate(params, pub, rng):
        ''' Create a ciphertext and shared key from the public key.
        '''
        ciphertext_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceGetCiphertextSize(params, ctypes.byref(ciphertext_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceGetCiphertextSize() failed: {0}'.format(Retval.StrError(retval)))
        shared_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceGetSharedKeySize(params, ctypes.byref(shared_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceGetSharedKeySize() failed: {0}'.format(Retval.StrError(retval)))

        ciphertext = ctypes.create_string_buffer(ciphertext_size.value)
        shared = ctypes.create_string_buffer(shared_size.value)

        retval = _iqr_toolkit.iqr_ClassicMcElieceEncapsulate(pub, rng, ciphertext, ciphertext_size, shared, shared_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceEncapsulate() failed: {0}'.format(Retval.StrError(retval)))

        return ciphertext.raw, shared.raw

    @staticmethod
    def Decapsulate(params, priv, ciphertext):
        ''' Extract the shared key from a private key and ciphertext.
        '''
        shared_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_ClassicMcElieceGetSharedKeySize(params, ctypes.byref(shared_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceGetSharedKeySize() failed: {0}'.format(Retval.StrError(retval)))

        shared = ctypes.create_string_buffer(shared_size.value)

        retval = _iqr_toolkit.iqr_ClassicMcElieceDecapsulate(priv, ciphertext, len(ciphertext), shared, shared_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceDecapsulate() failed: {0}'.format(Retval.StrError(retval)))

        return shared.raw


def test_ClassicMcEliece():
    ''' Run a simple ClassicMcEliece test.
    '''
    ctx = Context.Create()

    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_256, Hash.IQR_HASH_DEFAULT_SHA2_256)

    rng = Rng.CreateHMACDRBG(ctx, Hash.IQR_HASHALGO_SHA2_256)
    Rng.Initialize(rng, b'this is really bad seed data, never do this')

    params = ClassicMcEliece.CreateParams(ctx, ClassicMcEliece.IQR_CLASSICMCELIECE_6)
    pub, priv = ClassicMcEliece.CreateKeyPair(params, rng)

    ciphertext, shared = ClassicMcEliece.Encapsulate(params, pub, rng)
    print('ClassicMcEliece Encapsulate: {0} bytes'.format(len(shared)))
    shared2 = ClassicMcEliece.Decapsulate(params, priv, ciphertext)
    print('ClassicMcEliece Decapsulate: {0} bytes'.format(len(shared2)))

    assert(shared == shared2)

    pub_data = ClassicMcEliece.ExportPublicKey(params, pub)
    priv_data = ClassicMcEliece.ExportPrivateKey(params, priv)

    pub2 = ClassicMcEliece.ImportPublicKey(params, pub_data)
    priv2 = ClassicMcEliece.ImportPrivateKey(params, priv_data)

    ClassicMcEliece.DestroyPublicKey(pub)
    ClassicMcEliece.DestroyPrivateKey(priv)
    ClassicMcEliece.DestroyPublicKey(pub2)
    ClassicMcEliece.DestroyPrivateKey(priv2)
    ClassicMcEliece.DestroyParams(params)

    Rng.Destroy(rng)
    Context.Destroy(ctx)


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit Dilithium signatures: iqr_dilithium.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Dilithium:
    ''' Dilithium signature scheme.
    '''

    IQR_DILITHIUM_2 = _iqr_toolkit.IQR_DILITHIUM_2  # Low-security variant.
    IQR_DILITHIUM_3 = _iqr_toolkit.IQR_DILITHIUM_3  # Medium-security variant.
    IQR_DILITHIUM_5 = _iqr_toolkit.IQR_DILITHIUM_3  # High-security variant.

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_DilithiumCreateParams.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumCreateParams.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumDestroyParams.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumDestroyParams.restype = ctypes.c_int64

    _iqr_toolkit.iqr_DilithiumCreateKeyPair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                                        ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumCreateKeyPair.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumImportPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                          ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumImportPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumImportPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                           ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumImportPrivateKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumExportPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_DilithiumExportPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumExportPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_DilithiumExportPrivateKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumDestroyPublicKey.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumDestroyPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumDestroyPrivateKey.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_DilithiumDestroyPrivateKey.restype = ctypes.c_int64

    _iqr_toolkit.iqr_DilithiumGetPublicKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_DilithiumGetPublicKeySize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumGetPrivateKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_DilithiumGetPrivateKeySize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumGetSignatureSize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_DilithiumGetSignatureSize.restype = ctypes.c_int64

    _iqr_toolkit.iqr_DilithiumSign.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                               ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_DilithiumSign.restype = ctypes.c_int64
    _iqr_toolkit.iqr_DilithiumVerify.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                 ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_DilithiumVerify.restype = ctypes.c_int64

    @staticmethod
    def CreateParams(ctx, variant):
        ''' Create a parameter object for the Dilithium cryptographic system.
        '''
        params = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_DilithiumCreateParams(ctx, variant, ctypes.byref(params))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumCreateParams() failed: {0}'.format(Retval.StrError(retval)))

        return params

    @staticmethod
    def DestroyParams(params):
        ''' Clear and deallocate a Dilithium parameter object.
        '''
        retval = _iqr_toolkit.iqr_DilithiumDestroyParams(ctypes.byref(params))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumDestroyParams() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def CreateKeyPair(params, rng):
        pub_key = ctypes.c_void_p(0)
        priv_key = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_DilithiumCreateKeyPair(params, rng, ctypes.byref(pub_key), ctypes.byref(priv_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumCreateKeyPair() failed: {0}'.format(Retval.StrError(retval)))

        return pub_key, priv_key

    @staticmethod
    def DestroyPublicKey(pub_key):
        ''' Clear and deallocate a Dilithium public key object.
        '''
        retval = _iqr_toolkit.iqr_DilithiumDestroyPublicKey(ctypes.byref(pub_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumDestroyPublicKey() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def DestroyPrivateKey(pub_key):
        ''' Clear and deallocate a Dilithium private object.
        '''
        retval = _iqr_toolkit.iqr_DilithiumDestroyPrivateKey(ctypes.byref(pub_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumDestroyPrivateKey() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def ExportPublicKey(params, pub_key):
        ''' Export a Dilithium public key object to bytes.
        '''
        pub_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_DilithiumGetPublicKeySize(params, ctypes.byref(pub_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumGetPublicKeySize() failed: {0}'.format(Retval.StrError(retval)))

        pub_data = ctypes.create_string_buffer(pub_size.value)

        retval = _iqr_toolkit.iqr_DilithiumExportPublicKey(pub_key, pub_data, pub_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumExportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return pub_data.raw

    @staticmethod
    def ExportPrivateKey(params, priv_key):
        ''' Export a Dilithium private key object to bytes.
        '''
        priv_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_DilithiumGetPrivateKeySize(params, ctypes.byref(priv_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumGetPrivateKeySize() failed: {0}'.format(Retval.StrError(retval)))

        priv_data = ctypes.create_string_buffer(priv_size.value)

        retval = _iqr_toolkit.iqr_DilithiumExportPrivateKey(priv_key, priv_data, priv_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumExportPrivateKey() failed: {0}'.format(Retval.StrError(retval)))

        return priv_data.raw

    @staticmethod
    def ImportPublicKey(params, pub_data):
        ''' Import a Dilithium public key from bytes.
        '''
        pub = ctypes.c_void_p(0)
        retval = _iqr_toolkit.iqr_DilithiumImportPublicKey(params, pub_data, len(pub_data), ctypes.byref(pub))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumImportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return pub

    @staticmethod
    def ImportPrivateKey(params, priv_data):
        ''' Import a Dilithium private key from bytes.
        '''
        priv = ctypes.c_void_p(0)
        retval = _iqr_toolkit.iqr_DilithiumImportPrivateKey(params, priv_data, len(priv_data), ctypes.byref(priv))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumImportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return priv

    @staticmethod
    def Sign(params, priv, msg):
        ''' Create a signature from the given private key and message.
        '''
        sig_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_DilithiumGetSignatureSize(params, ctypes.byref(sig_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumGetSignatureSize() failed: {0}'.format(Retval.StrError(retval)))

        sig = ctypes.create_string_buffer(sig_size.value)

        retval = _iqr_toolkit.iqr_DilithiumSign(priv, msg, len(msg), sig, sig_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_DilithiumSign() failed: {0}'.format(Retval.StrError(retval)))

        return sig.raw

    @staticmethod
    def Verify(pub, msg, sig):
        ''' Verify a signature.
        '''
        retval = _iqr_toolkit.iqr_DilithiumVerify(pub, msg, len(msg), sig, len(sig))
        if retval == Retval.IQR_EINVSIGNATURE:
            return False
        elif retval != Retval.IQR_OK:
            raise RuntimeError('iqr_ClassicMcElieceDecapsulate() failed: {0}'.format(Retval.StrError(retval)))

        return True


def test_Dilithium():
    ''' Run a simple Dilithium test.
    '''
    ctx = Context.Create()

    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_256, Hash.IQR_HASH_DEFAULT_SHA2_256)

    rng = Rng.CreateHMACDRBG(ctx, Hash.IQR_HASHALGO_SHA2_256)
    Rng.Initialize(rng, b'this is really bad seed data, never do this')

    params = Dilithium.CreateParams(ctx, Dilithium.IQR_DILITHIUM_2)
    pub, priv = Dilithium.CreateKeyPair(params, rng)

    msg = b'This is a short message for signing.'
    sig = Dilithium.Sign(params, priv, msg)
    print('Dilithium signature: {0} bytes'.format(len(sig)))
    valid = Dilithium.Verify(pub, msg, sig)
    print('           verified: {0}'.format(valid))

    pub_data = Dilithium.ExportPublicKey(params, pub)
    priv_data = Dilithium.ExportPrivateKey(params, priv)

    pub2 = Dilithium.ImportPublicKey(params, pub_data)
    priv2 = Dilithium.ImportPrivateKey(params, priv_data)

    Dilithium.DestroyPublicKey(pub)
    Dilithium.DestroyPrivateKey(priv)
    Dilithium.DestroyPublicKey(pub2)
    Dilithium.DestroyPrivateKey(priv2)
    Dilithium.DestroyParams(params)

    Rng.Destroy(rng)
    Context.Destroy(ctx)


# ----------------------------------------------------------------------------------------------------------------------------------
# Frodo KEM: iqr_frodokem.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Frodo:
    ''' Frodo KEM.
    '''
    IQR_FRODOKEM_640_AES = _iqr_toolkit.IQR_FRODOKEM_640_AES  # FrodoKEM using AES, variant with 104 bit quantum security.
    IQR_FRODOKEM_640_SHAKE = _iqr_toolkit.IQR_FRODOKEM_640_SHAKE  # FrodoKEM using SHAKE, variant with 104 bit quantum security.
    IQR_FRODOKEM_976_AES = _iqr_toolkit.IQR_FRODOKEM_976_AES  # FrodoKEM using AES, variant with 150 bit quantum security.
    IQR_FRODOKEM_976_SHAKE = _iqr_toolkit.IQR_FRODOKEM_976_SHAKE  # FrodoKEM using SHAKE, variant with 150 bit quantum security.
    IQR_FRODOKEM_1344_AES = _iqr_toolkit.IQR_FRODOKEM_1344_AES  # FrodoKEM using AES, variant with 197 bit quantum security.
    IQR_FRODOKEM_1344_SHAKE = _iqr_toolkit.IQR_FRODOKEM_1344_SHAKE  # FrodoKEM using SHAKE, variant with 197 bit quantum security.

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_FrodoKEMCreateParams.argtypes = [ctypes.c_void_p,  # Context
                                                      ctypes.c_void_p,  # RNG
                                                      ctypes.POINTER(ctypes.c_void_p)]  # params
    _iqr_toolkit.iqr_FrodoKEMCreateParams.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMDestroyParams.argtypes = [ctypes.POINTER(ctypes.c_void_p)]  # params
    _iqr_toolkit.iqr_FrodoKEMDestroyParams.restype = ctypes.c_int64

    _iqr_toolkit.iqr_FrodoKEMGetPublicKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_FrodoKEMGetPublicKeySize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMGetPrivateKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_FrodoKEMGetPrivateKeySize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMGetCiphertextSize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_FrodoKEMGetCiphertextSize.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMGetSharedKeySize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    _iqr_toolkit.iqr_FrodoKEMGetSharedKeySize.restype = ctypes.c_int64

    _iqr_toolkit.iqr_FrodoKEMCreateKeyPair.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                       ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_FrodoKEMCreateKeyPair.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMDestroyPublicKey.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_FrodoKEMDestroyPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMDestroyPrivateKey.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_FrodoKEMDestroyPrivateKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMExportPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_FrodoKEMExportPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMExportPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_FrodoKEMExportPrivateKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMImportPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                         ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_FrodoKEMImportPublicKey.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMImportPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                                          ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_FrodoKEMImportPrivateKey.restype = ctypes.c_int64

    _iqr_toolkit.iqr_FrodoKEMEncapsulate.argtypes = [ctypes.c_void_p,  # Public Key
                                                     ctypes.c_void_p,  # RNG
                                                     ctypes.c_void_p, ctypes.c_size_t,  # Ciphertext
                                                     ctypes.c_void_p, ctypes.c_size_t]  # Shared Key
    _iqr_toolkit.iqr_FrodoKEMEncapsulate.restype = ctypes.c_int64
    _iqr_toolkit.iqr_FrodoKEMDecapsulate.argtypes = [ctypes.c_void_p,  # Private Key
                                                     ctypes.c_void_p, ctypes.c_size_t,  # Ciphertext
                                                     ctypes.c_void_p, ctypes.c_size_t]  # Shared Key
    _iqr_toolkit.iqr_FrodoKEMDecapsulate.restype = ctypes.c_int64

    @staticmethod
    def CreateParams(ctx, variant):
        ''' Create a parameter object for the FrodoKEM cryptographic system.
        '''
        params = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_FrodoKEMCreateParams(ctx, variant, ctypes.byref(params))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMCreateParams() failed: {0}'.format(Retval.StrError(retval)))

        return params

    @staticmethod
    def DestroyParams(params):
        ''' Clear and deallocate a FrodoKEM parameter object.
        '''
        retval = _iqr_toolkit.iqr_FrodoKEMDestroyParams(ctypes.byref(params))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMDestroyParams() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def CreateKeyPair(params, rng):
        pub_key = ctypes.c_void_p(0)
        priv_key = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_FrodoKEMCreateKeyPair(params, rng, ctypes.byref(pub_key), ctypes.byref(priv_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMCreateKeyPair() failed: {0}'.format(Retval.StrError(retval)))

        return pub_key, priv_key

    @staticmethod
    def DestroyPublicKey(pub_key):
        ''' Clear and deallocate a FrodoKEM public key object.
        '''
        retval = _iqr_toolkit.iqr_FrodoKEMDestroyPublicKey(ctypes.byref(pub_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMDestroyPublicKey() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def DestroyPrivateKey(pub_key):
        ''' Clear and deallocate a FrodoKEM private object.
        '''
        retval = _iqr_toolkit.iqr_FrodoKEMDestroyPrivateKey(ctypes.byref(pub_key))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMDestroyPrivateKey() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def ExportPublicKey(params, pub_key):
        ''' Export a FrodoKEM public key object to bytes.
        '''
        pub_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_FrodoKEMGetPublicKeySize(params, ctypes.byref(pub_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMGetPublicKeySize() failed: {0}'.format(Retval.StrError(retval)))

        pub_data = ctypes.create_string_buffer(pub_size.value)

        retval = _iqr_toolkit.iqr_FrodoKEMExportPublicKey(pub_key, pub_data, pub_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMExportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return pub_data.raw

    @staticmethod
    def ExportPrivateKey(params, priv_key):
        ''' Export a FrodoKEM private key object to bytes.
        '''
        priv_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_FrodoKEMGetPrivateKeySize(params, ctypes.byref(priv_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMGetPrivateKeySize() failed: {0}'.format(Retval.StrError(retval)))

        priv_data = ctypes.create_string_buffer(priv_size.value)

        retval = _iqr_toolkit.iqr_FrodoKEMExportPrivateKey(priv_key, priv_data, priv_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMExportPrivateKey() failed: {0}'.format(Retval.StrError(retval)))

        return priv_data.raw

    @staticmethod
    def ImportPublicKey(params, pub_data):
        ''' Import a FrodoKEM public key from bytes.
        '''
        pub = ctypes.c_void_p(0)
        retval = _iqr_toolkit.iqr_FrodoKEMImportPublicKey(params, pub_data, len(pub_data), ctypes.byref(pub))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMImportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return pub

    @staticmethod
    def ImportPrivateKey(params, priv_data):
        ''' Import a FrodoKEM private key from bytes.
        '''
        priv = ctypes.c_void_p(0)
        retval = _iqr_toolkit.iqr_FrodoKEMImportPrivateKey(params, priv_data, len(priv_data), ctypes.byref(priv))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMImportPublicKey() failed: {0}'.format(Retval.StrError(retval)))

        return priv

    @staticmethod
    def Encapsulate(params, pub, rng):
        ''' Create a ciphertext and shared key from the public key.
        '''
        ciphertext_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_FrodoKEMGetCiphertextSize(params, ctypes.byref(ciphertext_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMGetCiphertextSize() failed: {0}'.format(Retval.StrError(retval)))
        shared_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_FrodoKEMGetSharedKeySize(params, ctypes.byref(shared_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMGetSharedKeySize() failed: {0}'.format(Retval.StrError(retval)))

        ciphertext = ctypes.create_string_buffer(ciphertext_size.value)
        shared = ctypes.create_string_buffer(shared_size.value)

        retval = _iqr_toolkit.iqr_FrodoKEMEncapsulate(pub, rng, ciphertext, ciphertext_size, shared, shared_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMEncapsulate() failed: {0}'.format(Retval.StrError(retval)))

        return ciphertext.raw, shared.raw

    @staticmethod
    def Decapsulate(params, priv, ciphertext):
        ''' Extract the shared key from a private key and ciphertext.
        '''
        shared_size = ctypes.c_size_t(0)
        retval = _iqr_toolkit.iqr_FrodoKEMGetSharedKeySize(params, ctypes.byref(shared_size))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMGetSharedKeySize() failed: {0}'.format(Retval.StrError(retval)))

        shared = ctypes.create_string_buffer(shared_size.value)

        retval = _iqr_toolkit.iqr_FrodoKEMDecapsulate(priv, ciphertext, len(ciphertext), shared, shared_size)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_FrodoKEMDecapsulate() failed: {0}'.format(Retval.StrError(retval)))

        return shared.raw


def test_FrodoKEM():
    ''' Run a simple FrodoKEM test.
    '''
    ctx = Context.Create()

    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_256, Hash.IQR_HASH_DEFAULT_SHA2_256)

    rng = Rng.CreateHMACDRBG(ctx, Hash.IQR_HASHALGO_SHA2_256)
    Rng.Initialize(rng, b'this is really bad seed data, never do this')

    params = Frodo.CreateParams(ctx, Frodo.IQR_FRODOKEM_640_AES)
    pub, priv = Frodo.CreateKeyPair(params, rng)

    ciphertext, shared = Frodo.Encapsulate(params, pub, rng)
    print('Frodo Encapsulate: {0} bytes'.format(len(shared)))
    shared2 = Frodo.Decapsulate(params, priv, ciphertext)
    print('Frodo Decapsulate: {0} bytes'.format(len(shared2)))

    assert(shared == shared2)

    pub_data = Frodo.ExportPublicKey(params, pub)
    priv_data = Frodo.ExportPrivateKey(params, priv)

    pub2 = Frodo.ImportPublicKey(params, pub_data)
    priv2 = Frodo.ImportPrivateKey(params, priv_data)

    Frodo.DestroyPublicKey(pub)
    Frodo.DestroyPrivateKey(priv)
    Frodo.DestroyPublicKey(pub2)
    Frodo.DestroyPrivateKey(priv2)
    Frodo.DestroyParams(params)

    Rng.Destroy(rng)
    Context.Destroy(ctx)


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit hash implementations: iqr_hash.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Hash:
    ''' Hash implementations.

    TODO: Creating/using a Hash object is not currently supported.
    '''

    IQR_HASHALGO_SHA2_256 = 2  # SHA2-256 algorithm type identifier.
    IQR_HASHALGO_SHA2_384 = 3  # SHA2-384 algorithm type identifier.
    IQR_HASHALGO_SHA2_512 = 4  # SHA2-512 algorithm type identifier.
    IQR_HASHALGO_SHA3_256 = 5  # SHA3-256 algorithm type identifier.
    IQR_HASHALGO_SHA3_512 = 6  # SHA3-512 algorithm type identifier.

    IQR_SHA2_256_DIGEST_SIZE = 32  # The size of a SHA2-256 digest in bytes.
    IQR_SHA2_384_DIGEST_SIZE = 48  # The size of a SHA2-384 digest in bytes.
    IQR_SHA2_512_DIGEST_SIZE = 64  # The size of a SHA2-512 digest in bytes.
    IQR_SHA3_256_DIGEST_SIZE = 32  # The size of a SHA3-256 digest in bytes.
    IQR_SHA3_512_DIGEST_SIZE = 64  # The size of a SHA3-512 digest in bytes.

    IQR_HASH_DEFAULT_SHA2_256 = _iqr_toolkit.IQR_HASH_DEFAULT_SHA2_256  # Internal SHA2-256 implementation.
    IQR_HASH_DEFAULT_SHA2_384 = _iqr_toolkit.IQR_HASH_DEFAULT_SHA2_384  # Internal SHA2-384 implementation.
    IQR_HASH_DEFAULT_SHA2_512 = _iqr_toolkit.IQR_HASH_DEFAULT_SHA2_512  # Internal SHA2-512 implementation.
    IQR_HASH_DEFAULT_SHA3_256 = _iqr_toolkit.IQR_HASH_DEFAULT_SHA3_256  # Internal SHA3-256 implementation.
    IQR_HASH_DEFAULT_SHA3_512 = _iqr_toolkit.IQR_HASH_DEFAULT_SHA3_512  # Internal SHA3-512 implementation.

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_HashRegisterCallbacks.argtypes = [ctypes.c_void_p, ctypes.c_int64, ctypes.c_void_p]
    _iqr_toolkit.iqr_HashRegisterCallbacks.restype = ctypes.c_int64

    @staticmethod
    def RegisterCallbacks(ctx, algo, callbacks):
        retval = _iqr_toolkit.iqr_HashRegisterCallbacks(ctx, algo, callbacks)
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_HashRegisterCallbacks() failed: {0}'.format(Retval.StrError(retval)))


def test_hash():
    ''' Run a simple Hash test.
    '''
    ctx = Context.Create()

    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_256, Hash.IQR_HASH_DEFAULT_SHA2_256)
    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_384, Hash.IQR_HASH_DEFAULT_SHA2_384)
    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_512, Hash.IQR_HASH_DEFAULT_SHA2_512)
    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA3_256, Hash.IQR_HASH_DEFAULT_SHA3_256)
    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA3_512, Hash.IQR_HASH_DEFAULT_SHA3_512)

    Context.Destroy(ctx)


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

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_StrError.argtypes = [ctypes.c_int64]
    _iqr_toolkit.iqr_StrError.restype = ctypes.c_char_p

    @staticmethod
    def StrError(error_value):
        ''' Return a string representation of the given iqr_retval value.
        '''
        return _iqr_toolkit.iqr_StrError(error_value).decode('utf-8')


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit random number generators: iqr_rng.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Rng:
    ''' Toolkit random number generators.

    TODO: Providing your own callbacks is not currently supported.
    '''

    # Type hints for calling into the C library.
    _iqr_toolkit.iqr_RNGCreateHMACDRBG.argtypes = [ctypes.c_void_p, ctypes.c_int64, ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_RNGCreateHMACDRBG.restype = ctypes.c_int64
    _iqr_toolkit.iqr_RNGDestroy.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _iqr_toolkit.iqr_RNGDestroy.restype = ctypes.c_int64

    _iqr_toolkit.iqr_RNGInitialize.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    _iqr_toolkit.iqr_RNGInitialize.restype = ctypes.c_int64

    @staticmethod
    def CreateHMACDRBG(ctx, hash_algo):
        rng = ctypes.c_void_p(0)

        retval = _iqr_toolkit.iqr_RNGCreateHMACDRBG(ctx, hash_algo, ctypes.byref(rng))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_RNGCreateHMACDRBG() failed: {0}'.format(Retval.StrError(retval)))

        return rng

    @staticmethod
    def Destroy(rng):
        retval = _iqr_toolkit.iqr_RNGDestroy(ctypes.byref(rng))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_RNGDestroy() failed: {0}'.format(Retval.StrError(retval)))

    @staticmethod
    def Initialize(rng, seed):
        retval = _iqr_toolkit.iqr_RNGInitialize(rng, seed, len(seed))
        if retval != Retval.IQR_OK:
            raise RuntimeError('iqr_RNGInitialize() failed: {0}'.format(Retval.StrError(retval)))


def test_rng():
    ''' Run a simple RNG test.
    '''
    ctx = Context.Create()

    Hash.RegisterCallbacks(ctx, Hash.IQR_HASHALGO_SHA2_256, Hash.IQR_HASH_DEFAULT_SHA2_256)

    rng = Rng.CreateHMACDRBG(ctx, Hash.IQR_HASHALGO_SHA2_256)
    Rng.Initialize(rng, b'this is really bad seed data, never do this')

    Rng.Destroy(rng)
    Context.Destroy(ctx)


# ----------------------------------------------------------------------------------------------------------------------------------
# Toolkit return values: iqr_version.h
# ----------------------------------------------------------------------------------------------------------------------------------
class Version:
    ''' ISARA toolkit version information.
    '''

    IQR_VERSION_MAJOR = 2  # Major version number.
    IQR_VERSION_MINOR = 1  # Minor version number.

    IQR_VERSION_STRING = "ISARA Radiate Quantum-Safe Library 3.0"

    # Type hints for calling into the C library.
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


if __name__ == '__main__':
    # Run me via python3 iqr_toolkit.py
    print(Version.IQR_VERSION_STRING)
    print('Build target: {0}'.format(Version.GetBuildTarget()))
    print('Build hash: {0}'.format(Version.GetBuildHash()))

    # Building blocks. If these don't work, you're in trouble.
    test_chacha20()
    test_hash()
    test_rng()

    # KEMs
    test_ClassicMcEliece()
    test_FrodoKEM()

    # Signatures
    test_Dilithium()
