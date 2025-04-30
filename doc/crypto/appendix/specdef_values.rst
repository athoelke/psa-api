.. SPDX-FileCopyrightText: Copyright 2020-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _appendix-specdef-values:

Example macro implementations
-----------------------------

This appendix provides example implementations of the function-like macros that have specification-defined values.

.. note::
    In a future version of this specification, these example implementations will be replaced with a pseudo-code representation of the macro's computation in the macro description.

The examples here provide correct results for the valid inputs defined by each API, for an implementation that supports all of the defined algorithms and key types. An implementation can provide alternative definitions of these macros:

*   If the implementation does not support all of the algorithms or key types, it can provide a simpler definition of applicable macros.
*   If the implementation provides vendor-specific algorithms or key types, it needs to extend the definitions of applicable macros.

Algorithm macros
~~~~~~~~~~~~~~~~

.. code-block:: xref

    #define PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(aead_alg) \
        ((((aead_alg) & ~0x003f8000) == 0x05400100) ? PSA_ALG_CCM : \
         (((aead_alg) & ~0x003f8000) == 0x05400200) ? PSA_ALG_GCM : \
         (((aead_alg) & ~0x003f8000) == 0x05000500) ? PSA_ALG_CHACHA20_POLY1305 : \
         PSA_ALG_NONE)

    #define PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(aead_alg, min_tag_length) \
        ( PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, min_tag_length) | 0x00008000 )

    #define PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, tag_length) \
        ((psa_algorithm_t) (((aead_alg) & ~0x003f8000) | (((tag_length) & 0x3f) << 16)))

    #define PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(mac_alg, min_mac_length) \
        ( PSA_ALG_TRUNCATED_MAC(mac_alg, min_mac_length) | 0x00008000 )

    #define PSA_ALG_DETERMINISTIC_ECDSA(hash_alg) \
        ((psa_algorithm_t) (0x06000700 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_ECDSA(hash_alg) \
        ((psa_algorithm_t) (0x06000600 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_FULL_LENGTH_MAC(mac_alg) \
        ((psa_algorithm_t) ((mac_alg) & ~0x003f8000))

    #define PSA_ALG_GET_HASH(alg) \
        (((alg) & 0x000000ff) == 0 ? PSA_ALG_NONE : 0x02000000 | ((alg) & 0x000000ff))

    #define PSA_ALG_HKDF(hash_alg) \
        ((psa_algorithm_t) (0x08000100 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_HKDF_EXPAND(hash_alg) \
        ((psa_algorithm_t) (0x08000500 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_HKDF_EXTRACT(hash_alg) \
        ((psa_algorithm_t) (0x08000400 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_HMAC(hash_alg) \
        ((psa_algorithm_t) (0x03800000 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_IS_AEAD(alg) \
        (((alg) & 0x7f000000) == 0x05000000)

    #define PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) \
        (((alg) & 0x7f400000) == 0x05400000)

    #define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg) \
        (((alg) & 0x7f000000) == 0x07000000)

    #define PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) \
        (((alg) & 0x7fc00000) == 0x03c00000)

    #define PSA_ALG_IS_CIPHER(alg) \
        (((alg) & 0x7f000000) == 0x04000000)

    #define PSA_ALG_IS_DETERMINISTIC_ECDSA(alg) \
        (((alg) & ~0x000000ff) == 0x06000700)

    #define PSA_ALG_IS_ECDH(alg) \
        (((alg) & 0x7fff0000) == 0x09020000)

    #define PSA_ALG_IS_ECDSA(alg) \
        (((alg) & ~0x000001ff) == 0x06000600)

    #define PSA_ALG_IS_FFDH(alg) \
        (((alg) & 0x7fff0000) == 0x09010000)

    #define PSA_ALG_IS_HASH(alg) \
        (((alg) & 0x7f000000) == 0x02000000)

    #define PSA_ALG_IS_HASH_AND_SIGN(alg) \
        (PSA_ALG_IS_RSA_PSS(alg) || PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) || \
         PSA_ALG_IS_ECDSA(alg) || PSA_ALG_IS_HASH_EDDSA(alg))

    #define PSA_ALG_IS_HASH_EDDSA(alg) \
        (((alg) & ~0x000000ff) == 0x06000900)

    #define PSA_ALG_IS_HKDF(alg) \
        (((alg) & ~0x000000ff) == 0x08000100)

    #define PSA_ALG_IS_HKDF_EXPAND(alg) \
        (((alg) & ~0x000000ff) == 0x08000500)

    #define PSA_ALG_IS_HKDF_EXTRACT(alg) \
        (((alg) & ~0x000000ff) == 0x08000400)

    #define PSA_ALG_IS_HMAC(alg) \
        (((alg) & 0x7fc0ff00) == 0x03800000)

    #define PSA_ALG_IS_JPAKE(alg) \
        (((alg) & ~0x000000ff) == 0x0a000100)

    #define PSA_ALG_IS_KEY_AGREEMENT(alg) \
        (((alg) & 0x7f000000) == 0x09000000)

    #define PSA_ALG_IS_KEY_DERIVATION(alg) \
        (((alg) & 0x7f000000) == 0x08000000)

    #define PSA_ALG_IS_KEY_DERIVATION_STRETCHING(alg) \
        (((alg) & 0x7f800000) == 0x08800000)

    #define PSA_ALG_IS_KEY_ENCAPSULATION(alg) \
        (((alg) & 0x7f000000) == 0x0c000000)

    #define PSA_ALG_IS_MAC(alg) \
        (((alg) & 0x7f000000) == 0x03000000)

    #define PSA_ALG_IS_PAKE(alg) \
        (((alg) & 0x7f000000) == 0x0a000000)

    #define PSA_ALG_IS_PBKDF2_HMAC(alg) \
        (((alg) & ~0x000000ff) == 0x08800100)

    #define PSA_ALG_IS_RANDOMIZED_ECDSA(alg) \
        (((alg) & ~0x000000ff) == 0x06000600)

    #define PSA_ALG_IS_RSA_OAEP(alg) \
        (((alg) & ~0x000000ff) == 0x07000300)

    #define PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) \
        (((alg) & ~0x000000ff) == 0x06000200)

    #define PSA_ALG_IS_RSA_PSS(alg) \
        (((alg) & ~0x000010ff) == 0x06000300)

    #define PSA_ALG_IS_RSA_PSS_ANY_SALT(alg) \
        (((alg) & ~0x000000ff) == 0x06001300)

    #define PSA_ALG_IS_RSA_PSS_STANDARD_SALT(alg) \
        (((alg) & ~0x000000ff) == 0x06000300)

    #define PSA_ALG_IS_SIGN(alg) \
        (((alg) & 0x7f000000) == 0x06000000)

    #define PSA_ALG_IS_SIGN_HASH(alg) \
        PSA_ALG_IS_SIGN(alg)

    #define PSA_ALG_IS_SIGN_MESSAGE(alg) \
        (PSA_ALG_IS_SIGN(alg) && \
         (alg) != PSA_ALG_ECDSA_ANY && (alg) != PSA_ALG_RSA_PKCS1V15_SIGN_RAW)

    #define PSA_ALG_IS_SP800_108_COUNTER_HMAC(alg) \
        (((alg) & ~0x000000ff) == 0x08000700)

    #define PSA_ALG_IS_SPAKE2P(alg) \
        (((alg) & ~0x000003ff) == 0x0a000400)

    #define PSA_ALG_IS_SPAKE2P_CMAC(alg) \
        (((alg) & ~0x000000ff) == 0x0a000500)

    #define PSA_ALG_IS_SPAKE2P_HMAC(alg) \
        (((alg) & ~0x000000ff) == 0x0a000400)

    #define PSA_ALG_IS_STANDALONE_KEY_AGREEMENT(alg) \
        (((alg) & 0x7f00ffff) == 0x09000000)

    #define PSA_ALG_IS_STREAM_CIPHER(alg) \
        (((alg) & 0x7f800000) == 0x04800000)

    #define PSA_ALG_IS_TLS12_PRF(alg) \
        (((alg) & ~0x000000ff) == 0x08000200)

    #define PSA_ALG_IS_TLS12_PSK_TO_MS(alg) \
        (((alg) & ~0x000000ff) == 0x08000300)

    #define PSA_ALG_IS_WILDCARD(alg) \
        ((PSA_ALG_GET_HASH(alg) == PSA_ALG_ANY_HASH) || \
         (((alg) & 0x7f008000) == 0x03008000) || \
         (((alg) & 0x7f008000) == 0x05008000))

    #define PSA_ALG_IS_XOF(alg) \
        (((alg) & 0x7f000000) == 0x0D000000)

    #define PSA_ALG_JPAKE(hash_alg) \
        ((psa_algorithm_t) (0x0a000100 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_KEY_AGREEMENT(ka_alg, kdf_alg) \
        ((ka_alg) | (kdf_alg))

    #define PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) \
        ((psa_algorithm_t)((alg) & 0xff7f0000))

    #define PSA_ALG_KEY_AGREEMENT_GET_KDF(alg) \
        ((psa_algorithm_t)((alg) & 0xfe80ffff))

    #define PSA_ALG_PBKDF2_HMAC(hash_alg) \
        ((psa_algorithm_t)(0x08800100 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_RSA_OAEP(hash_alg) \
        ((psa_algorithm_t)(0x07000300 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg) \
        ((psa_algorithm_t)(0x06000200 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_RSA_PSS(hash_alg) \
        ((psa_algorithm_t)(0x06000300 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_RSA_PSS_ANY_SALT(hash_alg) \
        ((psa_algorithm_t)(0x06001300 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_SP800_108_COUNTER_HMAC(hash_alg) \
        ((psa_algorithm_t) (0x08000700 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_SPAKE2P_CMAC(hash_alg) \
        ((psa_algorithm_t) (0x0a000500 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_SPAKE2P_HMAC(hash_alg) \
        ((psa_algorithm_t) (0x0a000400 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_TLS12_PRF(hash_alg) \
        ((psa_algorithm_t) (0x08000200 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_TLS12_PSK_TO_MS(hash_alg) \
        ((psa_algorithm_t) (0x08000300 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length) \
        ((psa_algorithm_t) (((mac_alg) & ~0x003f8000) | (((mac_length) & 0x3f) << 16)))

    #define PSA_PAKE_PRIMITIVE(pake_type, pake_family, pake_bits) \
        ((pake_bits & 0xFFFF) != pake_bits) ? 0 :                 \
        ((psa_pake_primitive_t) (((pake_type) << 24 |             \
                (pake_family) << 16) | (pake_bits)))

    #define PSA_PAKE_PRIMITIVE_GET_BITS(pake_primitive) \
        ((size_t)(pake_primitive & 0xFFFF))

    #define PSA_PAKE_PRIMITIVE_GET_FAMILY(pake_primitive) \
        ((psa_pake_family_t)((pake_primitive >> 16) & 0xFF))

    #define PSA_PAKE_PRIMITIVE_GET_TYPE(pake_primitive) \
        ((psa_pake_primitive_type_t)((pake_primitive >> 24) & 0xFF))

.. _appendix-specdef-key-values:

Key type macros
~~~~~~~~~~~~~~~

.. code-block:: xref

    #define PSA_BLOCK_CIPHER_BLOCK_LENGTH(type) \
        (1u << (((type) >> 8) & 7))

    #define PSA_KEY_TYPE_DH_GET_FAMILY(type) \
        ((psa_dh_family_t) ((type) & 0x007f))

    #define PSA_KEY_TYPE_DH_KEY_PAIR(group) \
        ((psa_key_type_t) (0x7200 | ((group) & 0x007f)))

    #define PSA_KEY_TYPE_DH_PUBLIC_KEY(group) \
        ((psa_key_type_t) (0x4200 | ((group) & 0x007f)))

    #define PSA_KEY_TYPE_ECC_GET_FAMILY(type) \
        ((psa_ecc_family_t) ((type) & 0x007f))

    #define PSA_KEY_TYPE_ECC_KEY_PAIR(curve) \
        ((psa_key_type_t) (0x7100 | ((curve) & 0x007f)))

    #define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve) \
        ((psa_key_type_t) (0x4100 | ((curve) & 0x007f)))

    #define PSA_KEY_TYPE_IS_ASYMMETRIC(type) \
        (((type) & 0x4000) == 0x4000)

    #define PSA_KEY_TYPE_IS_DH(type) \
        ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) & 0xff80) == 0x4200)

    #define PSA_KEY_TYPE_IS_DH_KEY_PAIR(type) \
        (((type) & 0xff80) == 0x7200)

    #define PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(type) \
        (((type) & 0xff80) == 0x4200)

    #define PSA_KEY_TYPE_IS_ECC(type) \
        ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) & 0xff80) == 0x4100)

    #define PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type) \
        (((type) & 0xff80) == 0x7100)

    #define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type) \
        (((type) & 0xff80) == 0x4100)

    #define PSA_KEY_TYPE_IS_KEY_PAIR(type) \
        (((type) & 0x7000) == 0x7000)

    #define PSA_KEY_TYPE_IS_PUBLIC_KEY(type) \
        (((type) & 0x7000) == 0x4000)

    #define PSA_KEY_TYPE_IS_RSA(type) \
        (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) == 0x4001)

    #define PSA_KEY_TYPE_IS_SPAKE2P(type) \
        ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) & 0xff80) == 0x4400)

    #define PSA_KEY_TYPE_IS_SPAKE2P_KEY_PAIR(type) \
        (((type) & 0xff80) == 0x7400)

    #define PSA_KEY_TYPE_IS_SPAKE2P_PUBLIC_KEY(type) \
        (((type) & 0xff80) == 0x4400)

    #define PSA_KEY_TYPE_IS_UNSTRUCTURED(type) \
        (((type) & 0x7000) == 0x1000 || ((type) & 0x7000) == 0x2000)

    #define PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY(type) \
        ((psa_key_type_t) ((type) | 0x3000))

    #define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) \
        ((psa_key_type_t) ((type) & ~0x3000))

    #define PSA_KEY_TYPE_SPAKE2P_GET_FAMILY(type) \
        ((psa_ecc_family_t) ((type) & 0x007f))

    #define PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(curve) \
        ((psa_key_type_t) (0x7400 | ((curve) & 0x007f)))

    #define PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(curve) \
        ((psa_key_type_t) (0x4400 | ((curve) & 0x007f)))

Hash suspend state macros
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: xref

    #define PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg) \
        ((alg)==PSA_ALG_MD2 ? 64 : \
         (alg)==PSA_ALG_MD4 || (alg)==PSA_ALG_MD5 ? 16 : \
         (alg)==PSA_ALG_RIPEMD160 || (alg)==PSA_ALG_SHA_1 ? 20 : \
         (alg)==PSA_ALG_SHA_224 || (alg)==PSA_ALG_SHA_256 ? 32 : \
         (alg)==PSA_ALG_SHA_512 || (alg)==PSA_ALG_SHA_384 || \
            (alg)==PSA_ALG_SHA_512_224 || (alg)==PSA_ALG_SHA_512_256 ? 64 : \
         0)

    #define PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg) \
        ((alg)==PSA_ALG_MD2 ? 1 : \
         (alg)==PSA_ALG_MD4 || (alg)==PSA_ALG_MD5 || (alg)==PSA_ALG_RIPEMD160 || \
            (alg)==PSA_ALG_SHA_1 || (alg)==PSA_ALG_SHA_224 || (alg)==PSA_ALG_SHA_256 ? 8 : \
         (alg)==PSA_ALG_SHA_512 || (alg)==PSA_ALG_SHA_384 || \
            (alg)==PSA_ALG_SHA_512_224 || (alg)==PSA_ALG_SHA_512_256 ? 16 : \
         0)

    #define PSA_HASH_SUSPEND_OUTPUT_SIZE(alg) \
        (PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH + \
         PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg) + \
         PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg) + \
         PSA_HASH_BLOCK_LENGTH(alg) - 1)
