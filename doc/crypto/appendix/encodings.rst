.. SPDX-FileCopyrightText: Copyright 2022-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _appendix-encodings:

Algorithm and key type encoding
===============================

Algorithm identifiers (`psa_algorithm_t`) and key types (`psa_key_type_t`) in the |API| are structured integer values.

*   :secref:`algorithm-encoding` describes the encoding scheme for algorithm identifiers
*   :secref:`key-type-encoding` describes the encoding scheme for key types


.. _algorithm-encoding:

Algorithm identifier encoding
-----------------------------

Algorithm identifiers are 32-bit integer values of the type `psa_algorithm_t`. Algorithm identifier values have the structure shown in :numref:`fig-algorithm-fields`.

.. figure:: ../figure/encoding/algorithm.*
    :name: fig-algorithm-fields

    Encoding of `psa_algorithm_t`

:numref:`table-algorithm-fields` describes the meaning of the bit-fields --- some of the bit-fields are used in different ways by different algorithm categories.

.. list-table:: Bit fields in an algorithm identifier
    :name: table-algorithm-fields
    :header-rows: 1
    :widths: 2,2,17

    *   -   Field
        -   Bits
        -   Description
    *   -   V
        -   [31]
        -   Flag to indicate an implementation-defined algorithm identifier, when V=1.

            Algorithm identifiers defined by this specification always have V=0.
    *   -   CAT
        -   [30:24]
        -   Algorithm category. See :secref:`algorithm-category`.
    *   -   S
        -   [23]
        -   For a cipher algorithm, this flag indicates a stream cipher when S=1.

            For a key-derivation algorithm, this flag indicates a key-stretching or password-hashing algorithm when S=1.
    *   -   B
        -   [22]
        -   Flag to indicate an algorithm built on a block cipher, when B=1.
    *   -   LEN/T2
        -   [21:16]
        -   LEN is the length of a MAC or AEAD tag, T2 is a key-agreement algorithm sub-type.
    *   -   T1
        -   [15:8]
        -   Algorithm sub-type for most algorithm categories.
    *   -   H
        -   [7:0]
        -   Hash algorithm sub-type, also used in any algorithm that is parameterized by a hash.

.. _algorithm-category:

Algorithm categories
~~~~~~~~~~~~~~~~~~~~

The CAT field in an algorithm identifier takes the values shown in :numref:`table-algorithm-category`.

.. csv-table:: Algorithm identifier categories
    :name: table-algorithm-category
    :header-rows: 1
    :align: left
    :widths: auto

    Algorithm category, CAT, Category details
    None, ``0x00``, See `PSA_ALG_NONE`
    Hash, ``0x02``, See :secref:`hash-encoding`
    MAC, ``0x03``, See :secref:`mac-encoding`
    Cipher, ``0x04``, See :secref:`cipher-encoding`
    AEAD, ``0x05``, See :secref:`aead-encoding`
    Key derivation, ``0x08``, See :secref:`kdf-encoding`
    Asymmetric signature, ``0x06``, See :secref:`sign-encoding`
    Asymmetric encryption, ``0x07``, See :secref:`pke-encoding`
    Key agreement, ``0x09``, See :secref:`ka-encoding`
    Key encapsulation, ``0x0C``, See :secref:`key-encapsulation-encoding`
    PAKE, ``0x0A``, See :secref:`pake-encoding`

.. rationale::

    The values for the algorithm categories are chosen to support the composition of key-agreement and key-derivation algorithms.

    The only categories that can combine in a bitwise OR into a valid key-agreement algorithm identifier are key derivation (``0x08``) and key agreement (``0x09``). This reduces the risk of a programming error resulting in the combination of other algorithm types using `PSA_ALG_KEY_AGREEMENT()` and ending up with a valid algorithm identifier that can be used in a key-agreement operation.

.. _hash-encoding:

Hash algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for hash algorithms defined in this specification are encoded as shown in :numref:`fig-hash-fields`.

.. figure:: ../figure/encoding/hash.*
    :name: fig-hash-fields

    Hash algorithm encoding

The defined values for HASH-TYPE are shown in :numref:`table-hash-type`.

.. csv-table:: Hash algorithm sub-type values
    :name: table-hash-type
    :header-rows: 1
    :align: left
    :widths: auto

    Hash algorithm, HASH-TYPE, Algorithm identifier, Algorithm value
    MD2, ``0x01``, `PSA_ALG_MD2`, ``0x02000001``
    MD4, ``0x02``, `PSA_ALG_MD4`, ``0x02000002``
    MD5, ``0x03``, `PSA_ALG_MD5`, ``0x02000003``
    RIPEMD-160, ``0x04``, `PSA_ALG_RIPEMD160`, ``0x02000004``
    SHA1, ``0x05``, `PSA_ALG_SHA_1`, ``0x02000005``
    AES-MMO (Zigbee), ``0x07``, `PSA_ALG_AES_MMO_ZIGBEE`, ``0x02000007``
    SHA-224, ``0x08``, `PSA_ALG_SHA_224`, ``0x02000008``
    SHA-256, ``0x09``, `PSA_ALG_SHA_256`, ``0x02000009``
    SHA-384, ``0x0A``, `PSA_ALG_SHA_384`, ``0x0200000A``
    SHA-512, ``0x0B``, `PSA_ALG_SHA_512`, ``0x0200000B``
    SHA-512/224, ``0x0C``, `PSA_ALG_SHA_512_224`, ``0x0200000C``
    SHA-512/256, ``0x0D``, `PSA_ALG_SHA_512_256`, ``0x0200000D``
    SHA3-224, ``0x10``, `PSA_ALG_SHA3_224`, ``0x02000010``
    SHA3-256, ``0x11``, `PSA_ALG_SHA3_256`, ``0x02000011``
    SHA3-384, ``0x12``, `PSA_ALG_SHA3_384`, ``0x02000012``
    SHA3-512, ``0x13``, `PSA_ALG_SHA3_512`, ``0x02000013``
    SM3, ``0x14``, `PSA_ALG_SM3`, ``0x02000014``
    SHAKE256-512, ``0x15``, `PSA_ALG_SHAKE256_512`, ``0x02000015``
    *wildcard* :sup:`a`, ``0xFF``, `PSA_ALG_ANY_HASH`, ``0x020000FF``

a.  The wildcard hash `PSA_ALG_ANY_HASH` can be used to parameterize a signature algorithm which defines a key usage policy, permitting any hash algorithm to be specified in a signature operation using the key.

.. _mac-encoding:

MAC algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for MAC algorithms defined in this specification are encoded as shown in :numref:`fig-mac-fields`.

.. figure:: ../figure/encoding/mac.*
    :name: fig-mac-fields

    MAC algorithm encoding

The defined values for B and MAC-TYPE are shown in :numref:`table-mac-type`.

LEN = 0 specifies a default length output MAC, other values for LEN specify a truncated MAC.

W is a flag to indicate a wildcard permitted-algorithm policy:

*   W = 0 indicates a specific MAC algorithm and MAC length.
*   W = 1 indicates a wildcard key usage policy, which permits the MAC algorithm with a MAC length of at least LEN to be specified in a MAC operation using the key. LEN must not be zero.

H = HASH-TYPE (see :numref:`table-hash-type`) for hash-based MAC algorithms, otherwise H = 0.

.. csv-table:: MAC algorithm sub-type values
    :name: table-mac-type
    :header-rows: 1
    :align: left
    :widths: auto

    MAC algorithm, B, MAC-TYPE, Algorithm identifier, Algorithm value
    HMAC, 0, ``0x00``, :code:`PSA_ALG_HMAC(hash_alg)`, ``0x038000hh`` :sup:`a b`
    CBC-MAC :sup:`c`, 1, ``0x01``, `PSA_ALG_CBC_MAC`, ``0x03c00100`` :sup:`a`
    CMAC :sup:`c`, 1, ``0x02``, `PSA_ALG_CMAC`, ``0x03c00200`` :sup:`a`

a.  This is the default algorithm identifier, specifying a standard length tag. `PSA_ALG_TRUNCATED_MAC()` generates identifiers with non-default LEN values. `PSA_ALG_AT_LEAST_THIS_LENGTH_MAC()` generates permitted-algorithm policies with W = 1.

b.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash_alg``, used to construct the MAC algorithm.

c.  This is a MAC constructed using an underlying block cipher. The block cipher is determined by the key type that is provided to the MAC operation.

.. _cipher-encoding:

Cipher algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for CIPHER algorithms defined in this specification are encoded as shown in :numref:`fig-cipher-fields`.

.. figure:: ../figure/encoding/cipher.*
    :name: fig-cipher-fields

    CIPHER algorithm encoding

The defined values for S, B, and CIPHER-TYPE are shown in :numref:`table-cipher-type`.

.. csv-table:: Cipher algorithm sub-type values
    :name: table-cipher-type
    :header-rows: 1
    :align: left
    :widths: auto

    Cipher algorithm, S, B, CIPHER-TYPE, Algorithm identifier, Algorithm value
    *Stream cipher* :sup:`a`, 1, 0, ``0x01``, `PSA_ALG_STREAM_CIPHER`, ``0x04800100``
    CTR mode :sup:`b`, 1, 1, ``0x10``, `PSA_ALG_CTR`, ``0x04C01000``
    CFB mode :sup:`b`, 1, 1, ``0x11``, `PSA_ALG_CFB`, ``0x04C01100``
    OFB mode :sup:`b`, 1, 1, ``0x12``, `PSA_ALG_OFB`, ``0x04C01200``
    CCM* with zero-length tag :sup:`b`, 1, 1, ``0x13``, `PSA_ALG_CCM_STAR_NO_TAG`, ``0x04C01300``
    *CCM\* wildcard* :sup:`c`, 1, 1, ``0x93``, `PSA_ALG_CCM_STAR_ANY_TAG`, ``0x04c09300``
    XTS mode :sup:`b`, 0, 1, ``0xFF``, `PSA_ALG_XTS`, ``0x0440FF00``
    CBC mode without padding :sup:`b`, 0, 1, ``0x40``, `PSA_ALG_CBC_NO_PADDING`, ``0x04404000``
    CBC mode with PKCS#7 padding :sup:`b`, 0, 1, ``0x41``, `PSA_ALG_CBC_PKCS7`, ``0x04404100``
    ECB mode without padding :sup:`b`, 0, 1, ``0x44``, `PSA_ALG_ECB_NO_PADDING`, ``0x04404400``

a.  The stream cipher algorithm identifier `PSA_ALG_STREAM_CIPHER` is used with specific stream cipher key types, such as `PSA_KEY_TYPE_CHACHA20`.

b.  This is a cipher mode of an underlying block cipher. The block cipher is determined by the key type that is provided to the cipher operation.

c.  The wildcard algorithm `PSA_ALG_CCM_STAR_ANY_TAG` permits a key to be used with any CCM\* algorithm: unauthenticated cipher `PSA_ALG_CCM_STAR_NO_TAG`, and AEAD algorithm `PSA_ALG_CCM`.

.. _aead-encoding:

AEAD algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for AEAD algorithms defined in this specification are encoded as shown in :numref:`fig-aead-fields`.

.. figure:: ../figure/encoding/aead.*
    :name: fig-aead-fields

    AEAD algorithm encoding

The defined values for B and AEAD-TYPE are shown in :numref:`table-aead-type`.

LEN = 1..31 specifies the output tag length.

W is a flag to indicate a wildcard permitted-algorithm policy:

*   W = 0 indicates a specific AEAD algorithm and tag length.
*   W = 1 indicates a wildcard key usage policy, which permits the AEAD algorithm with a tag length of at least LEN to be specified in an AEAD operation using the key.

.. csv-table:: AEAD algorithm sub-type values
    :name: table-aead-type
    :header-rows: 1
    :align: left
    :widths: auto

    AEAD algorithm, B, AEAD-TYPE, Algorithm identifier, Algorithm value
    CCM :sup:`a`, 1, ``0x01``, `PSA_ALG_CCM`, ``0x05500100`` :sup:`b`
    GCM :sup:`a`, 1, ``0x02``, `PSA_ALG_GCM`, ``0x05500200`` :sup:`b`
    ChaCha20-Poly1305, 0, ``0x05``, `PSA_ALG_CHACHA20_POLY1305`, ``0x05100500`` :sup:`b`
    XChaCha20-Poly1305, 0, ``0x06``, `PSA_ALG_XCHACHA20_POLY1305`, ``0x05100600`` :sup:`b`

a.  This is an AEAD mode of an underlying block cipher. The block cipher is determined by the key type that is provided to the AEAD operation.

b.  This is the default algorithm identifier, specifying the default tag length for the algorithm. `PSA_ALG_AEAD_WITH_SHORTENED_TAG()` generates identifiers with alternative LEN values. `PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG()` generates wildcard permitted-algorithm policies with W = 1.

.. _kdf-encoding:

Key-derivation algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for key-derivation algorithms defined in this specification are encoded as shown in :numref:`fig-kdf-fields`.

.. figure:: ../figure/encoding/kdf.*
    :name: fig-kdf-fields

    Key-derivation algorithm encoding

The defined values for S and KDF-TYPE are shown in :numref:`table-kdf-type`.

The permitted values of HASH-TYPE (see :numref:`table-hash-type`) depend on the specific KDF algorithm.

.. csv-table:: Key-derivation algorithm sub-type values
    :name: table-kdf-type
    :header-rows: 1
    :align: left
    :widths: auto

    Key-derivation algorithm, S, KDF-TYPE, Algorithm identifier, Algorithm value
    HKDF, 0, ``0x01``, :code:`PSA_ALG_HKDF(hash)`, ``0x080001hh`` :sup:`a`
    TLS-1.2 PRF, 0, ``0x02``, :code:`PSA_ALG_TLS12_PRF(hash)`, ``0x080002hh`` :sup:`a`
    TLS-1.2 PSK-to-MasterSecret, 0, ``0x03``, :code:`PSA_ALG_TLS12_PSK_TO_MS(hash)`, ``0x080003hh`` :sup:`a`
    HKDF-Extract, 0, ``0x04``, :code:`PSA_ALG_HKDF_EXTRACT(hash)`, ``0x080004hh`` :sup:`a`
    HKDF-Expand, 0, ``0x05``, :code:`PSA_ALG_HKDF_EXPAND(hash)`, ``0x080005hh`` :sup:`a`
    TLS 1.2 ECJPAKE-to-PMS, 0, ``0x06``, :code:`PSA_ALG_TLS12_ECJPAKE_TO_PMS`, ``0x08000609``
    SP 800-108 Counter HMAC, 0, ``0x07``, :code:`PSA_ALG_SP800_108_COUNTER_HMAC(hash)`, ``0x080007hh`` :sup:`a`
    SP 800-108 Counter CMAC, 0, ``0x08``, :code:`PSA_ALG_SP800_108_COUNTER_CMAC`, ``0x08000800``
    PBKDF2-HMAC, 1, ``0x01``, :code:`PSA_ALG_PBKDF2_HMAC(hash)`, ``0x088001hh`` :sup:`a`
    PBKDF2-AES-CMAC-PRF-128, 1, ``0x02``, :code:`PSA_ALG_PBKDF2_AES_CMAC_PRF_128`, ``0x08800200``

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash``, used to construct the key-derivation algorithm.

.. _sign-encoding:

Asymmetric signature algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for asymmetric signature algorithms defined in this specification are encoded as shown in :numref:`fig-sign-fields`.

.. figure:: ../figure/encoding/sign.*
    :name: fig-sign-fields

    Asymmetric signature algorithm encoding

The defined values for SIGN-TYPE are shown in :numref:`table-sign-type`.

H = HASH-TYPE (see :numref:`table-hash-type`) for message signature algorithms that are parameterized by a hash algorithm, otherwise H = 0.

.. csv-table:: Asymmetric signature algorithm sub-type values
    :name: table-sign-type
    :header-rows: 1
    :align: left
    :widths: auto

    Signature algorithm, SIGN-TYPE, Algorithm identifier, Algorithm value
    RSA PKCS#1 v1.5, ``0x02``, :code:`PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)`, ``0x060002hh`` :sup:`a`
    RSA PKCS#1 v1.5 no hash :sup:`b`, ``0x02``, `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`, ``0x06000200``
    RSA PSS, ``0x03``, :code:`PSA_ALG_RSA_PSS(hash_alg)`, ``0x060003hh`` :sup:`a`
    RSA PSS any salt length, ``0x13``, :code:`PSA_ALG_RSA_PSS_ANY_SALT(hash_alg)`, ``0x060013hh`` :sup:`a`
    Randomized ECDSA, ``0x06``, :code:`PSA_ALG_ECDSA(hash_alg)`, ``0x060006hh`` :sup:`a`
    Randomized ECDSA no hash :sup:`b`, ``0x06``, `PSA_ALG_ECDSA_ANY`, ``0x06000600``
    Deterministic ECDSA, ``0x07``, :code:`PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)`, ``0x060007hh`` :sup:`a`
    PureEdDSA, ``0x08``, `PSA_ALG_PURE_EDDSA`, ``0x06000800``
    HashEdDSA, ``0x09``, `PSA_ALG_ED25519PH` and `PSA_ALG_ED448PH`, ``0x060009hh`` :sup:`c`

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash_alg``, used to construct the signature algorithm.

b.  Asymmetric signature algorithms without hashing can only be used with `psa_sign_hash()` and `psa_verify_hash()`.

c.  The HASH-TYPE for HashEdDSA is determined by the curve. SHA-512 is used for Ed25519ph, and the first 64 bytes of output from SHAKE256 is used for Ed448ph.

.. _pke-encoding:

Asymmetric encryption algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for asymmetric encryption algorithms defined in this specification are encoded as shown in :numref:`fig-pke-fields`.

.. figure:: ../figure/encoding/pke.*
    :name: fig-pke-fields

    Asymmetric encryption algorithm encoding

The defined values for ENCRYPT-TYPE are shown in :numref:`table-pke-type`.

H = HASH-TYPE (see :numref:`table-hash-type`) for asymmetric encryption algorithms that are parameterized by a hash algorithm, otherwise H = 0.

.. csv-table:: Asymmetric encryption algorithm sub-type values
    :name: table-pke-type
    :header-rows: 1
    :align: left
    :widths: auto

    Asymmetric encryption algorithm, ENCRYPT-TYPE, Algorithm identifier, Algorithm value
    RSA PKCS#1 v1.5, ``0x02``, `PSA_ALG_RSA_PKCS1V15_CRYPT`, ``0x07000200``
    RSA OAEP, ``0x03``, :code:`PSA_ALG_RSA_OAEP(hash_alg)`, ``0x070003hh`` :sup:`a`

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash_alg``, used to construct the encryption algorithm.

.. _ka-encoding:

key-agreement algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A key-agreement algorithm identifier can either be for the standalone key-agreement algorithm, or for a combined key-agreement with key-derivation algorithm. The former can only be used with `psa_key_agreement()` and `psa_raw_key_agreement()`, while the latter are used with `psa_key_derivation_key_agreement()`.

The algorithm identifier for standalone key-agreement algorithms defined in this specification are encoded as shown in :numref:`fig-ka-raw-fields`.

.. figure:: ../figure/encoding/ka_raw.*
    :name: fig-ka-raw-fields

    Standalone key-agreement algorithm encoding

The defined values for KA-TYPE are shown in :numref:`table-ka-type`.

.. csv-table:: Key-agreement algorithm sub-type values
    :name: table-ka-type
    :header-rows: 1
    :align: left
    :widths: auto

    Key-agreement algorithm, KA-TYPE, Algorithm identifier, Algorithm value
    FFDH, ``0x01``, `PSA_ALG_FFDH`, ``0x09010000``
    ECDH, ``0x02``, `PSA_ALG_ECDH`, ``0x09020000``

A combined key agreement is constructed by a bitwise OR of the standalone key-agreement algorithm identifier and the key-derivation algorithm identifier. This operation is provided by the `PSA_ALG_KEY_AGREEMENT()` macro.

.. figure:: ../figure/encoding/ka_combined.*

    Combined key-agreement algorithm encoding

The underlying standalone key-agreement algorithm can be extracted from the KA-TYPE field, and the key-derivation algorithm from the KDF-TYPE and HASH-TYPE fields.

.. _key-encapsulation-encoding:

Key-encapsulation algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for key-encapsulation algorithms defined in this specification are encoded as shown in :numref:`fig-key-encapsulation-encoding`.

.. figure:: /figure/encoding/kem_encoding.*
    :name: fig-key-encapsulation-encoding

    Encapsulation algorithm encoding

The defined values for ENCAPS-TYPE are shown in :numref:`table-key-encapsulation-type`.

.. csv-table:: Encapsulation algorithm sub-type values
    :name: table-key-encapsulation-type
    :header-rows: 1
    :align: left
    :widths: auto

    Encapsulation algorithm, ENCAPS-TYPE, Algorithm identifier, Algorithm value
    ECIES (SEC1), ``0x01``, `PSA_ALG_ECIES_SEC1`, ``0x0C000100``

.. _pake-encoding:

PAKE algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for PAKE algorithms defined in this specification are encoded as shown in :numref:`fig-pake-encoding`.

.. figure:: /figure/encoding/pake_encoding.*
    :name: fig-pake-encoding

    PAKE algorithm encoding

The defined values for PAKE-TYPE are shown in :numref:`table-pake-type`.

The permitted values of HASH-TYPE (see :numref:`table-hash-type`) depend on the specific PAKE algorithm.

.. csv-table:: PAKE algorithm sub-type values
    :name: table-pake-type
    :header-rows: 1
    :align: left
    :widths: auto

    PAKE algorithm, PAKE-TYPE, Algorithm identifier, Algorithm value
    J-PAKE, ``0x01``, :code:`PSA_ALG_JPAKE(hash)`, ``0x0A0001hh`` :sup:`a`
    SPAKE2+ with HMAC, ``0x04``, :code:`PSA_ALG_SPAKE2P_HMAC(hash)`, ``0x0A0004hh`` :sup:`a`
    SPAKE2+ with CMAC, ``0x05``, :code:`PSA_ALG_SPAKE2P_CMAC(hash)`, ``0x0A0005hh`` :sup:`a`
    SPAKE2+ for Matter, ``0x06``, :code:`PSA_ALG_SPAKE2P_MATTER`, ``0x0A000609``

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash``, used to construct the key-derivation algorithm.

.. _key-type-encoding:

Key type encoding
-----------------

Key types are 16-bit integer values of the type `psa_key_type_t`. Key type values have the structure shown in :numref:`fig-key-type-fields`.

.. figure:: ../figure/encoding/key_type.*
    :name: fig-key-type-fields

    Encoding of `psa_key_type_t`

:numref:`table-key-type-fields` describes the meaning of the bit-fields --- some of bit-fields are used in different ways by different key type categories.

.. list-table:: Bit fields in a key type
    :name: table-key-type-fields
    :header-rows: 1
    :widths: 5,2,14

    *   -   Field
        -   Bits
        -   Description
    *   -   V
        -   [15]
        -   Flag to indicate an implementation-defined key type, when V=1.

            Key types defined by this specification always have V=0.
    *   -   A
        -   [14]
        -   Flag to indicate an asymmetric key type, when A=1.
    *   -   CAT
        -   [13:12]
        -   Key type category. See :secref:`key-type-categories`.
    *   -   *category-specific type*
        -   [11:1]
        -   The meaning of this field is specific to each key category.
    *   -   P
        -   [0]
        -   Parity bit. Valid key type values have even parity.

.. rationale::

    Key types have a parity bit to ensure that a valid key type differs from another valid key type by at least two bits. This increases the difficultly of deliberately or accidentally corrupting a key type value into another one.

    Key type values are used by an implementation to determine how the key data is interpreted --- this design makes implementations less vulnerable to fault or glitch attacks.

.. _key-type-categories:

Key type categories
~~~~~~~~~~~~~~~~~~~

The A and CAT fields in a key type take the values shown in :numref:`table-key-type-category`.

.. csv-table:: Key type categories
    :name: table-key-type-category
    :header-rows: 1
    :align: left
    :widths: auto

    Key type category, A, CAT, Category details
    None, 0, 0, See `PSA_KEY_TYPE_NONE`
    Raw data, 0, 1, See :secref:`raw-key-encoding`
    Symmetric key, 0, 2, See :secref:`symmetric-key-encoding`
    Structured key, 0, 3, See :secref:`structured-key-encoding`
    Asymmetric public key, 1, 0, See :secref:`asymmetric-key-encoding`
    Asymmetric key pair, 1, 3, See :secref:`asymmetric-key-encoding`

.. _raw-key-encoding:

Raw key encoding
~~~~~~~~~~~~~~~~

The key type for raw keys defined in this specification are encoded as shown in :numref:`fig-raw-key-fields`.

.. figure:: ../figure/encoding/raw_key.*
    :name: fig-raw-key-fields

    Raw key encoding

The defined values for RAW-TYPE, SUB-TYPE, and P are shown in :numref:`table-raw-type`.

.. csv-table:: Raw key sub-type values
    :name: table-raw-type
    :header-rows: 1
    :align: left
    :widths: auto

    Raw key type, RAW-TYPE, SUB-TYPE, P, Key type, Key type value
    Raw data, 0, 0, 1, `PSA_KEY_TYPE_RAW_DATA`, ``0x1001``
    HMAC, 1, 0, 0, `PSA_KEY_TYPE_HMAC`, ``0x1100``
    Derivation secret, 2, 0, 0, `PSA_KEY_TYPE_DERIVE`, ``0x1200``
    Password, 2, 1, 1, `PSA_KEY_TYPE_PASSWORD`, ``0x1203``
    Password hash, 2, 2, 1, `PSA_KEY_TYPE_PASSWORD_HASH`, ``0x1205``
    Derivation pepper, 2, 3, 0, `PSA_KEY_TYPE_PEPPER`, ``0x1206``

.. _symmetric-key-encoding:

Symmetric key encoding
~~~~~~~~~~~~~~~~~~~~~~

The key type for symmetric keys defined in this specification are encoded as shown in :numref:`fig-symmetric-key-fields`.

.. figure:: ../figure/encoding/symmetric_key.*
    :name: fig-symmetric-key-fields

    Symmetric key encoding

For block-based cipher keys, the block size for the cipher algorithm is 2\ :sup:`BLK`.

The defined values for BLK, SYM-TYPE and P are shown in :numref:`table-symmetric-type`.

.. csv-table:: Symmetric key sub-type values
    :name: table-symmetric-type
    :header-rows: 1
    :align: left
    :widths: auto

    Symmetric key type, BLK, SYM-TYPE, P, Key type, Key type value
    ARC4, 0, 1, 0, `PSA_KEY_TYPE_ARC4`, ``0x2002``
    ChaCha20, 0, 2, 0, `PSA_KEY_TYPE_CHACHA20`, ``0x2004``
    XChaCha20, 0, 3, 1, `PSA_KEY_TYPE_XCHACHA20`, ``0x2007``
    DES, 3, 0, 1, `PSA_KEY_TYPE_DES`, ``0x2301``
    AES, 4, 0, 0, `PSA_KEY_TYPE_AES`, ``0x2400``
    CAMELLIA, 4, 1, 1, `PSA_KEY_TYPE_CAMELLIA`, ``0x2403``
    SM4, 4, 2, 1, `PSA_KEY_TYPE_SM4`, ``0x2405``
    ARIA, 4, 3, 0, `PSA_KEY_TYPE_ARIA`, ``0x2406``


Structured key encoding
~~~~~~~~~~~~~~~~~~~~~~~

The key type for structured keys defined in this specification are encoded as shown in :numref:`fig-structured-key-fields`.

.. figure:: ../figure/encoding/structured_key.*
    :name: fig-structured-key-fields

    Encoding of structured keys

The defined values for STRUCT-TYPE are shown in :numref:`table-structured-type`.

The defined values for FAMILY depend on the STRUCT-TYPE value. See the details for each structured key sub-type.

.. csv-table:: Structured key sub-type values
    :name: table-structured-type
    :header-rows: 1
    :align: left
    :widths: auto

    Structured key type, STRUCT-TYPE, Details
    WPA3-SAE password token, "0, 1", See :secref:`wpa3-sae-key-encoding`

.. _wpa3-sae-key-encoding:

WPA3-SAE password token encoding
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

WPA3-SAE can use either elliptic curve or Diffie-Hellman cipher suites.
These use distinct STRUCT-TYPE values, and use the same FAMILY values as elliptic curve and Diffie-Hellman key types.

.. rubric:: WPA3-SAE password tokens using elliptic curves

The key type for WPA3-SAE password tokens using elliptic curves defined in this specification are encoded as shown in :numref:`fig-wpa3-sae-ecc-fields`.

.. figure:: ../figure/encoding/wpa3_sae_ecc_key.*
    :name: fig-wpa3-sae-ecc-fields

    Encoding of WPA3-SAE password token using elliptic curves

The defined values for ECC-FAMILY and P are shown in :numref:`table-wpa3-sae-ecc-type`.

.. csv-table:: WPA3-SAE password token ECC family values
    :name: table-wpa3-sae-ecc-type
    :header-rows: 1
    :align: left
    :widths: auto

    WPA3-SAE suite, ECC-FAMILY, P, ECC family :sup:`a`, Key value
    SECP R1, 0x09, 0, `PSA_ECC_FAMILY_SECP_R1`, ``0x3292``
    Brainpool-P R1, 0x18, 0, `PSA_ECC_FAMILY_BRAINPOOL_P_R1`, ``0x32b0``

a.  The elliptic curve family values defined in the API also include the parity bit. The password token key type value is constructed from the elliptic curve family using :code:`PSA_KEY_TYPE_WPA3_SAE_ECC_PT(family)`.

.. rubric:: WPA3-SAE password tokens using finite fields

The key type for WPA3-SAE password tokens using finite fields defined in this specification are encoded as shown in :numref:`fig-wpa3-sae-dh-fields`.

.. figure:: ../figure/encoding/wpa3_sae_dh_key.*
    :name: fig-wpa3-sae-dh-fields

    Encoding of WPA3-SAE password token using finite fields

The defined values for DH-FAMILY and P are shown in :numref:`table-wpa3-sae-dh-type`.

RFC3526 defines a set of FF groups that are recommended for use with WPA3-SAE (those with primes >=3072 bits)

.. csv-table:: WPA3-SAE password token Diffie-Hellman family values
    :name: table-wpa3-sae-dh-type
    :header-rows: 1
    :align: left
    :widths: auto

    WPA3-SAE suite, DH-FAMILY, P, DH family :sup:`a`, Key value
    RFC3526, 0x02, 1, `PSA_DH_FAMILY_RFC3526`, ``0x3305``

a.  The Diffie Hellman family values defined in the API also include the parity bit. The password token key type value is constructed from the Diffie Hellman family using :code:`PSA_KEY_TYPE_WPA3_SAE_DH_PT(family)`.

.. _asymmetric-key-encoding:

Asymmetric key encoding
~~~~~~~~~~~~~~~~~~~~~~~

The key type for asymmetric keys defined in this specification are encoded as shown in :numref:`fig-asymmetric-key-fields`.

.. figure:: ../figure/encoding/asymmetric_key.*
    :name: fig-asymmetric-key-fields

    Asymmetric key encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for ASYM-TYPE are shown in :numref:`table-asymmetric-type`.

The defined values for FAMILY depend on the ASYM-TYPE value. See the details for each asymmetric key sub-type.

.. csv-table:: Asymmetric key sub-type values
    :name: table-asymmetric-type
    :header-rows: 1
    :align: left
    :widths: auto

    Asymmetric key type, ASYM-TYPE, Details
    Non-parameterized, 0, See :secref:`simple-asymmetric-key-encoding`
    Elliptic Curve, 2, See :secref:`ecc-key-encoding`
    Diffie-Hellman, 4, See :secref:`dh-key-encoding`
    SPAKE2+, 8, See :secref:`spakep2-key-encoding`

.. _simple-asymmetric-key-encoding:

Non-parameterized asymmetric key encoding
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The key type for non-parameterized asymmetric keys defined in this specification are encoded as shown in :numref:`fig-np-key-fields`.

.. figure:: ../figure/encoding/np_key.*
    :name: fig-np-key-fields

    Non-parameterized asymmetric keys encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for NP-FAMILY and P are shown in :numref:`table-np-type`.

.. csv-table:: Non-parameterized asymmetric key family values
    :name: table-np-type
    :header-rows: 1
    :align: left
    :widths: auto

    Key family, Public/pair, PAIR, NP-FAMILY, P, Key type, Key value
    RSA, Public key, 0, 0, 1, `PSA_KEY_TYPE_RSA_PUBLIC_KEY`, ``0x4001``
    , Key pair, 3, 0, 1, `PSA_KEY_TYPE_RSA_KEY_PAIR`, ``0x7001``

.. _ecc-key-encoding:

Elliptic curve key encoding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The key type for elliptic curve keys defined in this specification are encoded as shown in :numref:`fig-ecc-key-fields`.

.. figure:: ../figure/encoding/ecc_key.*
    :name: fig-ecc-key-fields

    Elliptic curve key encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for ECC-FAMILY and P are shown in :numref:`table-ecc-type`.

.. csv-table:: ECC key family values
    :name: table-ecc-type
    :header-rows: 1
    :align: left
    :widths: auto

    ECC key family, ECC-FAMILY, P, ECC family :sup:`a`, Public-key value, Key-pair value
    SECP K1, 0x0B, 1, `PSA_ECC_FAMILY_SECP_K1`, ``0x4117``, ``0x7117``
    SECP R1, 0x09, 0, `PSA_ECC_FAMILY_SECP_R1`, ``0x4112``, ``0x7112``
    SECP R2, 0x0D, 1, `PSA_ECC_FAMILY_SECP_R2`, ``0x411B``, ``0x711B``
    SECT K1, 0x13, 1, `PSA_ECC_FAMILY_SECT_K1`, ``0x4127``, ``0x7127``
    SECT R1, 0x11, 0, `PSA_ECC_FAMILY_SECT_R1`, ``0x4122``, ``0x7122``
    SECT R2, 0x15, 1, `PSA_ECC_FAMILY_SECT_R2`, ``0x412B``, ``0x712B``
    Brainpool-P R1, 0x18, 0, `PSA_ECC_FAMILY_BRAINPOOL_P_R1`, ``0x4130``, ``0x7130``
    FRP, 0x19, 1, `PSA_ECC_FAMILY_FRP`, ``0x4133``, ``0x7133``
    Montgomery, 0x20, 1, `PSA_ECC_FAMILY_MONTGOMERY`, ``0x4141``, ``0x7141``
    Twisted Edwards, 0x21, 0, `PSA_ECC_FAMILY_TWISTED_EDWARDS`, ``0x4142``, ``0x7142``

a.  The elliptic curve family values defined in the API also include the parity bit. The key type value is constructed from the elliptic curve family using either :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(family)` or :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)` as required.

.. _dh-key-encoding:

Diffie Hellman key encoding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The key type for Diffie Hellman keys defined in this specification are encoded as shown in :numref:`fig-dh-key-fields`.

.. figure:: ../figure/encoding/dh_key.*
    :name: fig-dh-key-fields

    Diffie Hellman key encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for DH-FAMILY and P are shown in :numref:`table-dh-type`.

.. csv-table:: Diffie Hellman key group values
    :name: table-dh-type
    :header-rows: 1
    :align: left
    :widths: auto

    DH key group, DH-FAMILY, P, DH group :sup:`a`, Public-key value, Key-pair value
    RFC7919, 0x01, 1, `PSA_DH_FAMILY_RFC7919`, ``0x4203``, ``0x7203``

a.  The Diffie Hellman family values defined in the API also include the parity bit. The key type value is constructed from the Diffie Hellman family using either :code:`PSA_KEY_TYPE_DH_PUBLIC_KEY(family)` or :code:`PSA_KEY_TYPE_DH_KEY_PAIR(family)` as required.

.. _spakep2-key-encoding:

SPAKE2+ key encoding
^^^^^^^^^^^^^^^^^^^^

The key type for SPAKE2+ keys defined in this specification are encoded as shown in :numref:`fig-spake2p-key-fields`.

.. figure:: ../figure/encoding/spake2p_key.*
    :name: fig-spake2p-key-fields

    SPAKE2+ key encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for ECC-FAMILY and P are shown in :numref:`table-spake2p-type`.

.. csv-table:: SPAKE2+ key family values
    :name: table-spake2p-type
    :header-rows: 1
    :align: left
    :widths: auto

    SPAKE2+ group, ECC-FAMILY, P, ECC family :sup:`a`, Public-key value, Key-pair value
    SECP R1, 0x09, 0, :code:`PSA_ECC_FAMILY_SECP_R1`, ``0x4412``, ``0x7412``
    Twisted Edwards, 0x21, 0, :code:`PSA_ECC_FAMILY_TWISTED_EDWARDS`, ``0x4442``, ``0x7442``

a.  The elliptic curve family values defined in the API also include the parity bit.
    The key type value is constructed from the elliptic curve family using either :code:`PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(family)` or :code:`PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(family)` as required.
