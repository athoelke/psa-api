.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 29

.. _key-encapsulation:

Key encapsulation
=================

A key-encapsulation algorithm can be used by two participants to establish a shared secret key over a public channel.
The shared secret key can then be used with symmetric-key cryptographic algorithms.
Key-encapsulation algorithms are often referred to as 'key encapsulation mechanisms' or KEMs.

In a key-encapsulation algorithm, one participant generates a key-pair: a private decapsulation key, and a public encapsulation key.
The public encapsulation key is made available to a second participant that needs to establish secure communication with the first participant.
The second participant uses the encapsulation key to generate one copy of a shared secret, and some associated encapsulation data.
The encapsulation data is transferred to the first participant, who uses the private decapsulation key to compute another copy of the shared secret.

Typically, the shared secret is used as input to a key-derivation function, to create keys for secure communication between the participants.
However, some key-encapsulation algorithms result in a pseudo-random shared secret, which is suitable to be used directly as a cryptographic key.

Applications can use the resulting keys for different use cases.
For example:

*   Encrypting and authenticating a single non-interactive message.
*   Securing an interactive communication channel.

.. _key-encapsulation-algorithms:

Elliptic Curve Integrated Encryption Scheme
-------------------------------------------

The Elliptic Curve Integrated Encryption Scheme (ECIES) was first proposed by Shoup, then improved by Ballare and Rogaway.

The original specification permitted a number of variants.
The |API| uses the version specified in :cite-title:`SEC1`.

The full ECIES scheme uses an elliptic-curve key agreement between the recipient's static public key and an ephemeral private key, to establish encryption and authentication keys for secure transmission of arbitrary-length messages to the recipient.

An application using ECIES must select all of the following parameters:

*   The elliptic curve for the initial key agreement.
*   The KDF to derive the symmetric keys, and any label used in that derivation.
*   The encryption and MAC algorithms.
*   The additional data to include when computing the authentication.

The |API| presents the key-agreement step of ECIES as a key-encapsulation algorithm.
The key derivation, encryption, and authentication steps are left to the application.

.. rationale::

    Although it is possible to implement this in an application using key generation and key agreement, using the key-encapsulation functions enables an easy migration to other key-encapsulation algorithms, such as ML-KEM.

.. admonition:: Implementation note

    It is possible that some applications may need to use alternative versions of ECIES to interoperate with legacy systems.

    While the application can implement this using key agreement functions, an implementation can choose to add these as a convenience with an :scterm:`implementation defined` key-encapsulation algorithm identifier.

.. macro:: PSA_ALG_ECIES_SEC1
    :definition: ((psa_algorithm_t)0x0b000100)

    .. summary::
        The Elliptic Curve Integrated Encryption Scheme (ECIES).

    This key-encapsulation algorithm is defined by :cite-title:`SEC1` §5.1 under the name Elliptic Curve Integrated Encryption Scheme.

    A call to `psa_encapsulate()` carries out steps 1 to 4 of the ECIES encryption process described in `[SEC1]` §5.1.3:

    *   The elliptic curve to use is determined by the key.
    *   The public key part of the input key is used as :math:`Q_V`.
    *   Cofactor ECDH is used to perform the key agreement.
    *   The shared secret :math:`Z` is output as the shared output key.
    *   The ephemeral public key :math:`\overline{R}` is output as the encapsulation data.

    A call to `psa_decapsulate()` carries out steps 2 to 5 of the ECIES decryption process described in `[SEC1]` §5.1.4:

    *   The elliptic curve to use is determined by the key.
    *   The encapsulation data is decoded as :math:`\overline{R}`.
    *   The private key of the input key is used as :math:`d_V`.
    *   Cofactor ECDH is used to perform the key agreement.
    *   The shared secret :math:`Z` is output as the shared output key.

    The encapsulation provided by `PSA_ALG_ECIES_SEC1` is not authenticated.
    When used in a full ECIES scheme, the authentication of the encrypted message implicitly confirms that the derived keys were identical.

    The shared output key that is produced by `PSA_ALG_ECIES_SEC1` is not suitable for use as an encryption key.
    It must be used as an input to a key derivation operation to produce additional cryptographic keys.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)`

        where ``family`` is a Weierstrass or Montgomery Elliptic curve family.
        That is, one of the following values:

        *   ``PSA_ECC_FAMILY_SECT_XX``
        *   ``PSA_ECC_FAMILY_SECP_XX``
        *   `PSA_ECC_FAMILY_FRP`
        *   `PSA_ECC_FAMILY_BRAINPOOL_P_R1`
        *   `PSA_ECC_FAMILY_MONTGOMERY`

Key-encapsulation functions
---------------------------

.. function:: psa_encapsulate

    .. summary::
        Use a public key to generate a new shared secret key and associated encapsulation data.

    .. param:: psa_key_id_t key
        Identifier of the key to use for the encapsulation.
        It must be a public key or an asymmetric key pair.
        It must permit the usage `PSA_KEY_USAGE_ENCAPSULATE`.
    .. param:: psa_algorithm_t alg
        The key-encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.
    .. param:: const psa_key_attributes_t * attributes
        The attributes for the output key.
        This function uses the attributes as follows:

        *   The key type.
            All key-encapsulation algorithms can output a key of type :code:`PSA_KEY_TYPE_DERIVE` or :code:`PSA_KEY_TYPE_HMAC`.
            Key-encapsulation algorithms that produce a pseudo-random shared secret, can also output block-cipher key types, for example :code:`PSA_KEY_TYPE_AES`.
            Refer to the documentation of individual key-encapsulation algorithms for more information.

        The following attributes must be set for keys used in cryptographic operations:

        *   The key permitted-algorithm policy, see :secref:`permitted-algorithms`.
        *   The key usage flags, see :secref:`key-usage-flags`.

        The following attributes must be set for keys that do not use the default volatile lifetime:

        *   The key lifetime, see :secref:`key-lifetimes`.
        *   The key identifier is required for a key with a persistent lifetime, see :secref:`key-identifiers`.

        The following attributes are optional:

        *   If the key size is nonzero, it must be equal to the size of the shared secret.

        .. note::
            This is an input parameter: it is not updated with the final key attributes.
            The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.
    .. param:: psa_key_id_t * output_key
        On success, an identifier for the newly created shared output key.
        `PSA_KEY_ID_NULL` on failure.
    .. param:: uint8_t * encapsulation
        Buffer where the encapsulated data is to be written.
    .. param:: size_t encapsulation_size
        Size of the ``encapsulation`` buffer in bytes.
        This must be appropriate for the selected algorithm and key:

        *   A sufficient output size is :code:`PSA_ENCAPSULATION_SIZE(type, bits, alg)`, where ``type`` and ``bits`` are the type and bit-size of ``key``.
        *   `PSA_ENCAPSULATION_MAX_SIZE` evaluates to the maximum output size of any supported key-encapsulation algorithm.
    .. param:: size_t * encapsulation_length
        On success, the number of bytes that make up the encapsulated data value.

    .. return:: psa_status_t

    .. retval:: PSA_SUCCESS
        Success.
        The bytes of ``encapsulation`` contain the data to be sent to the other participant and ``output_key`` contains the identifier for the shared output key.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not a key-encapsulation algorithm.
        *   ``key`` is not supported for use with ``alg``.
        *   The output key attributes, as a whole, are not supported, either by the implementation in general or in the specified storage location.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not a key-encapsulation algorithm.
        *   ``key`` is not a public key or an asymmetric key pair, that is compatible with ``alg``.
        *   The output key attributes in ``attributes`` are not valid:

            -   The key type is not valid for the shared output key.
            -   The key size is nonzero, and is not the size of the shared output.
            -   The key lifetime is invalid.
            -   The key identifier is not valid for the key lifetime.
            -   The key usage flags include invalid values.
            -   The key's permitted-usage algorithm is invalid.
            -   The key attributes, as a whole, are invalid.
    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``encapsulation`` buffer is too small.
        `PSA_ENCAPSULATION_SIZE()` or `PSA_ENCAPSULATION_MAX_SIZE` can be used to determine a sufficient buffer size.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    The ``output_key`` location, policy, and type are taken from ``attributes``.

    The size of the returned key is always the bit-size of the shared secret, rounded up to a whole number of bytes.
    The size of the shared secret is dependent on the key-encapsulation algorithm and the type and size of ``key``.

    It is recommended that this key is used as an input to a key derivation operation to produce additional cryptographic keys.
    For some key-encapsulation algorithms, the shared secret is also suitable for use as a key in cryptographic operations such as encryption.
    Refer to the documentation of individual key-encapsulation algorithms for more information.

    The ``encapsulation`` data is sent to the other participant, who uses the decapsulation key to extract another copy of the shared secret key.

.. function:: psa_decapsulate

    .. summary::
        Use a private key to decapsulate a shared secret key from encapsulation data.

    .. param:: psa_key_id_t key
        Identifier of the key to use for the decapsulation.
        It must be an asymmetric key pair.
        It must permit the usage `PSA_KEY_USAGE_DECAPSULATE`.
    .. param:: psa_algorithm_t alg
        The key-encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.
    .. param:: const uint8_t * encapsulation
        The encapsulation data received from the other participant.
    .. param:: size_t encapsulation_length
        Size of the ``encapsulation`` buffer in bytes.
    .. param:: const psa_key_attributes_t * attributes
        The attributes for the output key.
        This function uses the attributes as follows:

        *   The key type.
            All key-encapsulation algorithms can output a key of type :code:`PSA_KEY_TYPE_DERIVE` or :code:`PSA_KEY_TYPE_HMAC`.
            Key-encapsulation algorithms that produce a pseudo-random shared secret, can also output block-cipher key types, for example :code:`PSA_KEY_TYPE_AES`.
            Refer to the documentation of individual key-encapsulation algorithms for more information.

        The following attributes must be set for keys used in cryptographic operations:

        *   The key permitted-algorithm policy, see :secref:`permitted-algorithms`.
        *   The key usage flags, see :secref:`key-usage-flags`.

        The following attributes must be set for keys that do not use the default volatile lifetime:

        *   The key lifetime, see :secref:`key-lifetimes`.
        *   The key identifier is required for a key with a persistent lifetime, see :secref:`key-identifiers`.

        The following attributes are optional:

        *   If the key size is nonzero, it must be equal to the size of the key-encapsulation shared secret.

        .. note::
            This is an input parameter: it is not updated with the final key attributes.
            The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.
    .. param:: psa_key_id_t * output_key
        On success, an identifier for the newly created shared output key.
        `PSA_KEY_ID_NULL` on failure.

    .. return:: psa_status_t

    .. retval:: PSA_SUCCESS
        Success.
        ``output_key`` contains the identifier for the shared output key.

        In some algorithms, decapsulation failure is implicit, resulting in an incorrect output key, instead of reporting an error status.

        .. todo::
            What should the result be for an explicit decapsulation failure? - INVALID_SIGNATURE, or INVALID_ARGUMENT (as per the detection of incorrect-length encapsulation data)?
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not a key-encapsulation algorithm.
        *   ``key`` is not supported for use with ``alg``.
        *   The output key attributes, as a whole, are not supported, either by the implementation in general or in the specified storage location.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not a key-encapsulation algorithm.
        *   ``key`` is not an asymmetric key pair, that is compatible with ``alg``.
        *   The output key attributes in ``attributes`` are not valid:

            -   The key type is not valid for the shared output key.
            -   The key size is nonzero, and is not the size of the shared output.
            -   The key lifetime is invalid.
            -   The key identifier is not valid for the key lifetime.
            -   The key usage flags include invalid values.
            -   The key's permitted-usage algorithm is invalid.
            -   The key attributes, as a whole, are invalid.
        *   ``encapsulation`` is not obviously valid for the selected algorithm and key.
            For example, the implementation can detect that it is an incorrect length.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    The ``output_key`` location, policy, and type are taken from ``attributes``.

    The size of the returned key is always the bit-size of the shared secret, rounded up to a whole number of bytes.
    The size of the shared secret is dependent on the key-encapsulation algorithm and the type and size of ``key``.

    It is recommended that this key is used as an input to a key derivation operation to produce additional cryptographic keys.
    For some key-encapsulation algorithms, the shared secret is also suitable for use as a key in cryptographic operations such as encryption.
    Refer to the documentation of individual key-encapsulation algorithms for more information.

    .. warning::
        A successful result from `psa_decapsulate()` does not indicate that the output key is identical to the key produce by the call to `psa_encapsulate()`:

        *   Some key-encapsulation algorithms do not authenticate the encapsulation data.
        *   Some key-encapsulation algorithms report authentication failure implicitly, by returning a pseudo-random key value.

        It is recommended that application uses the output key in a way that will confirm that the derived keys are identical.

Support macros
--------------

.. macro:: PSA_ENCAPSULATION_SIZE
    :definition: /* implementation-defined value */

    .. summary::
       Sufficient encapsulation buffer size for `psa_encapsulate()`, in bytes.

    .. param:: key_type
       A key type that is compatible with algorithm ``alg``.
    .. param:: key_bits
       The size of the key in bits.
    .. param:: alg
       A key-encapsulation algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

    .. return::
       A sufficient output buffer size for the specified algorithm, key type, and size. An implementation can return either ``0`` or a correct size for an algorithm, key type, and size that it recognizes, but does not support. If the parameters are not valid, the return value is unspecified.

       If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate()` will not fail due to an insufficient buffer size. The actual size of the output might be smaller in any given call.

        See also `PSA_ENCAPSULATION_MAX_SIZE`.

.. macro:: PSA_ENCAPSULATION_MAX_SIZE
   :definition: /* implementation-defined value */

    .. summary::
       Sufficient output buffer size for `psa_encapsulate()`, for any of the supported key types and key-encapsulation algorithms.

       If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate()` will not fail due to an insufficient buffer size.

       See also `PSA_ENCAPSULATION_SIZE()`.
