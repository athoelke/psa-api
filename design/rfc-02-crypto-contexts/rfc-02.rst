.. SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

RFC-02: Support for caller contexts in the Crypto API
=====================================================

**Contents**

*  `Background`_
*  `Analysis`_
*  `Proposed design`_
*  `Draft API design`_
*  `Detailed API definition`_
*  `Open Issues`_
*  `Revision history`_

Background
----------

When first designed, the Crypto API was intended to be **the** API for an application to perform cryptographic operations and manage cryptographic secrets. To keep the API very simple for embedded/IoT uses, it is stateless. For an application, that implies that all use of the API occurs within a single context, and a single key-store namespace.For an implementation, that requires that the key store state, or the communication from the application to an isolated cryptoprocessor is effectively static or global for the application.

This API design and its implications are challenging for some scenarios:

1. Deployment of the API in systems which need to carefully account for, manage, and clean up resources. Without an explicit context in which application resources (e.g. RAM) are managed, it is not easy for an application to request that the Crypto API resources are released back to the operating system.

2. Use of an implementation of the API within a programming environment that does not permit global state.

3. Use of the API in an intermediate/adaptation layer of the software. For example, where an existing application cryptographic API is used, and the PSA Crypto API is being used as a common porting interface from the existing cryptographic service to a secure hardware component.

4. This type of feature has been specifically requested for the API in the past: see **Issue #77**: `Use Explicit Context in the Crypto API <https://github.com/ARM-software/psa-api/issues/77>`_.

The discussion that has given rise to this RFC is based arounce use case (3) above. In this software stack, a single caller of the PSA Crypto API is acting as a proxy for multiple applications, and the requirement is to be able to provide some application-specific context to the Crypto API implementation as part of every API call.

Analysis
--------

Currently, there is no explicit mechanism to provide caller-specific information in each API call. The API design assumes that state is global to the caller execution context. For caller-isolated implementations, it is assumed that the implementation (or the operating system in which it is embedded), provides a secure caller-identity to the cryptoprocessor.

In the driving use case (3), the caller is acting as a proxy for multiple applications to the hardware component. In this architecture, it is possible for the caller to keep application keys and operations isolated - as it must already map between the key identifiers used by the top and bottom interfaces. However, there are application-specific attributes that need to be conveyed to the hardware component (an application identity and priority) to provide the behaviour required by the system.

One way to achieve this with the existing Crypto API is to use a separate thread for each application caller, and use an implementation-specific API to set per-thread information that is needed by the hardware component. The implementation can then use the per-thread state to determine which application is associated with the call. Even if this approach is possible in a system, the use of additional threads uses significant system resources, requires that the Crypto API implementation is multi-threaded, and may require substantial redesign and reimplementation of the software. This is not a viable approach for the primary use case.

An alternative approach is to make some systematic changes to the Crypto API. These changes introduce 'sessions', objects which are explicitly connected to, and disconnected from, the cryptoprocessor implementation; and every function call or operation object is attached to a connected session. The session object provides a container to convey application attributes to the implementation as needed for use case (3). If we design the 'session' API appropriately, we could also to address the other use cases --- (1) and (2) --- above.

The downside of the alternative approach, is that the resulting API is source-incompatible with the existing Crypto API. It is not merely a new version of the API, it is more like a parallel variant of it. It retains alomst all of the concepts, API patterns, and programming model; but an implementation of this variant cannot be used directly with an application written for the current API.

Proposed design
---------------

This proposal is based around the second approach in the analysis: introducing some new API elements, and a set of systematic changes to the current API that provides a mechanism to associate every request to the cryptoprocessor with an application-managed context.

The basic concept is the introduction of session object, whose content is implementation defined (as with other Crypto API data structures), and a pair of functions to initiate and terminate the session.

API elements that do not require access to the cryptoprocessor or keystore are unchanged. That is, function-like macros, and functions that are permitted to be implemented inline, for example `psa_set_key_type()`.

An active session object must be associated with every other function that could be expected to use the key store or crypto-processor:

*   For single-part/standalone functions, this is done directly as an additional parameter to the function.
*   For a multi-part operation, the association with a specific session is made during set up, and only broken when the operation is terminated.

    -   Any setup function in a multi-part operation has an additional session parameter.
    -   Other multi-part operation functions are unchanged - the implementation must remember the session provided during setup of the multi-part operation.

Alignment with the v1.3 API
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Adding a session parameter to many of the APIs could be done in two ways:

1.  Just add the parameter, leaving the function name unchanged.
2.  Use a common pattern to rename each API that requires an additional parameter.

The first of these provides obvious alignment with the existing API definition. However, reading code that uses the modified API could be confusing to someone who is only familiar with the current Crypto API. Also, it might be vaulable to present an implementation of the current API as one that provides the session-based API; or vice versa. Adaptations such as these are very difficult if the two variants of the API use the same name for different functions, in a language that does not support function overloading.

Although the second option significantly increases the number of identifiers in the API, the benefits of clearer intentions in application code, and the possibility of adpating one variant of the API to the other make this the preferred option.

Session lifecycle
~~~~~~~~~~~~~~~~~

As with other objects in the Crypto API, the members of the session type are implementation-defined. The API provides functions to interact with a session object:

*   Initialize a newly allocated session object. Similar to other INIT operations, this ensure that the object represents a valid, inactive session.
*   Set session attributes.
    Some attributes are fixed for the duration of a session, and must be set prior to opening the session.
    Other attributes may be mutable while the session is active.
*   Open a session.
    This makes the session active, after which it can be used for other functions in the API.
*   Close a session.
    If the session is inactive, this will have no effect.

Using a session that is not active in a call to other functions in the API is an error.

An implementation can attach resources to an active session, which will only be released or recovered when the session is closed.
It is recommended that applications that use multiple sessions, explicitly close session objects once they are no longer required.

Session attributes
~~~~~~~~~~~~~~~~~~

One of the specific use cases driving this RFC requires a session identifier and a priority attribute to be associated with each session.
These are used by the implementation in resource allocation, and the ordering of requests from multiple callers and sessions on shared cryptoprocessor resources.

The session id and priority can be integral values.

It must be possible for the calling application to select and specify the session identifier, which is fixed for the duration of the open session.

Rationale
    For this scenario, the session identifiers are allocated as part of system integration.
    The application sets this in the session object to reference pre-assigned resources in the implementation.

TBD:
    *Should the session identifier be a parameter to the open operation, which makes it clearly immutable?*

If the implementation does not use a session identifier, this will be ignored.

It must be possible for the calling application to set a session priority, and possibly modify it while the session is open. An updated priority would be used for any subsequent function that uses the session.

TBD:
    *Do we need functions to query the attributes of a session?*

See also `Open Issues`_.

Session behavior
~~~~~~~~~~~~~~~~

A single application thread can open multiple session objects concurrently (if resources permit), and use them in different calls to the API.

Although separate sessions provide distinct contexts for operations in the implementation, they are not treated as separate 'callers' in a caller-isolated implementation.
That is, two sessions that are opened from the same 'caller' will have access to the same key store.

TBD:
    *Is it permitted to close a session, while it is still attached to a multi-part operation that is in an active state? - if so, what happens if the application then tries to continue the operation? What about a multi-part operation in an error state?*

Draft API design
----------------

Session definition and initialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``psa_session_t`` (type)
^^^^^^^^^^^^^^^^^^^^^^^^

The type of a session object.

.. code-block:: c

    typedef /* implemention-specific type */ psa_session_t;

The members of a session object are implementation specific.

``PSA_SESSION_INIT`` (macro)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Initializer for a ``psa_session_t`` object.

.. code-block:: c

    #define PSA_SESSION_INIT(session) /* implementation-specific definition */

Initialize memory to represent an inactive session object.

``psa_session_init`` (function)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Return an initialized ``psa_session_t`` object.

.. code-block:: c

    psa_session_t psa_session_init();


Session attributes
~~~~~~~~~~~~~~~~~~

``psa_session_id_t`` (type)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A session identifier value.

.. code-block:: c

    typedef uint32_t psa_session_id_t;

A session identifier is set before opening a session, and cannot be changed for the duration of the session.

TBD:
    *We could make it a parameter to ``psa_session_open()``. Then we would either need to define a 'no-id' value for applications to use with an implementation that does not use session ids; or define two open functions, one of which takes a session id.*

``psa_session_set_id`` (function)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the identifier for the session.

.. code-block:: c

    psa_status_t psa_session_set_id(psa_session_t * session, psa_session_id_t id);

The session identifier can only be set before the session is opened.

TBD:
    *Does the session id need to be unique? - at least within the caller's context?*

    *If so, reporting of an already-existing id might only happen when the session is opened.*

Note
    This can be implemented as an inline function.

``psa_session_priority_t`` (type)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A session priority value.

.. code-block:: c

    typedef uint32_t psa_session_priority_t;

The session priority can be set prior to opening the session, or after the session is open.
The priority is used for subsequent operations that use the session.

``psa_session_set_priority`` (function)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the priority of the session.

.. code-block:: c

    psa_status_t psa_session_set_priority(psa_session_t * session, psa_session_priority_t priority);

Priority can be set at any time.
The attribute value at the time the session is used in a function call determines the priority value for that call.

Note
    This can be implemented as an inline function.

    TBD:
        *If so, is the implementation is permitted to defer reporting an error with the provided priority value until the session is used in another function?*

Session operation
~~~~~~~~~~~~~~~~~

It is implementation defined whether a session object is just a value type, storing session attributes, where open and close have no effect; or a resource type, where correct use of open and close is essential.
Portable applications should always call these functions if they use the session APIs.

``psa_session_open`` (function)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Open a session before using Crypto API functions.

.. code-block:: c

    psa_status_t psa_session_open(psa_session_t * session);

A session object that is inactive can only be used in calls to ``psa_session_open()``, ``psa_session_set_id()``, ``psa_session_set_priority()``, and ``psa_session_close()``.
After a successful call to ``psa_session_open()``, the session can be used in other Crypto API functions.

To terminate an active session, call ``psa_session_close()``.

The application must call ``psa_crypto_init()`` before opening a session.

``psa_session_close`` (function)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Close an open session.

.. code-block:: c

    psa_status_t psa_session_close(psa_session_t * session);

This function has no effect if called on a session that is inactive.

Session usage (in existing APIs)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An additional ``const psa_session_t * session`` parameter is required in many of the existing Crypto API functions.
This provides the session context in which the function, or the multi-part operation, is carried out.

Where the additional parameter is required, the function signature and description is changed using the following pattern:

*   The function name is changed by inserting ``session_`` immediately after the initial ``psa_`` prefix.
    For example, ``psa_import_key()`` becomes ``psa_session_import_key()``.
*   An additional ``const psa_session_t * session`` parameter is added to the beginning of the parameter list.
    For example,

    .. code-block:: c

        psa_status_t psa_copy_key(psa_key_id_t source_key,
                                  const psa_key_attributes_t * attributes,
                                  psa_key_id_t * target_key);

    becomes

    .. code-block:: c

        psa_status_t psa_session_copy_key(const psa_session_t * session,
                                          psa_key_id_t source_key,
                                          const psa_key_attributes_t * attributes,
                                          psa_key_id_t * target_key);

*   The provided session object must be active.
    If not, the API will return a ``PSA_ERROR_BAD_STATE`` response code.

The following categories of API element will not require the additional parameter:

*   Function-like macros.
    These are all expected to be able to provide a result without access to any key-store or crypto-processor state or resources.
*   Data structure initialization macros and functions.
    These just initialize the memory of a data structure to a well-defined 'inactive' or 'empty state'.
*   Simple data structure setter and getter functions.
    For example, the functions to access the attributes of a ``psa_key_attributes_t`` object.
    These functions typically include a note that they can be implemented as inline functions, and they do not return a ``psa_status_t`` response code.
*   Non-setup functions that are part of a multi-part operation.
    The setup function will associate the operation object with a specific session, and this association remains until the operation is terminated.

The full list (based on v1.3 of the API) of functions that are modified is as follows:

.. code-block:: c

    // Key management
    psa_import_key();
    psa_generate_key();
    psa_generate_key_custom();
    psa_export_key();
    psa_export_public_key();
    psa_copy_key();
    psa_destroy_key();
    psa_purge_key();
    psa_get_key_attributes();
    // Hash
    psa_hash_compute();
    psa_hash_compare();
    psa_hash_setup();
    psa_hash_resume();
    psa_hash_clone();
    // MAC
    psa_mac_compute();
    psa_mac_verify();
    psa_mac_sign_setup();
    psa_mac_verify_setup();
    // Cipher
    psa_cipher_encrypt();
    psa_cipher_decrypt();
    psa_cipher_encrypt_setup();
    psa_cipher_decrypt_setup();
    // AEAD
    psa_aead_encrypt();
    psa_aead_decrypt();
    psa_aead_encrypt_setup();
    psa_aead_decrypt_setup();
    // KDF
    psa_key_derivation_setup();
    // Signature
    psa_sign_hash();
    psa_verify_hash();
    psa_sign_message();
    psa_verify_message();
    // Asymmetric encryption
    psa_asymmetric_encrypt();
    psa_asymmetric_decrypt();
    // Key agreement
    psa_key_agreement();
    psa_raw_key_agreement();
    // KEM
    psa_encapsulate();
    psa_decapsulate();
    // PAKE
    psa_pake_setup();
    // Other
    psa_generate_random();

Detailed API definition
-----------------------

*To-do*

Open Issues
-----------

1.  Should the session identifier be set as a parameter to ``psa_session_open()``, instead of using a separate ``psa_session_set_id()``?

    If provided in a separate call, the session object must include a data member to store the value, even if the implementation passes it through to an isolated cryptoprocessor as part of the session open operation.

    If included in a ``psa_session_open()`` function, the implementation can store it in the session object, and/or provide it to the cryptoprocessor, depending on implementation design.
#.  Do we need to be able to query the attributes of a session?
#.  Behavior of an multi-part operation if the associated session is closed whiel the operation is active?
#.  If the implementation stores the session priority within the cryptoprocessor (and the session object is just a proxy/handle to the actual session data), it might be preferable to not permit the priority to be set before the session is open.

    Or is the small cost of storing a priority (and a session id) in the session object prior to being opened not worth making the API a bit more awkward for the application to use?
#.  If ``psa_session_set_priority()`` is inline (e.g. session is just an attribute-store), can reporting an error for an invalid priority value be deferred to when the session is used? - or must it be reported by the set-priority function?

Revision history
----------------

**v0.1** - 18/06/2025
   Initial draft proposal.
