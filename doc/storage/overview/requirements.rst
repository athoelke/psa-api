.. SPDX-FileCopyrightText: Copyright 2018-2019, 2022-2023 Arm Limited and/or its affiliates
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Requirements
============

Protected Storage requirements
------------------------------

1.  The technology and techniques used by the Protected Storage service must allow for frequent writes and data updates.
2.  If writing to external storage, the Protected Storage service must provide confidentiality --- unless the caller specifically requests integrity only.
3.  Confidentiality for a Protected Storage service may be provided by cryptographic ciphers using device-bound keys, a tamper resistant enclosure, or an inaccessible deployment location, depending on the threat model of the deployed system. If using counter-based encryption, the service must ensure a fresh key and nonce pair is used for each object instance encrypted.
4.  If writing to external storage, the Protected Storage service must provide integrity protection.
5.  Integrity protection for a Protected Storage service may be provided by cryptographic Message Authentication Codes (MAC) or signatures generated using device-bound keys, a tamper resistant enclosure, or an inaccessible deployment location, depending on the threat model of the deployed system.
6.  If writing to external storage, the Protected Storage service must provide replay protection by writing replay protection values through the Internal Trusted Storage API, unless the caller specifically requests no replay protection.
7.  If providing services to :term:`Secure Partition`\s, and the system isolates partitions from each other, then the Protected Storage service must provide protection from one partition accessing the storage assets of a different partition.
8.  The Protected Storage service must use the partition identifier associated with each request for its access control mechanism.
9.  If the Protected Storage service is providing services to other :term:`ARoT` services, it must be implemented inside the ARoT itself.
10. If implemented inside the ARoT, the Protected Storage service can use helper services outside of the ARoT to perform actual read and write operations through the external interface or file system.
11. In the event of power failures or unexpected flash write failures, the implementation must attempt to fallback to allow retention of old content.
12. The creation of a ``uid`` with value ``0`` (zero) must be treated as an error.

.. _its-requirements:

Internal Trusted Storage requirements
-------------------------------------

1.  The storage underlying the Internal Trusted Storage service must be protected from read and modification by attackers with physical access to the device.
2.  The storage underlying the Internal Trusted Storage service must be protected from direct read or write access from software partitions outside of the :term:`Platform Root of Trust`.
3.  The technology and techniques used by the Internal Trusted Storage service must allow for frequent writes and data updates.
4.  Confidentiality of data stored by the Internal Trusted Storage service can be implemented using an inaccessible deployment location, cryptographic ciphers, or a combination of these techniques.
5.  Integrity of data stored by the Internal Trusted Storage service can be implemented using an inaccessible deployment location, cryptographic Message Authentication Codes (MAC) or signatures, or a combination of these techniques.
6.  The Internal Trusted Storage service must provide protection from one partition accessing the storage assets of a different partition.
7.  The Internal Trusted Storage service must use the partition identifier associated with each request for its access control mechanism.
8.  The medium and methods utilized by a Internal Trusted Storage service must provide confidentiality within the threat model of the system.
9.  The medium and methods utilized by a Internal Trusted service must provide integrity within the threat model of the system.
10. If the Debug Lifecycle state allows for a device to be debugged after deployment, then the Internal Trusted Storage service must provide confidentiality and integrity using cryptographic primitives with keys that are unavailable in the debug state.
11. If the device supports the ``RECOVERABLE_PSA_ROT_DEBUG`` Lifecycle state, then the Internal Trusted Storage service must provide confidentiality and integrity using cryptographic primitives with keys that are unavailable in the ``RECOVERABLE_PSA_ROT_DEBUG`` state.
12. In the event of power failures or unexpected flash write failures, the implementation must attempt to fallback to allow retention of old content.
13. In the extreme case of storage medium being completely non-accessible, no assurances can be made about the availability of the old content.
14. The `PSA_STORAGE_FLAG_WRITE_ONCE` must be enforced when the Root of Trust Lifecycle state of the device is ``SECURED``  or ``NON_PSA_ROT_DEBUG``. It must not be enforced when the device is in the ``PSA_ROT_PROVISIONING`` state.
15. The creation of a ``uid`` with value ``0`` (zero) must be treated as an error.

The lifecycle states are described in :cite-title:`PSM` and :cite-title:`PSA FFM`.
