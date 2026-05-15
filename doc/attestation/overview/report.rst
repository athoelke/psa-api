.. SPDX-FileCopyrightText: Copyright 2018-2025 Arm Limited and/or its affiliates
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _report:

Initial Attestation report
==========================

The attestation report returned by the |API| is formatted and encoded as a signed PSA Attestation Token. This is defined in :rfc-title:`9783`.

The PSA Attestation Token is an incompatible evolution of the original attestation format, that was specified in version 1.0 of the |API|.

To comply with version |APIversion| of the |API|, an implementation must only produce attestation reports that conform to :rfc:`9783`.

:numref:`tab-psa-token-notes` provides specific recommendations for the construction of some of the token claims.

.. list-table:: Recommended construction of the token claims
   :name: tab-psa-token-notes
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 4
   :align: left

   *  -  Claim
      -  Recommended construction

   *  -  Instance ID
      -  The construction of the 32-byte key-hash component of this claim depends on the type of :term:`Initial Attestation Key` (IAK):

         *  When using an asymmetric key-pair for the IAK, the Instance ID is a hash of the corresponding public key --- ``InstanceID = H(IAK)``.
         *  When using a symmetric key for the IAK, it is recommended that the Instance ID is a *double* hash of the key --- ``InstanceID = H(H(IAK))``.

         .. rationale::

            According to :rfc-title:`2104`, if a HMAC key is longer than the HMAC block size, the key will be first hashed. The hash output is used as the key in HMAC computation.

            When HMAC is used to authenticate the token, and IAK is longer than the HMAC block size, then ``HMAC(IAK, token) == HMAC(H(IAK), token)``. If Instance ID is defined to be ``H(IAK)``, then an attacker can use the Instance ID value in an attestation token to fake malicious reports by using Instance ID as the HMAC key.

            Constructing Instance ID as a double hash of IAK eliminates this risk.
