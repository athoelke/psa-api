.. SPDX-FileCopyrightText: Copyright 2018-2019, 2022 Arm Limited and/or its affiliates
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Theory of Operation
===================

Internal Trusted Storage API
--------------------------------

The Internal Trusted Storage service that implements the Internal Trusted Storage API is not expected to replace the need for a filesystem that resides on external storage. Instead, it's intended to be used to interface to a small piece of storage that is only accessible to software that is part of the :term:`Platform Root of Trust`. The Internal Trusted Storage API can be made accessible to the :term:`Non-secure Processing Environment` as well as the :term:`Secure Processing Environment`.

Internally the Internal Trusted Storage service should be designed such that one partition cannot access the data owned by another partition. The method of doing this is not specified here, but one method would be to store metadata with the data indicating the partition that owns it.

:numref:`fig-crypto-storage` provides a simple example of how an Internal Trusted Storage service can be used by a service that implements :cite-title:`PSA CRYPT` to secure keystore material. This is illustrative and not prescriptive.

.. figure:: /figure/storage.*
   :name: fig-crypto-storage
   :alt: Sample Storage

   Sample Storage implementation with a service implementing the Crypto API

Memory access errors
--------------------

When specifying an input or output buffer, the caller should ensure that the entire buffer is within memory it can access.

Attempting to reference memory that does not belong to the caller will either result in a memory access violation or will cause the function to return ``PSA_ERROR_INVALID_ARGUMENT``.

Implementations of the Internal Trusted Storage API and Protected Storage API must check the length parameters of a buffer before attempting to access them. It is permissible to pass a null pointer to a zero length buffer.
