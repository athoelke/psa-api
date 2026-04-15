.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022-2026 Arm Limited and/or its affiliates
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. Releases of this specification

.. release:: 1.0.0
    :date: June 2019
    :confidentiality: Non-confidential

    First stable release with finalized 1.0 API.

.. release:: 1.0.1
    :date: August 2019
    :confidentiality: Non-confidential

    Recommend type byte 0x01 for arm_psa_UEID.

    Remove erroneous guidance regarding EAT’s origination claim.

.. release:: 1.0.2
    :date: February 2020
    :confidentiality: Non-confidential

    Clarify the claim number of Instance ID.

    Permit COSE-Mac0 for signing tokens (with appropriate warning).

    Update URLs.

.. release:: 1.0.3
    :date: October 2022
    :confidentiality: Non-confidential

    Relicensed as open source under CC BY-SA 4.0.

    CDDL definition added to the appendices.

    Example header file added to the appendices.

    Minor corrections and clarifications.

.. release:: 1.0.4
    :date: September 2025
    :confidentiality: Non-confidential

    GlobalPlatform governance of PSA Certified evaluation scheme.

.. release:: 2.0.0
    :date: May 2026
    :confidentiality: Non-confidential

    Updated attestation token format to the PSA attestation token.

.. release-info::
    :extend:

    The detailed changes in each release are described in :secref:`document-history`.

.. References used within this specification

.. reference:: PSM
   :title: Platform Security Model
   :doc_id: ARM DEN 0128
   :url: developer.arm.com/documentation/den0128

.. reference:: PSA-STAT
    :title: PSA Certified Status code API
    :doc_id: ARM IHI 0097
    :url: arm-software.github.io/psa-api/status-code

.. reference:: PSA-FFM
    :title: Arm® Platform Security Architecture Firmware Framework
    :doc_id: ARM DEN 0063
    :url: developer.arm.com/documentation/den0063

.. reference:: C99
    :title: ISO/IEC 9899:1999 --- Programming Languages --- C
    :author: ISO/IEC
    :publication: December 1999
    :url: www.iso.org/standard/29237.html

.. reference:: RFC9783
    :title: Arm's Platform Security Architecture (PSA) Attestation Token
    :author: H. Tschofenig, S. Frost, M. Brossard, A. Shaw, and T. Fossati
    :publication: June 2025
    :url: tools.ietf.org/html/rfc9783

.. reference:: RFC2104
    :title: HMAC: Keyed-Hashing for Message Authentication
    :author: IETF
    :publication: February 1997
    :url: tools.ietf.org/html/rfc2104


.. Terms used within this specification

.. term:: Initial Attestation Key
    :abbr: IAK

    Typically, the Initial Attestation Key is a secret private key from an asymmetric key-pair accessible only to the Initial Attestation service within the :term:`Platform Root of Trust`. See :cite-title:`PSM`.

.. term:: PSA

    Platform Security Architecture

.. term:: Platform Root of Trust
    :abbr: PRoT

    The overall trust anchor for the system. This ensures the platform is securely booted and configured, and establishes the secure environments required to protect security services. See :cite-title:`PSM`.

.. scterm:: Implementation Defined

    Behavior that is not defined by this specification, but is defined and documented by individual implementations.

    Application developers can choose to depend on :sc:`IMPLEMENTATION DEFINED` behavior, but must be aware that their code might not be portable to another implementation.

.. term:: Secure Processing Environment
    :abbr: SPE

    This is the security domain that includes the :term:`Platform Root of Trust` domain.

.. term:: Non-secure Processing Environment
    :abbr: NSPE

    This is the security domain outside of the :term:`Secure Processing Environment`. It is the application domain, typically containing the application firmware and hardware.



.. potential-for-change::

    The contents of this specification are stable for version |docversion|.

    The following may change in updates to the version |docversion| specification:

    *   Small optional feature additions.
    *   Clarifications.

    Significant additions, or any changes that affect the compatibility of the interfaces defined in this specification will only be included in a new major or minor version of the specification.

.. about::
