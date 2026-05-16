.. SPDX-FileCopyrightText: Copyright 2023-2024 Arm Limited and/or its affiliates
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _sra:

Security Risk Assessment
========================

This appendix provides a Security Risk Assessment (SRA) of the |API| and of a generic implementation of storage.
It describes the threats presented by various types of adversaries against the security goals for an implementation of a secure storage service, and mitigating actions for those threats.

*  :secref:`sra-about` describes the assessment methodology.
*  :secref:`sra-definition` defines the security problem.
*  :secref:`sra-threats` describes the threats and the recommended mitigating actions.
*  :secref:`sra-mitigations` summarizes the mitigations, and where these are implemented.

.. _sra-about:

About this assessment
---------------------

Subject and scope
^^^^^^^^^^^^^^^^^

This SRA analyses the security of the |API| itself, and of the conceptual architectures for storage, not of any specific implementation of the API, or any specific use of the API.
It does, however, divide implementations into four deployment models representing common implementation types, and looks at the different mitigations needed in each deployment model.

In this SRA:

*  *Storage service* means the firmware implementing the |API|.
*  *Storage medium* refers to the physical storage location.

Risk assessment methodology
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Our risk ratings use an approach derived from :cite-title:`SP800-30`: for each Threat, we determine its Likelihood and the Impact.
Each is evaluated on a 5-level scale, as defined in :numref:`tab-sra-likelihood` and :numref:`tab-sra-impact`.

.. list-table:: Likelihood levels
   :name: tab-sra-likelihood
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 6

   *  -  Level
      -  Definition

   *  -  Very Low
      -  Unlikely to ever occur in practice, or *mathematically near impossible*
   *  -  Low
      -  The event could occur, but only if the attacker employs *significant* resources; or it is *mathematically unlikely*
   *  -  Medium
      -  A motivated, and well-equipped adversary can make it happen within the lifetime of a product based on the feature (resp. of the feature itself)
   *  -  High
      -  Likely to happen within the lifetime of the product or feature
   *  -  Very High
      -  Will happen, and soon (for instance a zero-day)

.. list-table:: Impact levels
   :name: tab-sra-impact
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 3 3

   *  -  Level
      -  Definition
      -  Example Effects

   *  -  Very Low
      -  Causes virtually no damage.
      -  Probably none.
   *  -  Low
      -  The damage can easily be tolerated or absorbed.
      -  There would be a CVE at most.
   *  -  Medium
      -  The damage will have a *noticeable* effect, such as *degrading* some functionality, but won't degrade completely the use of the considered functionality.
      -  There would be a CVE at most.
   *  -  High
      -  The damage will have a *strong* effect, such as causing a significant reduction in its functionality or in its security guarantees.
      -  Security Analysts would discuss this at length, there would be papers, blog entries.
         Partners would complain.
   *  -  Very High
      -  The damage will have *critical* consequences --- it could kill the feature, by affecting several of its security guarantees.
      -  It would be quite an event.

         Partners would complain strongly, and delay or cancel deployment of the feature.

For both Likelihood and Impact, when in doubt always choose the higher value.
These two values are combined using :numref:`tab-sra-overall-risk` to determine the Overall Risk of a Threat.

.. csv-table:: Overall risk calculation
   :name: tab-sra-overall-risk
   :header-rows: 2
   :stub-columns: 1
   :align: right

   ,Impact,,,,
   Likelihood, Very Low, Low, Medium, High, Very High
   Very Low, Very Low, Very Low, Very Low, Low, Low
   Low, Very Low, Very Low, Low, Low, Medium
   Medium, Very Low, Low, Medium, Medium, High
   High, (Very) Low, Low, Medium, High, Very High
   Very High, (Very) Low, Medium, High, Very High, Very High

Threats are handled starting from the most severe ones.
Mitigations will be devised for these Threats one by one (note that a Mitigation may mitigate more Threats, and one Threat may require the deployment of more than one Mitigation to be addressed).
Likelihood and Impact will be reassessed assuming that the Mitigations are in place, resulting in a Mitigated Likelihood (this is the value that usually decreases), a Mitigated Impact (it is less common that this value will decrease), and finally a Mitigated Risk.
The Analysis is completed when all the Mitigated Risks are at the chosen residual level or lower, which usually is Low or Very Low.

The Mitigating actions that can be taken are defined in the acronym **CAST**:

*  **Control**: Put in place steps to reduce the Likelihood and/or Impact of a Threat, thereby reducing the risk to an acceptable level.
*  **Accept**: The threat is considered to be of acceptable risk such that a mitigation is not necessary or must be accepted because of other constraint or market needs.
*  **Suppress**: Remove the feature or process that gives rise to the threat.
*  **Transfer**: Identify a more capable or suitable party to address the risk and transfer the responsibility of providing a mitigation for the threat to them.

.. _sra-definition:

Feature definition
------------------

Introduction
^^^^^^^^^^^^

Background
~~~~~~~~~~

:secref:`introduction` provides the context in which the |API| is designed.

Purpose
~~~~~~~

The |API| separates the software responsible for providing the security of the data from the caller.
The storage service calls on firmware that provides low level reads and writes of non-volatile storage medium and the access to any required bus.
The |API| is to provide a consistent interface, so that applications do not need to account for the different low-level implementations.

This analysis does not address the engineering requirements to create a reliable storage medium from the underlying physical storage.
It is assumed that the implementation will use the standard techniques, error correcting codes, wear levelling and so on, to ensure the storage is reliable.

Lifecycle
^^^^^^^^^

:numref:`fig-lifecycle` shows the typical lifecycle of a device.

.. figure:: /figure/lifecycle.*
   :name: fig-lifecycle

   Device lifecycle of a system providing storage

The storage service, and the |API| are active during the operational phase, implemented within the boot-time and run-time software.

Within a boot session, it is the responsibility of the secure boot firmware to:

*  Set up the isolation barriers between partitions.
*  Provision the firmware implementing the storage service.
*  Provision the credentials for authorizing the storage of data.
*  Enable or disable debug facilities.

This SRA only considers threats to the storage service in its operational phase.
The security of the boot process and of any data provisioning service are not considered in this SRA.

Operation and trust boundaries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:numref:`fig-boundaries` shows all of the main components in the storage service.
Presenting the context in which the |API| operates aids understanding of the threats and security mitigations and provides justification for some of the aspects of the API design.

.. figure:: /figure/callers.*
   :name: fig-boundaries

   Trust boundaries of a system providing storage

|API| is a C language API.
Therefore, any implementation of the API must execute, at least partially, within the context of the caller.
When an implementation includes a trust boundary, the mechanism and protocol for communication across the boundary is not defined by this specification.

The operational dataflow diagram is reproduced for each of the deployment models.
Although the dataflow itself is common to the models, the placement of trust boundaries is different.

It is helpful to visualize the effect of these differences on the threats against the dataflows.


Deployment models
^^^^^^^^^^^^^^^^^

:deployment-model:`PROTECTED`
   The storage service and all physical storage is within the :term:`Platform Root of Trust` (:term:`PRoT`) partition.
   The :term:`PRoT` partition has sole access to an area of non-volatile storage, thus that storage cannot be accessed by any other partition or any other means.
   This means that the storage service, any driver code, the storage service and storage medium all reside with the :term:`PRoT` and are protected by the :term:`PRoT`'s isolation mechanisms as shown in :numref:`fig-protected`.

   .. figure:: /figure/dm-protected.*
      :name: fig-protected

      Trust boundaries in the deployment model `DM.PROTECTED`

   The storage service is the arbitrator of access from different applications and manages all data accesses (write, update and deletion).
   Therefore, the storage service is responsible for the `SG.CONFIDENTIALITY`, `SG.INTEGRITY` and `SG.CURRENCY` goals of each caller, including maintaining confidentiality between different callers.

   An example of this deployment model is the use of on-chip flash or OTP with an access control mechanism such as a Memory Protection Unit.

:deployment-model:`EXPOSED`
   The :term:`PRoT` partition does not have sole access to the area of non-volatile storage, thus the storage medium can be read or written by another partition or by other means.
   This means that the driver code, or the storage medium resides outside the :term:`PRoT` and is accessible to other partitions or by other means, as shown in  as shown in :numref:`fig-exposed`.
   Therefore, attackers can bypass the storage service.

   .. figure:: /figure/dm-exposed.*
      :name: fig-exposed

      Trust boundaries in the deployment model `DM.EXPOSED`

   The storage service is the arbitrator of access from different applications and manages accesses that write, update, and delete data.
   Therefore, the storage service is responsible for the `SG.CONFIDENTIALITY`, `SG.INTEGRITY` and `SG.CURRENCY` goal with respect to preventing access by a different caller.

   The storage service cannot prevent other partitions or other means from reading or writing the storage, or accessing the link DF3.
   Therefore, the storage service is responsible for the `SG.CONFIDENTIALITY`, `SG.INTEGRITY` and `SG.CURRENCY` goals.

   An example of this deployment model is the use of a file system on a flash chip.


:deployment-model:`AUTHORIZED`
   There is a separate isolated storage medium that can only be accessed in response to an authenticated command and from which all replies include a means for verification of the response, as shown in :numref:`fig-authorized`.
   The isolation guarantees that there is no access to the storage medium other than by using the authentication mechanism.

   .. figure:: /figure/dm-authorized.*
      :name: fig-authorized

      Trust boundaries in the deployment model `DM.AUTHORIZED`

   The storage service is the arbitrator of access from different applications and manages those data accesses (write, update and deletion).
   Therefore, the storage service is responsible for the `SG.CONFIDENTIALITY` goal with respect to preventing access by a different caller.

   The authorization and verification mechanism provided by the storage medium controls access to data (reads, writes and modification).
   Therefore, the storage medium is responsible for the `SG.INTEGRITY` and `SG.CURRENCY` goals.
   Attacks on these mechanisms are out of scope.

   However, the communication between the storage service and the storage medium is observable by other partitions and any other means as any data sent in plain text can be observed.
   Therefore, the storage service is responsible for  `SG.CONFIDENTIALITY`.

   The storage service and the storage medium are jointly responsible for protecting the assets required to authorize commands.
   Attacks on the storage service that expose these assets are in scope.

   An example of this deployment model is the use of an RPMB memory block.

:deployment-model:`SECURE_LINK`
   There is a separate isolated storage medium that can only be accessed across a cryptographically protected secure channel as shown in :numref:`fig-external-secure`.
   The secure channel protocol provides authentication, confidentiality and integrity of data in transit.
   The isolation guarantees that there is no access to the storage medium other than by using this channel.

   .. figure:: /figure/dm-secure-link.*
      :name: fig-external-secure

      Trust boundaries in the deployment model `DM.SECURE_LINK`

   The storage service is the arbitrator of access from different applications and manages those data accesses (write, update and deletion).
   Therefore, the storage service is responsible for the `SG.CONFIDENTIALITY` goal with respect to preventing access by a different caller.

   The authorization and verification mechanism provided by the secure channel protocol controls access to data (reads, writes and modification).
   Therefore, the storage medium is responsible for the `SG.INTEGRITY` and `SG.CURRENCY` goals.
   Attacks on the storage medium are out of scope.

   The communication between the storage service and the storage medium is protected from observation by other partitions and other means as the data is sent in encrypted form over the secure channel.
   Attacks on the  secure channel protocol are out of scope.

   The storage service uses the secure channel protocol, the storage service and the storage medium are jointly responsible for protecting the assets required to set up the channel.
   Attacks on the storage service that expose these assets are in scope.

   An example of this deployment model is the use of a Secure Element, or a secure flash device.


.. _isolation:

Optional isolation
~~~~~~~~~~~~~~~~~~

Implementations can isolate the storage service from the caller and can further isolate multiple calling applications.
Various technologies can provide protection, for example:

*  Process isolation in an operating system.
*  Partition isolation, either with a virtual machine or a partition manager.
*  Physical separation between execution environments.

The mechanism for identifying callers is beyond the scope of this specification.
An implementation that provides caller isolation must document the identification mechanism.
An implementation that provides caller isolation must document any implementation-specific extension of the API that enables callers to share data in any form.

In summary, there are three types of implementation:

*  No isolation: there is no security boundary between the caller and the storage service.
   For example, a statically or dynamically linked library is an implementation with no isolation.
   As the caller is in the same security domain as the storage, the API cannot prevent access to the storage medium that does not go through the API.

*  Simple Isolation: A single security boundary separates the storage service from the callers, but there is no isolation between callers.
   The only access to stored data is via the storage service, but the storage service cannot partition data between different callers.

*  Caller isolation: there are multiple caller instances, with a security boundary between the caller instances among themselves, as well as between the storage service and the caller instances.
   For example, a storage service in a multiprocessor environment is an implementation with caller isolation.
   The only access to the stored data is via the storage service and the storage service can partition stored data between the different callers.

Assumptions, constraints, and interacting entities
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This SRA makes the following assumptions about the |API| design:

*  The API does not provide arguments that identify the caller, because they can be spoofed easily, and cannot be relied upon.
   It is assumed that the implementation of the API can determine the caller identity, where this is required.
   See :secref:`isolation`.

*  The API does not prevent the use of mitigations that are required by an implementation of the API.
   See :secref:`tab-sra-remediations`.

*  The :cite-title:`PSM` assumes that at least the code in the :term:`Root of Trust` partitions (:term:`PRoT` and :term:`ARoT`) are verified at boot, and on any update.
   Therefore, it is assumed that this code is trustworthy.
   If any malicious code can run in the RoT partitions, it has achieved full control.

*  For the purposes of this analysis, it is assumed that in deployment models `DM.AUTHORIZED` and `DM.SECURE_LINK`, there is no way to access the stored data without going through the authenticated channel.
   That is, an attack that would expose the physical storage medium is beyond the resources of the attacker.

*  The analysis ignores attacks that only result in a denial of service.
   There are many ways an attacker can deny service to the complete system, with or without involving the storage service.

*  The analysis only looks at an active attack.
   However, data is also subject to accidental modification, for example from cosmic radiation causing a bit flip.
   Therefore, standard engineering practice --- such as use of error correcting codes --- should be taken to protect data.

Stakeholders and Assets
^^^^^^^^^^^^^^^^^^^^^^^

This analysis looks at the security from the point of view of the applications that call on the service to store data, and on the overall system.

The following assets are considered in this assessment:

Data to be stored
   The purpose of a storage service is to securely store data for its callers.

Caller Identities
   To ensure that data stored for one caller is not revealed to a different caller, each caller must have a unique identity.

Implementation Secrets
   If in order to secure the data, the storage service uses encryption keys for confidentiality and integrity, these mut be considered assets of the storage service.

Goals
^^^^^

:security-goal:`CONFIDENTIALITY`
   An adversary is unable to disclose Stored Data that belongs to a different Stored Data Owner.
   A legitimate owner can guarantee their data has not been exposed.

:security-goal:`INTEGRITY`
   An adversary is unable to modify Stored Data that belongs to a different Stored Data Owner, to a value that was not previously stored by the Stored Data Owner.
   A legitimate owner can guarantee that data returned is a value they have stored.

:security-goal:`CURRENCY`
   An adversary is unable to modify Stored Data that belongs to a different Stored Data Owner.
   The legitimate owner can guarantee that data returned is the most recent value that have stored.

Adversarial models
^^^^^^^^^^^^^^^^^^

Adversarial models are descriptions of capabilities that adversaries of systems implementing the |API| can have, grouped into classes.
The adversaries are defined in this way to assist with threat modelling an abstract API, which can have different implementations, in systems with a wide range of security sensitivity.

:adversarial-model:`0`
   The Adversary is only capable of accessing data that requires neither physical access to a system containing an implementation of the feature nor the ability to run software on it.
   This Adversary is intercepting or providing data or requests to the target system via a network or other remote connection.

   For instance, the Adversary can:

   *  Read any input and output to the target through external apparatus.
   *  Provide, forge, replay or modify such inputs and outputs.
   *  Perform timings on the observable operations being done by the target, either in normal operation or as a response to crafted inputs.
      For example, timing attacks on web servers.

:adversarial-model:`1`
   The Adversary can additionally mount attacks from software running on a target processor implementing the feature.
   This type of Adversary can run software on the target.

   For instance, the Adversary can:

   *  Attempt software exploitation by running software on the target.
   *  Exploit access to any memory mapped configuration, monitoring, debug register.
   *  Mount any side channel analysis that relying on software-exposed built-in hardware features to perform physical unit and time measurements.
   *  Perform software-induced glitching of resources such as Rowhammer, RASpberry or crashing the CPU by running intensive tasks.

:adversarial-model:`2`
   In addition to the above, the Adversary is capable of mounting hardware attacks and fault injection that does not require breaching the physical envelope of the chips.
   This type of Adversary has access to a system containing an implementation of the target feature.

   For instance, the Adversary can:

   *  Conduct side-channel analysis that requires measurement equipment.
      For example, this can utilize leakage sources such as EM emissions, power consumption, photonics emission, or acoustic channels.
   *  Plug malicious hardware into an unmodified system.
   *  Gain access to the internals of the target system and interpose the SoC or memory for the purposes of reading, blocking, replaying, and injecting transactions.
   *  Replace or add chips on the motherboard.
   *  Make simple, reversible modifications, to perform glitching.

:adversarial-model:`3`
   In addition to all the above, the Adversary can perform invasive SoC attacks.

   For instance, the Adversary can:

   *  Decapsulate a chip, via laser or chemical etching, followed by microphotography to reverse engineer the chip.
   *  Use a focused ion beam microscope to perform gate level modification.

The adversarial models that are in scope depend on the product requirements.
To ensure that the |API| can be used in a wide range of systems, this assessment considers adversarial models `AM.0`, `AM.1`, and `AM.2` to be in-scope.

Code in the RoT partitions is assumed to be trustworthy --- and any untrustworthy code running in :term:`PRoT` partitions already has complete control of the target --- therefore, in `AM.1` this SRA only considers threats from malicious actors running in :term:`Non-secure Processing Environment`.

.. _sra-threats:

Threats
-------

Because |API| can be used in a wide range of deployment models and a wide range of threats, not all mitigating actions apply to all deployment models.
As a result, various mitigations are optional to implement, depending on which threats exist in a particular domain of application, and which deployment model is used.

:numref:`tab-sra-threats` summarizes the threats.

.. csv-table:: Summary of threats
   :name: tab-sra-threats
   :class: longtable
   :align: left
   :widths: 1 3
   :header-rows: 1

   Threat, Description
   `T.INTERFACE_ABUSE`, Call the API with illegal inputs
   `T.SPOOF_READ`, Reading data for a different caller using the API
   `T.SPOOF_WRITE`, Writing data for a different caller using the API
   `T.EAVESDROPPING`, Accessing data in transit
   `T.MITM`, A Man in the Middle can actively interfere with communication
   `T.DIRECT_READ`, "Directly reading stored data, bypassing the API"
   `T.DIRECT_WRITE`, "Directly modifying data, bypassing the API"
   `T.REPLACE`, Physical replacement of the storage medium
   `T.GLITCH_READ`, Glitching during a read
   `T.GLITCH_WRITE`, Glitching during a write

.. threat:: Illegal inputs to the API
   :id: INTERFACE_ABUSE

   .. description::
      An attacker can abuse the |API|.
      For example:

      *  Passing out of range values to the interface to provoke unexpected behavior of the implementation.
      *  Passing invalid input or output buffers to the interface, that would cause the implementation to access non-existent memory, or memory that is inaccessible to the caller --- including accessing assets of the storage service.

   .. security-goal:: `SG.CONFIDENTIALITY`, `SG.INTEGRITY`
   .. adversarial-model:: `AM.1`

   .. mitigations::
      :mitigation:`ValidateParameter`.
      **Transfer** to the implementation: check all API parameters to lie within valid ranges, including memory access permissions.

      :mitigation:`MemoryBuffer`.
      **Control** by API design: input buffers are fully consumed by the implementation before returning from a function.
      An implementation must not access the caller's memory after a function has returned.

   .. unmitigated::
      :impact:  VH
      :likelihood: VH

   .. residual::
      :impact: VH
      :likelihood: VL


.. threat:: Use the API to read another caller's data
   :id: SPOOF_READ

   .. description::
      In all deployment models, an attacker attempts to read data stored for another caller using the |API|.

      The API does not require that the names used by caller for stored data are globally unique, only unique within that caller's namespace.

   .. mitigations::
      :mitigation:`ImplicitIdentity`.
      **Control** by API design: caller identity is not provided by the caller to the API.
      If caller identity is supplied by the caller in the API, the identity can be spoofed by another caller.
      Using authentication credentials only moves the problem of storing secrets, but does not solve it.

      **Transfer** to the implementation: provide caller identities, to isolate data that belongs to different callers.
      The assurance that the storage service can give is limited by the assurance that the implementation can give as to the identity of the caller.

      Where each user runs in a separate partition, the identity can be provided by the partition manager.
      Where different users run within a single partition, **Transfer** the responsibility for separating users within that partition to the operating system or run time within that partition.

      :mitigation:`FullyQualifiedNames`.
      **Transfer** to the implementation: use a fully-qualified data identifier, that is a combination of an owner identity and the item UID.
      The implementation must used the owner identity to ensure that a data request to the storage service does not return data of the same UID, that was stored by a different caller.

      The storage service must also ensure that if a data item with the fully-qualified identifier does not exist, the implementation returns the correct error.

   .. security-goal:: :SG:`CONFIDENTIALITY`

   .. adversarial-model:: `AM.1`

   .. unmitigated::
      :impact:  VH
      :likelihood: VH

   .. residual::
      :impact: VH
      :likelihood: VL

.. threat:: Use the API to modify another caller's data
   :id: SPOOF_WRITE

   .. description::
      In all deployment models, an attacker attempts to write data to a file belonging to another caller using the |API| or create a new file in a different caller's namespace.

      This threat is the counterpart to `T.SPOOF_READ` except that the attacker tries to write data rather than read.
      It is therefore subject to the same analysis.

   .. mitigations:: `M.FullyQualifiedNames`, `M.ImplicitIdentity`.

   .. security-goal:: :SG:`CONFIDENTIALITY`
   .. adversarial-model:: `AM.1`

   .. unmitigated::
      :impact: VH
      :likelihood: VH

   .. residual::
      :impact: VH
      :likelihood: VL

.. threat:: Eavesdropping
   :id: EAVESDROPPING

   .. description::
      An attacker accesses data in transit, either between the caller and the storage service, or between the storage service and the storage medium.

      In all deployment models, by the definition of an isolated partition in the :cite-title:`PSM`, transfer within the partition, and transfers between one  :term:`Secure Partition` and another are isolated from eavesdroppers.
      Therefore, if the caller is in a :term:`Secure Partition`, there is no possibility of an eavesdropper accessing the data.
      However, if data is sent or returned to a caller in the :term:`Non-secure Processing Environment` (NSPE), although the data is securely delivered to the :term:`NSPE`, it is exposed to all users in the :term:`NSPE`.
      As previously noted, the implementation **transfers** the duty of separating users in the :term:`NSPE` to the OS.

      For deployment model `DM.PROTECTED`, the storage service and the storage medium are isolated.

      In `DM.EXPOSED`, any adversary that can obtain operating system privileges in the :term:`NSPE` will have access to all the memory and will therefore be able to eavesdrop on all data in transit.

      An attacker that is external to the processor, `AM.2`, will be able to exploit an eavesdropping attack if the bus to which the memory is attached is accessible via external pins.
      Otherwise, the attack is limited to internal attackers `AM.1`.

      In `DM.AUTHORIZED`, an attacker with access to the bus, or to intermediate data buffers, can eavesdrop and obtain the messages.

      In `DM.SECURE_LINK`, an attacker can only eavesdrop on any data transfer not protected by the secure channel.

   .. mitigations::
      :mitigation:`Encrypt`.
      **Transfer** to the implementation: for `DM.EXPOSED` and `DM.AUTHORIZED`, the data at rest must be encrypted.
      The storage service must apply the encryption to the data before it leaves the :term:`PRoT` partition.
      The encryption mechanism chosen must be sufficiently robust.
      The key used for encryption must be sufficiently protected, that is, it must only be available to the storage service.

      :mitigation:`PRoTRootedSecLink`.
      **Transfer** to the implementation: for `DM.SECURE_LINK`, communication with the storage medium must be over a well-designed secure channel.
      If the secure channel is not rooted in the :term:`PRoT` then any adversary in the partition (`AM.1`), or with access to the partition (`AM.2`), in which the channel terminates will be able to eavesdrop on traffic leaving the :term:`PRoT` before it is encrypted.
      The secure channel must be rooted within the PRoT.
      However, the stored data does not need to be separately encrypted beyond the protection provided by the secure channel.
      The private information required to establish the channel must be suitably protected by both the storage service and the storage medium.

      :mitigation:`UseSecurePartitions`.
      **Transfer** to the application: for all deployment models, place callers that handle sensitive data into separate partitions.
      To ensure that an attacker in the :term:`NSPE` cannot access the data sent by the caller to the storage service, or the replies the storage service returns to the caller, place all code that needs to use the storage service into one or more :term:`Secure Partition`, with one partition per service.


   .. security-goal:: :SG:`CONFIDENTIALITY`

   .. adversarial-model:: `AM.0`, `AM.1`, `AM.2`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a --- except for transfer of data to clients in the :term:`NSPE`
      :risk: n/a

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORIZED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: VH
      :likelihood: H

   .. residual:: DM.SECURE_LINK
      :impact: VH
      :likelihood: VL


.. threat:: Man In The Middle
   :id: MITM

   .. description::
      An attacker can actively interfere with communication and replace the transmitted data.
      In this threat the SRA only considers attackers between the storage service and the storage medium.
      An attacker interposing between the Caller and the storage service is considered under `T.SPOOF_READ` or `T.SPOOF_WRITE`.

      For `DM.PROTECTED`, the storage service and the storage medium are isolated.

      For `DM.EXPOSED`, any code running in the :term:`NSPE` has access to the storage medium and any driver firmware, and therefore can act as a man in the middle, by for example persuading the storage service to write to one buffer, and the storage medium to read from another.

      For `DM.AUTHORIZED`, a man in the middle eavesdrops on data in transit.

      For `DM.SECURE_LINK`, a naive secure channel is vulnerable to a man in the middle attack.

   .. mitigations::
      `M.Encrypt`.
      **Transfer** to the implementation: if data is encrypted, a man in the middle cannot know what data is being transferred.
      It also means they cannot force a specific value to be stored.

      :mitigation:`MAC`.
      **Transfer** to the implementation: for `DM.EXPOSED`, apply a Message Authentication Code or a signature to the stored data, or use an authenticated encryption scheme. If the storage service checks the MAC or tag when data is read back from the storage medium to detect unauthorized modification.

      :mitigation:`UniqueKeys`.
      **Transfer** to the implementation: for `DM.AUTHORIZED` and `DM.SECURE_LINK`, use unique keys for securing the authenticated or secure channel.
      If the keys used by the storage medium are unique to each instance, as an attacker can only learn the key used on this specific instance.
      They cannot construct a class break by discovering the key for every instance.

      :mitigation:`VerifyReplies`.
      **Transfer** to the implementation: for `DM.AUTHORIZED`, commands and replies are authenticated by the storage medium.
      Therefore, the man in the middle cannot forge a valid reply which indicates that the data has been stored when it has not.
      If the storage service validates replies from the storage medium, it can verify that the data it sent was correctly stored, and the data retrieved is the value previously stored.

      :mitigation:`AuthenticateEndpoints`.
      **Transfer** to the implementation: for `DM.SECURE_LINK`, use mutual authentication of the storage service and storage medium when setting up the secure channel.
      For example, this can be achieved by using a single key, known only to both parties.

      :mitigation:`ReplayProtection`.
      **Transfer** to the implementation: for `DM.AUTHORIZED` and `DM.SECURE_LINK`, use replay protection in the communication protocol.
      This can be achieved by including a nonce in the construction of protocol messages.
      This enables the storage medium to detect attempts to replay previous commands and reject them.

   .. security-goal:: :SG:`INTEGRITY`
   .. adversarial-model:: `AM.1`, `AM.2`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORIZED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: H
      :likelihood: H

   .. residual:: DM.SECURE_LINK
     :impact: H
     :likelihood: VL


.. threat:: Bypassing the API to directly read data
   :id: DIRECT_READ

   .. description::
      An attacker might be able to read stored data through a mechanism other than the API.

      In `DM.PROTECTED`, no attacker should be able to access the stored data.

      In `DM.EXPOSED`, all attackers can access the data.

      In `DM.AUTHORIZED`, the attacker cannot form valid requests to access data.
      It can, however, eavesdrop on a legitimate request and replay it later.

      In `DM.SECURE_LINK`, the attacker cannot form valid requests to access data.
      It can, however, eavesdrop on a legitimate request and even if it cannot understand it, it could replay it later.

   .. adversarial-model:: `AM.1`, `AM.2`

   .. security-goal:: :SG:`CONFIDENTIALITY`

   .. mitigations::
      `M.ReplayProtection`.
      **Transfer** to the implementation: for `DM.AUTHORIZED` and `DM.SECURE_LINK`, use replay protection in the communication protocol.

      `M.Encrypt`.
      **Transfer** to the implementation: for `DM.EXPOSED` and `DM.AUTHORIZED`, encrypting the data prevents disclosure.

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORIZED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: H
      :likelihood: H

   .. residual:: DM.SECURE_LINK
     :impact: H
     :likelihood: VL



.. threat:: Bypassing the API to directly modify data
   :id: DIRECT_WRITE

   .. description:: An attacker might be able to modify data stored for another caller.

      In `DM.PROTECTED`, no attacker should be able to access the stored data.

      In `DM.EXPOSED`, the SRA assumes that any attacker capable of running code in the :term:`NSPE` can modify the stored data.
      However, assuming it is encrypted, the attacker cannot create the correct ciphertext for chosen plain text.

      In `DM.AUTHORIZED`, although the attacker cannot form a valid command, the attacker can eavesdrop on a legitimate request and replay it later.

      In `DM.SECURE_LINK`, although the attacker cannot form a valid command, the attacker can eavesdrop on a legitimate request and replay it later.


   .. adversarial-model:: `AM.1` `AM.2`

   .. security-goal:: `SG.INTEGRITY`, `SG.CURRENCY`

   .. mitigations::
      `M.Encrypt`.
      **Transfer** to the implementation: encrypted data cannot be modified to an attacker-chosen plaintext value.
      However, an attacker can still corrupt the stored data.

      `M.MAC`.
      **Transfer** to the implementation: for `DM.EXPOSED`, integrity-protect the stored data using a MAC, signature, or AEAD scheme.
      The verification of data integrity must be implemented within the storage service in the :term:`PRoT`, otherwise the result could be spoofed.

      `M.ReplayProtection`.
      **Transfer** to the implementation: for `DM.AUTHORIZED` and `DM.SECURE_LINK`, if the channel protocol includes replay protection, the storage medium will check the nonce for freshness, and prevent replay of old messages.

      :mitigation:`AntiRollback`.
      **Transfer** to the implementation: in `DM.EXPOSED`, `M.MAC` is insufficient to prevent an attacker from replacing one version of stored data --- or the entire contents of the storage medium --- with a previously stored version.
      The previously stored data would pass the integrity checks.

      To prevent this attack, the storage service must keep some authentication data in a location the attacker cannot access.
      This location could be stored within the :term:`PRoT` partition, that is using the `DM.PROTECTED`, or in a separate secure enclave using the deployment model `DM.AUTHORIZED` or `DM.SECURE_LINK`.
      The data could be the root of a hash tree, or it could be a counter used with a root key to generate a version-specific MAC key.

      In the case of a counter, some consideration should be given to the expected number of updates that will be made to the data.
      If the implementation only needs to offer rollback protection on firmware updates, where a low number is expected in the lifetime of the product and the counter could be stored in fuse.
      If the implementations needs to ensure the currency of a file store that is regularly updated --- the number of updates could exhaust any practical number of fuses and would instead need a 32-bit counter.


   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORIZED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: H
      :likelihood: H

   .. residual:: DM.SECURE_LINK
     :impact: H
     :likelihood: VL


.. threat:: Physical replacement of the storage medium
   :id: REPLACE

   .. description:: An attacker might physically replace the storage medium.

      For `DM.PROTECTED`, it is not possible to replace the storage.

      For `DM.EXPOSED`, if the storage medium is integrated with the chip, it is not possible to replace the storage.
      But in many systems, the storage medium will be on a separate device.

      For `DM.AUTHORIZED` and `DM.SECURE_LINK`, it is possible to replace the storage medium.

   .. adversarial-model:: `AM.3`

   .. security-goal:: `SG.INTEGRITY`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORIZED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: VH
      :likelihood: H

   .. residual:: DM.SECURE_LINK
     :impact: H
     :likelihood: VL

   .. mitigations::
      `M.UniqueKeys` and `M.MAC`.
      **Transfer** to the implementation: for `DM.EXPOSED`, use device-specific secret keys to authenticate the stored data.
      With unique authentication keys, data stored on one device cannot be verified on another device.

     `M.UniqueKeys` and `M.VerifyReplies`.
     **Transfer** to the implementation: for `DM.AUTHORIZED` and `DM.SECURE_LINK`, use device-specific secret keys to authenticate the communication between the storage service and storage medium.

     In `DM.AUTHORIZED`, the attacker will not be able to find a new instance of the storage medium that can form the correct responses to commands.

     In `DM.SECURE_LINK`, the attacker will not be able to find a new instance of the storage medium that can complete the handshake to set up the secure channel.

.. threat:: Glitching during a read
   :id: GLITCH_READ

   .. description:: An attacker with physical access might be able to disrupt the power or clock to cause a misread.

      In this threat, an attacker with physical access to the device causes a power or frequency glitch to cause a misread.
      In particular, it might prevent the storage service from performing the verification of replies or causing it to ignore the result of any check.
      Thus, causing the storage service to return an incorrect value to the caller.

   .. adversarial-model:: `AM.3`

   .. security-goal:: `SG.INTEGRITY`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: H

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: L

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: H

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: L

   .. residual:: DM.AUTHORIZED
     :impact: VH
     :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: VH
      :likelihood: L

   .. residual:: DM.SECURE_LINK
     :impact: VH
     :likelihood: VL

   .. mitigations::
      :mitigation:`GlitchDetection`.
      **Transfer** to the implementation: for all deployment models, active glitch detection circuits can raise an exception if a glitch is detected, permitting the computing circuitry to take corrective action.


.. threat:: Glitching during a write
   :id: GLITCH_WRITE

   .. description:: An attacker with physical access might be able to disrupt the power or clock to prevent a write from being completed.

      In this threat, an attacker with physical access to the device causes a power or frequency glitch to cause a write to fail.

   .. adversarial-model:: `AM.3`

   .. security-goal:: `SG.INTEGRITY`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: H

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: L

   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: H

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORIZED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORIZED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_LINK
      :impact: VH
      :likelihood: H

   .. residual:: DM.SECURE_LINK
     :impact: H
     :likelihood: VL

   .. mitigations::
      `M.MAC`.
      **Transfer** to the implementation:

      *  For `DM.PROTECTED` and `DM.EXPOSED`, if the implementation applies a MAC, a subsequent read can detect that data had not been written correctly.
         However, MAC's are not error correcting, therefore the implementation can only mark the data as corrupt and the data is lost.

      *  For `DM.AUTHORIZED` and `DM.SECURE_LINK`, if the implementation relies on the channel to provide the MAC or tag, there is a brief time of check, time of use (TOCTOU) window, where the storage medium has verified the command but has not written the data to physical storage.
         If a glitch occurs in this window, and then a subsequent read occurs, the storage medium will apply a new tag to a reply containing corrupt data, and the storage service will not be aware that that data returned has been corrupted.
         However, if the storage service applies a MAC before submitting the command, it can detect, but not correct, this corruption.

      :mitigation:`ErrorCorrectingCoding`.
      **Transfer** to the implementation: for all deployment models, if the storage medium uses error correcting codes (ECC), it can detect and correct a certain number of incorrect bits in the data it reads back --- at the expense of extra storage.
      If the storage medium does not offer ECC capability, the storage service could apply it and verify the coding in software, although this is generally less efficient than hardware.

      `M.GlitchDetection`.
      **Transfer** to the implementation: for all deployment models, glitch detection can reduce the risk of a successful glitch.

      :mitigation:`ReadAfterWrite`.
      **Transfer** to the implementation: for all deployment models, perform a checked-read after a write in the storage service.
      The storage service can perform a read operation immediately after a write, while it still retains the original value in memory, and compare the two before reporting a successful write.
      However, this has performance challenges: therefore, the implementation can decide to do this on a sampling basis.


.. _sra-mitigations:

Mitigation Summary
------------------

This section provides a summary of the mitigations described in the threat analysis, organized by the entity responsible for providing the mitigation.

Architecture level mitigations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-architecture` lists the mitigations that are controlled by the architecture.

.. list-table:: Mitigations that are **controlled** by the Architecture
   :name: tab-sra-architecture
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable

   *  -  Mitigations
      -  Description
      -  Threats

   *  -  `M.MemoryBuffer`
      -  In all deployment models, input buffers are fully consumed by the implementation before returning from a function.
      -  `T.INTERFACE_ABUSE`

Implementation-level mitigations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-remediations` lists the mitigations that are transferred to the implementation.
These are also known as 'remediations'.

.. list-table:: Mitigations that are **transferred** to the implementation
   :name: tab-sra-remediations
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable

   *  -  Mitigations
      -  Description
      -  Threats

   *  -  `M.AntiRollback`
      -  When using `DM.EXPOSED`, the implementation must provide a mechanism to prevent an attacker from replacing the stored data with a version that was valid at a previous date.
         An attacker can use this attack to reinstate flawed firmware, or to return to a version with a broken credential.
      -  `T.DIRECT_WRITE`

   *  -  `M.AuthenticateEndpoints`
      -  When using `DM.AUTHORIZED` or `DM.SECURE_LINK`, the storage service must authenticate the storage medium before reading from it or writing to it.
      -  `T.MITM`

   *  -  `M.Encrypt`
      -  When using `DM.EXPOSED` or `DM.AUTHORIZED`, the storage service must encrypt data to be written to storage, and decrypt data read from storage, inside the isolated environment to ensure confidentiality.
      -  `T.EAVESDROPPING`, `T.MITM`, `T.DIRECT_READ`, `T.DIRECT_WRITE`

   *  -  `M.ErrorCorrectingCoding`
      -  In all deployments, to deter attacks based on glitching the power or clock, the implementation can implement error correcting coding on stored data.
      -  `T.GLITCH_WRITE`

   *  -  `M.FullyQualifiedNames`
      -  In all deployments, the implementation must identify which caller each stored object belongs to and must refer to them internally by the combination of caller identity and name.
         Otherwise, it might return a stored object to the wrong caller.
      -  `T.SPOOF_READ`, `T.SPOOF_WRITE`

   *  -  `M.ImplicitIdentity`
      -  In all deployments, the implementation must identify the caller.
      -  `T.SPOOF_READ`, `T.SPOOF_WRITE`

   *  -  `M.GlitchDetection`
      -  In all deployments, to deter attacks based on glitching the power or clock, the implementation can implement detection circuits.
      -  `T.GLITCH_READ`, `T.GLITCH_WRITE`

   *  -  `M.MAC`
      -  In `DM.EXPOSED`, the storage service must apply an integrity check, a MAC, signature, or authenticated encryption tag, within the storage service before it is sent to storage.
         It must also verify this on every read.
      -  `T.MITM`, `T.DIRECT_WRITE`, `T.REPLACE`

   *  -  `M.PRoTRootedSecLink`
      -  In `DM.SECURE_LINK`, the storage service must use a secure channel rooted within the isolated environment to ensure there is no opportunity for eavesdropping.
      -  `T.EAVESDROPPING`

   *  -  `M.ReadAfterWrite`
      -  To deter glitch attacks on writing data, the implementation can read the data it has just written to verify it.
      -  `T.GLITCH_WRITE`

   *  -  `M.ReplayProtection`
      -  In `DM.AUTHORIZED` and `DM.SECURE_LINK` there must be protection against an attacker replaying previous messages.
      -  `T.DIRECT_READ`,  `T.DIRECT_WRITE`

   *  -  `M.UniqueKeys`
      -  In `DM.AUTHORIZED` and `DM.SECURE_LINK` the keys used by the storage service and storage medium must be unique, otherwise there is no mechanism for detecting that the storage medium has been replaced.
      -  `T.MITM`, `T.REPLACE`

   *  -  `M.ValidateParameter`
      -  In all deployment models, check all API parameters to lie within valid ranges, including memory access permissions.
      -  `T.INTERFACE_ABUSE`

   *  -  `M.VerifyReplies`
      -  In `DM.AUTHORIZED` and `DM.SECURE_LINK` the storage service must verify all replies from the partition that implements storage, to ensure that they do indeed come from the expected partition and no errors are reported.
      -  `T.MITM`, `T.REPLACE`


User-level mitigations
^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-residual-risk` lists mitigations that are transferred to the application or other external components.
These are also known as 'residual risks'.

.. list-table:: Mitigations that are **transferred** to the application
   :name: tab-sra-residual-risk
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable


   *  -  Mitigations
      -  Description
      -  Threats

   *  -  `M.UseSecurePartitions`
      -  In all deployments, if the caller wants to be certain that there is no chance of eavesdropping, they should make use of caller isolation, with each caller in its own isolated partition.
      -  `T.EAVESDROPPING`

Mitigations required by each deployment model
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-api-mitigations` summarizes the mitigations required in each deployment model.

.. list-table:: Mitigations required by each deployment model
   :name: tab-sra-api-mitigations
   :widths: 1 3
   :header-rows: 1
   :class: longtable

   *  -  Implementation
      -  Mitigations


   *  -  `DM.PROTECTED`
      -  `M.ErrorCorrectingCoding`,
         `M.FullyQualifiedNames`,
         `M.GlitchDetection`,
         `M.ImplicitIdentity`,
         `M.MemoryBuffer`,
         `M.ReadAfterWrite`,
         `M.UseSecurePartitions`,
         `M.ValidateParameter`

   *  -  `DM.EXPOSED`
      -  `M.AntiRollback`,
         `M.Encrypt`,
         `M.ErrorCorrectingCoding`,
         `M.FullyQualifiedNames`,
         `M.GlitchDetection`,
         `M.ImplicitIdentity`,
         `M.MAC`,
         `M.MemoryBuffer`,
         `M.ReadAfterWrite`,
         `M.UseSecurePartitions`,
         `M.ValidateParameter`

   *  -  `DM.AUTHORIZED`
      -  `M.AuthenticateEndpoints`,
         `M.ErrorCorrectingCoding`,
         `M.FullyQualifiedNames`,
         `M.GlitchDetection`,
         `M.ImplicitIdentity`,
         `M.MemoryBuffer`,
         `M.ReadAfterWrite`,
         `M.ReplayProtection`,
         `M.UniqueKeys`,
         `M.UseSecurePartitions`,
         `M.VerifyReplies`,
         `M.ValidateParameter`

   *  -  `DM.SECURE_LINK`
      -  `M.AuthenticateEndpoints`,
         `M.ErrorCorrectingCoding`,
         `M.FullyQualifiedNames`,
         `M.GlitchDetection`,
         `M.ImplicitIdentity`,
         `M.MemoryBuffer`,
         `M.PRoTRootedSecLink`,
         `M.ReadAfterWrite`,
         `M.ReplayProtection`,
         `M.UniqueKeys`,
         `M.UseSecurePartitions`,
         `M.VerifyReplies`,
         `M.ValidateParameter`


In implementations `DM.PROTECTED` and `DM.SECURE_LINK`, the stored data can be implicitly trusted, and therefore it is not required to be encrypted or authenticated.
There is no more secure location to store verification data, therefore, any attacker able to access the stored data would also be able to access the key.
However, it is possible for the data to be accidentally corrupted, therefore standard engineering practice to guard against this, for example the use of error correcting codes, should be used.

In implementation `DM.EXPOSED`, the data can be read or modified by an attacker, therefore the storage service must provide confidentiality, integrity, and authenticity by cryptographic means.
The keys used to do this must be stored securely.
This could be a key derived from the HUK, or separately stored in fuse in a location only readable from the :term:`PRoT`.

As the attacker can always read and modify the stored data, even if they cannot decrypt the data, they can attempt to subvert a change by resetting the storage medium to a prior state.
To detect this, the storage service needs to have some means of authenticating that it is reading the most recent state.
This implies some form of authentication data stored in a location the attacker cannot modify.

In implementation `DM.AUTHORIZED`, the data can be observed, even if it cannot be modified.
Therefore, data stored does need to be encrypted for confidentiality.
However, provided the authentication protocol is strong, and prevents replay, it should not be possible for an attacker to modify the stored data.
As the store applies a MAC to each reply, the storage service does not need to apply extra integrity.

In implementation `DM.SECURE_LINK` provided the secure channel is rooted within the :term:`PRoT`, the data transferred cannot be observed, and any modification will be detected.
Therefore, no further encryption is needed for confidentiality or integrity.
