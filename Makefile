# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates
# SPDX-License-Identifier: Apache-2.0

PSA_API_TOOL = ../psa-api-tool

# The location of psa-api-tool must be specified
ifeq ($(wildcard $(PSA_API_TOOL)/make),)
 $(error The 'PSA_API_TOOL' variable is not set, or does not point to a suitable installation of psa-api-tool)
endif

include $(PSA_API_TOOL)/make
