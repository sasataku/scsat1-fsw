# Copyright (c) 2024 Space Cubics, LLC.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(core)
add_subdirectory_ifdef(CONFIG_SC_LIB_FLASH flash)
