/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

int sc_erase_cfg_mem(uint8_t bank, uint8_t id, off_t offset, size_t size);
