/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "sc_csp.h"

#include <zephyr/logging/log.h>

#define LOOP_START_EVENT (0U)
#define LOOP_STOP_EVENT  (1U)
#define LOG_ENABLE       (true)
#define LOG_DISABLE      (false)

#define HWTEST_LOG_INF(log, format, ...)                                                           \
	if (log) {                                                                                 \
		LOG_INF(format, ##__VA_ARGS__);                                                    \
	}
#define HWTEST_LOG_DBG(log, format, ...)                                                           \
	if (log) {                                                                                 \
		LOG_DBG(format, ##__VA_ARGS__);                                                    \
	}
#define HWTEST_LOG_ERR(log, format, ...)                                                           \
	if (log) {                                                                                 \
		LOG_ERR(format, ##__VA_ARGS__);                                                    \
	}

#define SYSHK_FIFO_NUM (10U)

struct all_test_result {
	uint32_t loop_count;
	uint32_t err_cnt;
	char version[32];
	char last_cmd[32];
};
