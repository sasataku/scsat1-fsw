/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/storage/flash_map.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(sc_flash);

#include "sc_fpgasys.h"

int sc_erase_cfg_mem(enum sc_cfgmem bank, uint8_t id, off_t offset, size_t size)
{
	int ret = 0;
	const struct flash_area *flash = NULL;

	ret = sc_select_cfgmem(bank);
	if (ret < 0) {
		LOG_ERR("Failed to select the config memory (bank:%d)", bank);
		goto end;
	}

	ret = flash_area_open(id, &flash);
	if (ret < 0) {
		LOG_ERR("Failed to open the partition (bank:%d, id:%d)", bank, id);
		goto end;
	}

	ret = flash_area_erase(flash, offset, size);
	if (ret < 0) {
		LOG_ERR("Failed to erase the partition (bank:%d, id:%d)", bank, id);
	} else {
		LOG_INF("Finish to erase the partition (bank:%d, id:%d, offset:%ld, size:%d)", bank,
			id, offset, size);
	}

	flash_area_close(flash);

end:
	return ret;
}
