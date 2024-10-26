/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/byteorder.h>
#include <csp/csp.h>
#include "file.h"
#include "sc_csp.h"
#include "reply.h"
#include "sc_fpgaconf.h"
#include "sc_fpgasys.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(file, CONFIG_SC_LIB_CSP_LOG_LEVEL);

/* Command size */
#define FILE_CMD_MIN_SIZE  (1U)
#define FILE_INFO_CMD_SIZE (1U) /* without file name length */

/* Command ID */
#define FILE_INFO_CMD        (0U)
#define FILE_COPY_TO_CFG_CMD (1U)

/* Command argument offset */
#define FILE_FNAME_OFFSET (1U)

static int copy_file_to_cfg(uint8_t bank, uint8_t partition_id, const char *src_file)
{
	int ret;
	const struct flash_area *flash = NULL;
	struct fs_file_t file;
	struct fs_dirent entry;
	uint8_t buffer[256];
	off_t offset = 0;
	ssize_t size;

	LOG_INF("Copy Start");

	fs_file_t_init(&file);

	ret = fs_open(&file, src_file, FS_O_READ);
	if (ret < 0) {
		LOG_ERR("Faild to open the src file %s (%d)", src_file, ret);
	}

	ret = fs_stat(src_file, &entry);
	if (ret < 0) {
		LOG_ERR("Faild to get the file info %s (%d)", src_file, ret);
	}

	ret = sc_select_cfgmem(bank);
	if (ret < 0) {
		goto end;
	}

	ret = flash_area_open(partition_id, &flash);
	if (ret < 0) {
		LOG_ERR("Failed to open flash area");
		goto end;
	}

	size_t remainig_size = entry.size;

	while (remainig_size) {
		size = fs_read(&file, buffer, 256);
		if (ret < 0) {
			LOG_ERR("Failed to read from src file %s", src_file);
			break;
		}

		ret = flash_area_write(flash, offset, buffer, size);
		if (ret < 0) {
			LOG_ERR("Failed to write to NOR flash");
			break;
		}

		offset += size;
		remainig_size -= size;
	}

	flash_area_close(flash);

	LOG_INF("Finish Copy");

end:
	return ret;
}

static int csp_get_file_info(const char *fname, struct fs_dirent *entry)
{
	int ret;

	ret = fs_stat(fname, entry);
	if (ret < 0) {
		LOG_ERR("Faild to get the file info %s (%d)", fname, ret);
	}

	LOG_INF("File Info: (entry %d) (size: %u) (name: %s)", entry->type, entry->size,
		entry->name);

	return ret;
}

static void csp_send_file_info_reply(struct fs_dirent *entry, csp_packet_t *packet,
				     uint8_t command_id, int err_code)
{
	struct file_info_telemetry tlm;

	if (err_code) {
		memset(&tlm, 0, sizeof(tlm));
	} else {
		tlm.entry_type = entry->type;
		tlm.file_size = sys_cpu_to_le32(entry->size);
		strncpy(tlm.file_name, entry->name, CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN);
		tlm.file_name[CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN - 1] = '\0';
	}

	tlm.telemetry_id = command_id;
	tlm.error_code = sys_cpu_to_le32(err_code);

	memcpy(packet->data, &tlm, sizeof(tlm));
	packet->length = sizeof(tlm);

	csp_sendto_reply(packet, packet, CSP_O_SAME);
}

static int csp_file_info_cmd(uint8_t command_id, csp_packet_t *packet)
{
	int ret = 0;
	char fname[CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN];
	struct fs_dirent entry;

	if (packet->length != FILE_INFO_CMD_SIZE + CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN) {
		LOG_ERR("Invalide command size: %d", packet->length);
		ret = -EINVAL;
		goto end;
	}

	strncpy(fname, &packet->data[FILE_FNAME_OFFSET], CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN);
	fname[CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN - 1] = '\0';

	LOG_INF("File info command (fname: %s)", fname);

	ret = csp_get_file_info(fname, &entry);

end:
	csp_send_file_info_reply(&entry, packet, command_id, ret);
	return ret;
}

static int csp_file_copy_to_cfg_cmd(uint8_t command_id, csp_packet_t *packet)
{
	int ret = 0;
	char src_file[CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN];
	off_t src_offset;
	uint8_t bank;
	off_t dst_offset;
	size_t size;

	strncpy(src_file, &packet->data[1], CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN);
	src_file[CONFIG_SC_LIB_CSP_FILE_NAME_MAX_LEN - 1] = '\0';
	src_offset = sys_le32_to_cpu(*(uint32_t *)&packet->data[65]);
	bank = packet->data[69];
	dst_offset = sys_le32_to_cpu(*(uint32_t *)&packet->data[70]);
	size = sys_le32_to_cpu(*(uint32_t *)&packet->data[74]);

	LOG_INF("File copy to config mem command (src: %s) (src offset: %ld) (dst bank: %d) (dst offste: %ld) (size: %d)",
		src_file, src_offset, bank, dst_offset, size);

	/* TODO: partion ID */
	copy_file_to_cfg(bank, 2, src_file);

	return ret;
}

int csp_file_handler(csp_packet_t *packet)
{
	int ret;
	uint8_t command_id;

	if (packet == NULL) {
		ret = -EINVAL;
		goto end;
	}

	if (packet->length < FILE_CMD_MIN_SIZE) {
		LOG_ERR("Invalide command size: %d", packet->length);
		ret = -EINVAL;
		goto free;
	}

	command_id = packet->data[CSP_COMMAND_ID_OFFSET];

	switch (command_id) {
	case FILE_INFO_CMD:
		csp_file_info_cmd(command_id, packet);
		break;
	case FILE_COPY_TO_CFG_CMD:
		csp_file_copy_to_cfg_cmd(command_id, packet);
		break;
	default:
		LOG_ERR("Unkown command code: %d", command_id);
		ret = -EINVAL;
		break;
	}

free:
	csp_buffer_free(packet);

end:
	return ret;
}
