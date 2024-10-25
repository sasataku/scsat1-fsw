/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/fs/fs.h>
#include <zephyr/sys/byteorder.h>
#include <csp/csp.h>
#include "sc_csp.h"
#include "reply.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(upload, CONFIG_SCSAT1_MAIN_LOG_LEVEL);

/* Command size */
#define UPLOAD_CMD_MIN_SIZE (1U)
#define UPLOAD_WRQ_CMD_SIZE (3U) /* with out file name length */

/* Command ID */
#define UPLOAD_WRQ_CMD (0U)

/* Command argument offset */
#define UPLOAD_SID_OFFSET   (1U)
#define UPLOAD_FNAME_OFFSET (3U)

static struct fs_file_t cur_upload_file;

static int csp_open_upload_file(const char *fname)
{
	struct fs_file_t file;
	int ret;

	fs_file_t_init(&file);

	ret = fs_open(&file, fname, FS_O_CREATE | FS_O_RDWR);
	if (ret < 0) {
		LOG_ERR("Faild to open the upload file %s (%d)", fname, ret);
	}

	cur_upload_file = file;

	return ret;
}

static int csp_upload_wrq_cmd(uint8_t command_id, csp_packet_t *packet)
{
	int ret = 0;
	uint16_t session_id;
	char fname[CONFIG_SC_LIB_CSP_UPLOAD_FILE_NAME_LEN];

	if (packet->length != UPLOAD_WRQ_CMD_SIZE + CONFIG_SC_LIB_CSP_UPLOAD_FILE_NAME_LEN) {
		LOG_ERR("Invalide command size: %d", packet->length);
		ret = -EINVAL;
		goto end;
	}

	session_id = sys_le16_to_cpu(*(uint16_t *)&packet->data[UPLOAD_SID_OFFSET]);
	strncpy(fname, &packet->data[UPLOAD_FNAME_OFFSET], CONFIG_SC_LIB_CSP_UPLOAD_FILE_NAME_LEN);
	fname[CONFIG_SC_LIB_CSP_UPLOAD_FILE_NAME_LEN - 1] = '\0';

	LOG_INF("Upload (WRQ) command (session_id: %d) (fname: %s)", session_id, fname);

	ret = csp_open_upload_file(fname);

end:
	csp_send_std_reply(packet, command_id, ret);
	return ret;
}

int csp_upload_handler(csp_packet_t *packet)
{
	int ret;
	uint8_t command_id;

	if (packet == NULL) {
		ret = -EINVAL;
		goto end;
	}

	if (packet->length < UPLOAD_CMD_MIN_SIZE) {
		LOG_ERR("Invalide command size: %d", packet->length);
		ret = -EINVAL;
		goto free;
	}

	command_id = packet->data[CSP_COMMAND_ID_OFFSET];

	switch (command_id) {
	case UPLOAD_WRQ_CMD:
		csp_upload_wrq_cmd(command_id, packet);
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
