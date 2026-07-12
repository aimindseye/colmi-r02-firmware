/*
 * Build-only SDK3 task adapter for the verified RingCLI protocol core.
 *
 * Hardware effects are intentionally inert. The adapter implements GATT
 * routing, CCCD state, write confirmations, and notifications only.
 */

#include "rwip_config.h"

#include "gap.h"
#include "gattc_task.h"
#include "user_profile.h"
#include "user_profile_task.h"
#include "ry02_ringcli_protocol.h"

#include "ke_mem.h"
#include "ke_msg.h"

#include <string.h>

static struct ry02_protocol_state protocol_state =
{
    .battery_level = 78,
    .charging = false,
    .heart_period_enabled = false,
    .heart_period = 60,
    .realtime_active = false,
    .realtime_type = 0,
};

static uint16_t notify_sequence = 0;

static int send_notification(
    uint16_t handle,
    const uint8_t *bytes,
    uint8_t length
)
{
    struct gattc_send_evt_cmd *notify_cmd;

    if ((handle == 0) || (bytes == NULL) || (length == 0))
    {
        return -1;
    }

    notify_cmd = KE_MSG_ALLOC_DYN(
        GATTC_SEND_EVT_CMD,
        TASK_GATTC,
        TASK_APP,
        gattc_send_evt_cmd,
        length
    );

    notify_cmd->operation = GATTC_NOTIFY;
    notify_cmd->seq_num = notify_sequence++;
    notify_cmd->length = length;
    notify_cmd->handle = handle;

    memcpy(notify_cmd->value, bytes, length);
    ke_msg_send(notify_cmd);

    return 0;
}

int ry02_profile_notify_command(const uint8_t *bytes, uint8_t length)
{
    if ((ry02_user_profile_env == NULL)
        || (ry02_user_profile_env->command_notify_enabled == 0))
    {
        return -1;
    }

    return send_notification(
        ry02_command_notify_handle(),
        bytes,
        length
    );
}

int ry02_profile_notify_data(const uint8_t *bytes, uint8_t length)
{
    if ((ry02_user_profile_env == NULL)
        || (ry02_user_profile_env->data_notify_enabled == 0))
    {
        return -1;
    }

    return send_notification(
        ry02_data_notify_handle(),
        bytes,
        length
    );
}

int ry02_profile_notify_realtime_value(uint8_t value)
{
    uint8_t packet[RY02_COMMAND_PACKET_SIZE];

    if (!protocol_state.realtime_active)
    {
        return -1;
    }

    ry02_make_realtime_value_notification(
        protocol_state.realtime_type,
        value,
        packet
    );

    return ry02_profile_notify_command(
        packet,
        (uint8_t)sizeof(packet)
    );
}

static void send_write_confirmation(
    struct gattc_write_req_ind *param,
    ke_task_id_t const dest_id,
    ke_task_id_t const src_id,
    uint8_t status
)
{
    struct gattc_write_cfm *cfm = KE_MSG_ALLOC(
        GATTC_WRITE_CFM,
        src_id,
        dest_id,
        gattc_write_cfm
    );

    cfm->handle = param->handle;
    cfm->status = status;
    ke_msg_send(cfm);
}

static uint8_t cccd_enabled(
    const struct gattc_write_req_ind *param
)
{
    return (param->length >= 2)
        && (param->value[0] == 0x01)
        && (param->value[1] == 0x00);
}

static int gattc_write_req_ind_handler(
    ke_msg_id_t const msgid,
    struct gattc_write_req_ind *param,
    ke_task_id_t const dest_id,
    ke_task_id_t const src_id
)
{
    uint8_t response[RY02_COMMAND_PACKET_SIZE];
    struct ry02_result protocol_result;
    uint8_t request_id = 0;

    (void)msgid;

    if ((ke_state_get(dest_id) != USER_PROFILE_IDLE)
        || (ry02_user_profile_env == NULL))
    {
        send_write_confirmation(
            param,
            dest_id,
            src_id,
            GAP_ERR_NO_ERROR
        );
        return KE_MSG_CONSUMED;
    }

    if (param->handle == ry02_command_cccd_handle())
    {
        ry02_user_profile_env->command_notify_enabled = cccd_enabled(param);
    }
    else if (param->handle == ry02_data_cccd_handle())
    {
        ry02_user_profile_env->data_notify_enabled = cccd_enabled(param);
    }
    else if (param->handle == ry02_command_write_handle())
    {
        memset(response, 0, sizeof(response));

        protocol_result = ry02_handle_command(
            &protocol_state,
            param->value,
            param->length,
            response
        );

        if ((protocol_result.status == RY02_STATUS_OK)
            && (protocol_result.response_length
                == RY02_COMMAND_PACKET_SIZE))
        {
            ry02_profile_notify_command(
                response,
                (uint8_t)protocol_result.response_length
            );
        }

        /*
         * Hardware effects remain intentionally inert:
         *   TIME_SET, FLASH_LED, SHUTDOWN, and sensor control are recorded
         *   only in protocol_state or protocol_result.
         */
    }
    else if (param->handle == ry02_data_write_handle())
    {
        /*
         * r1 recognizes the two verified history requests but does not yet
         * synthesize sleep or oxygen history responses.
         */
        (void)ry02_parse_data_request(
            param->value,
            param->length,
            &request_id
        );
    }

    send_write_confirmation(
        param,
        dest_id,
        src_id,
        GAP_ERR_NO_ERROR
    );

    return KE_MSG_CONSUMED;
}

static int gattc_read_req_ind_handler(
    ke_msg_id_t const msgid,
    struct gattc_read_req_ind const *param,
    ke_task_id_t const dest_id,
    ke_task_id_t const src_id
)
{
    struct gattc_read_cfm *cfm;
    uint16_t value = 0;

    (void)msgid;

    if (ry02_user_profile_env != NULL)
    {
        if (param->handle == ry02_command_cccd_handle())
        {
            value = ry02_user_profile_env->command_notify_enabled ? 1 : 0;
        }
        else if (param->handle == ry02_data_cccd_handle())
        {
            value = ry02_user_profile_env->data_notify_enabled ? 1 : 0;
        }
    }

    cfm = KE_MSG_ALLOC_DYN(
        GATTC_READ_CFM,
        src_id,
        dest_id,
        gattc_read_cfm,
        2
    );

    cfm->handle = param->handle;
    cfm->status = ATT_ERR_NO_ERROR;
    cfm->length = 2;
    cfm->value[0] = (uint8_t)(value & 0xFF);
    cfm->value[1] = (uint8_t)((value >> 8) & 0xFF);

    ke_msg_send(cfm);
    return KE_MSG_CONSUMED;
}

static int gattc_cmp_evt_handler(
    ke_msg_id_t const msgid,
    struct gattc_cmp_evt const *param,
    ke_task_id_t const dest_id,
    ke_task_id_t const src_id
)
{
    (void)msgid;
    (void)param;
    (void)dest_id;
    (void)src_id;
    return KE_MSG_CONSUMED;
}

static const struct ke_msg_handler user_default_handler[] =
{
    {
        GATTC_WRITE_REQ_IND,
        (ke_msg_func_t)gattc_write_req_ind_handler
    },
    {
        GATTC_READ_REQ_IND,
        (ke_msg_func_t)gattc_read_req_ind_handler
    },
    {
        GATTC_CMP_EVT,
        (ke_msg_func_t)gattc_cmp_evt_handler
    },
};

const struct ke_state_handler userp_default_handler =
    KE_STATE_HANDLER(user_default_handler);
