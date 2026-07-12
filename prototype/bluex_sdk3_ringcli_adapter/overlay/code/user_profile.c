/*
 * Build-only RingCLI-compatible BlueX SDK3 profile.
 *
 * This file creates two independent 128-bit UART-style services:
 *   command service: 16-byte request/notify protocol
 *   data service:    6-byte history-request protocol
 *
 * UUID arrays use the BlueX/stock-firmware reverse-byte storage order.
 */

#include "rwip_config.h"

#include "gap.h"
#include "gapm_task.h"
#include "gattc_task.h"
#include "attm.h"
#include "user_profile.h"
#include "user_profile_task.h"
#include "prf_utils.h"

#include "ke_mem.h"
#include "ke_msg.h"

#include "gattm_task.h"
#include "attm_db.h"

#include <string.h>

#define RY02_COMMAND_SERVICE_UUID_128 \
    {0x9E,0xCA,0xDC,0x24,0x0E,0xE5,0xA9,0xE0, \
     0x93,0xF3,0xA3,0xB5,0xF0,0xFF,0x40,0x6E}

#define RY02_COMMAND_WRITE_UUID_128 \
    {0x9E,0xCA,0xDC,0x24,0x0E,0xE5,0xA9,0xE0, \
     0x93,0xF3,0xA3,0xB5,0x02,0x00,0x40,0x6E}

#define RY02_COMMAND_NOTIFY_UUID_128 \
    {0x9E,0xCA,0xDC,0x24,0x0E,0xE5,0xA9,0xE0, \
     0x93,0xF3,0xA3,0xB5,0x03,0x00,0x40,0x6E}

#define RY02_DATA_SERVICE_UUID_128 \
    {0xC7,0x5D,0x2A,0x01,0xE3,0x65,0x26,0xAF, \
     0x47,0x4E,0x11,0xD7,0x28,0xF7,0x5B,0xDE}

#define RY02_DATA_WRITE_UUID_128 \
    {0xC7,0x5D,0x2A,0x01,0xE3,0x65,0x26,0xAF, \
     0x47,0x4E,0x11,0xD7,0x2A,0xF7,0x5B,0xDE}

#define RY02_DATA_NOTIFY_UUID_128 \
    {0xC7,0x5D,0x2A,0x01,0xE3,0x65,0x26,0xAF, \
     0x47,0x4E,0x11,0xD7,0x29,0xF7,0x5B,0xDE}

#define RY02_MAX_VALUE_SIZE 244

#define ATT_DESC_CLIENT_CHAR_CFG_ARRAY {0x02,0x29}
#define ATT_DECL_CHAR_ARRAY            {0x03,0x28}

static const struct attm_desc_128 command_att_db[RY02_SVC_ATT_NUM] =
{
    [RY02_SVC_IDX_SVC] = {
        RY02_COMMAND_SERVICE_UUID_128,
        PERM(RD, ENABLE),
        0,
        0
    },
    [RY02_SVC_IDX_WRITE_CHAR] = {
        .uuid = ATT_DECL_CHAR_ARRAY,
        .perm = PERM(RD, ENABLE),
        .max_size = 0,
        .ext_perm = PERM(UUID_LEN, UUID_16),
    },
    [RY02_SVC_IDX_WRITE_VAL] = {
        .uuid = RY02_COMMAND_WRITE_UUID_128,
        .perm = PERM(WRITE_REQ, ENABLE)
              | PERM(WRITE_COMMAND, ENABLE)
              | PERM(WP, NO_AUTH),
        .max_size = RY02_COMMAND_PACKET_SIZE,
        .ext_perm = PERM(UUID_LEN, UUID_128) | PERM(RI, ENABLE),
    },
    [RY02_SVC_IDX_NOTIFY_CHAR] = {
        .uuid = ATT_DECL_CHAR_ARRAY,
        .perm = PERM(RD, ENABLE),
        .max_size = 0,
        .ext_perm = PERM(UUID_LEN, UUID_16),
    },
    [RY02_SVC_IDX_NOTIFY_VAL] = {
        .uuid = RY02_COMMAND_NOTIFY_UUID_128,
        .perm = PERM(NTF, ENABLE),
        .max_size = RY02_COMMAND_PACKET_SIZE,
        .ext_perm = PERM(UUID_LEN, UUID_128) | PERM(RI, ENABLE),
    },
    [RY02_SVC_IDX_NOTIFY_CFG] = {
        .uuid = ATT_DESC_CLIENT_CHAR_CFG_ARRAY,
        .perm = PERM(RD, ENABLE) | PERM(WRITE_REQ, ENABLE),
        .max_size = 2,
        .ext_perm = PERM(UUID_LEN, UUID_16),
    },
};

static const struct attm_desc_128 data_att_db[RY02_SVC_ATT_NUM] =
{
    [RY02_SVC_IDX_SVC] = {
        RY02_DATA_SERVICE_UUID_128,
        PERM(RD, ENABLE),
        0,
        0
    },
    [RY02_SVC_IDX_WRITE_CHAR] = {
        .uuid = ATT_DECL_CHAR_ARRAY,
        .perm = PERM(RD, ENABLE),
        .max_size = 0,
        .ext_perm = PERM(UUID_LEN, UUID_16),
    },
    [RY02_SVC_IDX_WRITE_VAL] = {
        .uuid = RY02_DATA_WRITE_UUID_128,
        .perm = PERM(WRITE_REQ, ENABLE)
              | PERM(WRITE_COMMAND, ENABLE)
              | PERM(WP, NO_AUTH),
        .max_size = RY02_DATA_REQUEST_SIZE,
        .ext_perm = PERM(UUID_LEN, UUID_128) | PERM(RI, ENABLE),
    },
    [RY02_SVC_IDX_NOTIFY_CHAR] = {
        .uuid = ATT_DECL_CHAR_ARRAY,
        .perm = PERM(RD, ENABLE),
        .max_size = 0,
        .ext_perm = PERM(UUID_LEN, UUID_16),
    },
    [RY02_SVC_IDX_NOTIFY_VAL] = {
        .uuid = RY02_DATA_NOTIFY_UUID_128,
        .perm = PERM(NTF, ENABLE),
        .max_size = RY02_MAX_VALUE_SIZE,
        .ext_perm = PERM(UUID_LEN, UUID_128) | PERM(RI, ENABLE),
    },
    [RY02_SVC_IDX_NOTIFY_CFG] = {
        .uuid = ATT_DESC_CLIENT_CHAR_CFG_ARRAY,
        .perm = PERM(RD, ENABLE) | PERM(WRITE_REQ, ENABLE),
        .max_size = 2,
        .ext_perm = PERM(UUID_LEN, UUID_16),
    },
};

struct user_profile_env_tag *ry02_user_profile_env = NULL;

static uint8_t attm_svc_create_db_128(
    uint16_t *shdl,
    const uint8_t *uuid,
    uint8_t *cfg_flag,
    uint8_t max_nb_att,
    uint8_t *att_tbl,
    ke_task_id_t const dest_id,
    const struct attm_desc_128 *att_db,
    uint8_t svc_perm
)
{
    uint8_t nb_att = 0;
    uint8_t i;
    uint8_t status = ATT_ERR_NO_ERROR;
    struct gattm_svc_desc *svc_desc;

    for (i = 1; i < max_nb_att; i++)
    {
        if ((cfg_flag == NULL) || (((cfg_flag[i / 8] >> (i % 8)) & 1) == 1))
        {
            nb_att++;
        }
    }

    svc_desc = (struct gattm_svc_desc *)ke_malloc(
        sizeof(struct gattm_svc_desc)
            + (sizeof(struct gattm_att_desc) * nb_att),
        KE_MEM_NON_RETENTION
    );

    svc_desc->start_hdl = *shdl;
    svc_desc->nb_att = nb_att;
    svc_desc->task_id = dest_id;
    svc_desc->perm = svc_perm;

    memcpy(
        svc_desc->uuid,
        uuid,
        (PERM_GET(svc_perm, SVC_UUID_LEN) == PERM_UUID_16)
            ? ATT_UUID_16_LEN
            : ((PERM_GET(svc_perm, SVC_UUID_LEN) == PERM_UUID_32)
                ? ATT_UUID_32_LEN
                : ATT_UUID_128_LEN)
    );

    nb_att = 0;

    for (i = 1; i < max_nb_att; i++)
    {
        if ((cfg_flag == NULL) || (((cfg_flag[i / 8] >> (i % 8)) & 1) == 1))
        {
            svc_desc->atts[nb_att].max_len = att_db[i].max_size;
            svc_desc->atts[nb_att].ext_perm = att_db[i].ext_perm;
            svc_desc->atts[nb_att].perm = att_db[i].perm;

            memcpy(
                svc_desc->atts[nb_att].uuid,
                &(att_db[i].uuid),
                (PERM_GET(att_db[i].ext_perm, UUID_LEN) == PERM_UUID_16)
                    ? ATT_UUID_16_LEN
                    : ((PERM_GET(att_db[i].ext_perm, UUID_LEN) == PERM_UUID_32)
                        ? ATT_UUID_32_LEN
                        : ATT_UUID_128_LEN)
            );

            nb_att++;
        }
    }

    status = attmdb_add_service(svc_desc);

    if (status == ATT_ERR_NO_ERROR)
    {
        *shdl = svc_desc->start_hdl;
        nb_att = 0;

        for (i = 0; (i < max_nb_att) && (att_tbl != NULL); i++)
        {
            if ((cfg_flag == NULL) || (((cfg_flag[i / 8] >> (i % 8)) & 1) == 1))
            {
                att_tbl[i] = *shdl + nb_att;
                nb_att++;
            }
        }
    }

    ke_free(svc_desc);
    return status;
}

static uint8_t user_init(
    struct prf_task_env *env,
    uint16_t *start_hdl,
    uint16_t app_task,
    uint8_t sec_lvl,
    struct user_db_cfg *params
)
{
    uint8_t status;
    uint16_t command_start = *start_hdl;
    uint16_t data_start = 0;
    uint8_t command_uuid[] = RY02_COMMAND_SERVICE_UUID_128;
    uint8_t data_uuid[] = RY02_DATA_SERVICE_UUID_128;
    struct user_profile_env_tag *user_env;

    (void)params;

    status = attm_svc_create_db_128(
        &command_start,
        command_uuid,
        NULL,
        RY02_SVC_ATT_NUM,
        NULL,
        env->task,
        command_att_db,
        PERM(SVC_MI, DISABLE)
            | PERM(SVC_EKS, DISABLE)
            | PERM(SVC_AUTH, NO_AUTH)
            | PERM(SVC_UUID_LEN, UUID_128)
    );

    if (status != ATT_ERR_NO_ERROR)
    {
        return status;
    }

    status = attm_svc_create_db_128(
        &data_start,
        data_uuid,
        NULL,
        RY02_SVC_ATT_NUM,
        NULL,
        env->task,
        data_att_db,
        PERM(SVC_MI, DISABLE)
            | PERM(SVC_EKS, DISABLE)
            | PERM(SVC_AUTH, NO_AUTH)
            | PERM(SVC_UUID_LEN, UUID_128)
    );

    if (status != ATT_ERR_NO_ERROR)
    {
        return status;
    }

    user_env = (struct user_profile_env_tag *)ke_malloc(
        sizeof(struct user_profile_env_tag),
        KE_MEM_ATT_DB
    );

    memset(user_env, 0, sizeof(*user_env));

    env->env = (prf_env_t *)user_env;

    user_env->command_start_hdl = command_start;
    user_env->data_start_hdl = data_start;
    user_env->connection_index = GAP_INVALID_CONIDX;

    user_env->prf_env.app_task = app_task
        | (PERM_GET(sec_lvl, SVC_MI)
            ? PERM(PRF_MI, ENABLE)
            : PERM(PRF_MI, DISABLE));
    user_env->prf_env.prf_task = env->task | PERM(PRF_MI, ENABLE);

    env->id = TASK_ID_USER;
    env->desc.idx_max = USER_PROFILE_IDX_MAX;
    env->desc.state = user_env->state;
    env->desc.default_handler = &userp_default_handler;

    *start_hdl = command_start;
    ry02_user_profile_env = user_env;

    ke_state_set(env->task, USER_PROFILE_IDLE);
    return status;
}

static void user_destroy(struct prf_task_env *env)
{
    struct user_profile_env_tag *user_env =
        (struct user_profile_env_tag *)env->env;

    ry02_user_profile_env = NULL;
    env->env = NULL;

    if (user_env != NULL)
    {
        ke_free(user_env);
    }
}

static void user_create(struct prf_task_env *env, uint8_t conidx)
{
    struct user_profile_env_tag *user_env =
        (struct user_profile_env_tag *)env->env;

    if (user_env != NULL)
    {
        user_env->connection_index = conidx;
        user_env->command_notify_enabled = 0;
        user_env->data_notify_enabled = 0;
    }
}

static void user_cleanup(
    struct prf_task_env *env,
    uint8_t conidx,
    uint8_t reason
)
{
    struct user_profile_env_tag *user_env =
        (struct user_profile_env_tag *)env->env;

    (void)conidx;
    (void)reason;

    if (user_env != NULL)
    {
        user_env->connection_index = GAP_INVALID_CONIDX;
        user_env->command_notify_enabled = 0;
        user_env->data_notify_enabled = 0;
    }
}

void app_user_add_profile(void)
{
    struct user_db_cfg *db_cfg;
    struct gapm_profile_task_add_cmd *req = KE_MSG_ALLOC_DYN(
        GAPM_PROFILE_TASK_ADD_CMD,
        TASK_GAPM,
        TASK_APP,
        gapm_profile_task_add_cmd,
        sizeof(struct user_db_cfg)
    );

    req->operation = GAPM_PROFILE_TASK_ADD;
    req->sec_lvl = PERM(SVC_AUTH, NO_AUTH);
    req->prf_task_id = TASK_ID_USER;
    req->app_task = TASK_APP;
    req->start_hdl = 0;

    db_cfg = (struct user_db_cfg *)req->param;
    db_cfg->features = USER_ALL_SUP;

    ke_msg_send(req);
}

static const struct prf_task_cbs user_itf =
{
    (prf_init_fnct)user_init,
    user_destroy,
    user_create,
    user_cleanup,
};

const struct prf_task_cbs *user_profile_prf_itf_get(void)
{
    return &user_itf;
}

uint16_t ry02_command_write_handle(void)
{
    return ry02_user_profile_env == NULL
        ? 0
        : ry02_user_profile_env->command_start_hdl + RY02_SVC_IDX_WRITE_VAL;
}

uint16_t ry02_command_notify_handle(void)
{
    return ry02_user_profile_env == NULL
        ? 0
        : ry02_user_profile_env->command_start_hdl + RY02_SVC_IDX_NOTIFY_VAL;
}

uint16_t ry02_command_cccd_handle(void)
{
    return ry02_user_profile_env == NULL
        ? 0
        : ry02_user_profile_env->command_start_hdl + RY02_SVC_IDX_NOTIFY_CFG;
}

uint16_t ry02_data_write_handle(void)
{
    return ry02_user_profile_env == NULL
        ? 0
        : ry02_user_profile_env->data_start_hdl + RY02_SVC_IDX_WRITE_VAL;
}

uint16_t ry02_data_notify_handle(void)
{
    return ry02_user_profile_env == NULL
        ? 0
        : ry02_user_profile_env->data_start_hdl + RY02_SVC_IDX_NOTIFY_VAL;
}

uint16_t ry02_data_cccd_handle(void)
{
    return ry02_user_profile_env == NULL
        ? 0
        : ry02_user_profile_env->data_start_hdl + RY02_SVC_IDX_NOTIFY_CFG;
}
