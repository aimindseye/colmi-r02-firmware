#ifndef USER_PROFILE_H_
#define USER_PROFILE_H_

#include "rwip_config.h"
#include "prf_types.h"
#include "prf.h"

#include <stdint.h>

#define USER_PROFILE_IDX_MAX 1

enum
{
    USER_PROFILE_IDLE,
    USER_PROFILE_BUSY,
    USER_PROFILE_STATE_MAX
};

enum ry02_service_att_db_handles
{
    RY02_SVC_IDX_SVC = 0,
    RY02_SVC_IDX_WRITE_CHAR,
    RY02_SVC_IDX_WRITE_VAL,
    RY02_SVC_IDX_NOTIFY_CHAR,
    RY02_SVC_IDX_NOTIFY_VAL,
    RY02_SVC_IDX_NOTIFY_CFG,
    RY02_SVC_ATT_NUM
};

struct user_profile_env_tag
{
    prf_env_t prf_env;

    uint16_t command_start_hdl;
    uint16_t data_start_hdl;

    uint8_t command_notify_enabled;
    uint8_t data_notify_enabled;
    uint8_t connection_index;

    ke_state_t state[USER_PROFILE_IDX_MAX];
};

extern struct user_profile_env_tag *ry02_user_profile_env;
extern const struct ke_state_handler userp_default_handler;

const struct prf_task_cbs *user_profile_prf_itf_get(void);

uint16_t ry02_command_write_handle(void);
uint16_t ry02_command_notify_handle(void);
uint16_t ry02_command_cccd_handle(void);
uint16_t ry02_data_write_handle(void);
uint16_t ry02_data_notify_handle(void);
uint16_t ry02_data_cccd_handle(void);

int ry02_profile_notify_command(const uint8_t *bytes, uint8_t length);
int ry02_profile_notify_data(const uint8_t *bytes, uint8_t length);
int ry02_profile_notify_realtime_value(uint8_t value);

#endif
