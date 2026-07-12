#ifndef USER_PROFILE_TASK_H_
#define USER_PROFILE_TASK_H_

#include <stdint.h>
#include "rwip_task.h"
#include "prf_types.h"

enum user_features
{
    USER_ALL_SUP = 0x0001
};

struct user_db_cfg
{
    uint16_t features;
};

#endif
