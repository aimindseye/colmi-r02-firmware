#ifndef RY02_BLUEX_ADAPTER_CONTRACT_H
#define RY02_BLUEX_ADAPTER_CONTRACT_H

#include "ry02_ringcli_protocol.h"

#include <stddef.h>
#include <stdint.h>

/*
 * This is an integration boundary, not a BlueX implementation.
 *
 * A future SDK3 adapter should:
 *   1. register the six verified 128-bit UUIDs;
 *   2. feed command writes to ry02_handle_command();
 *   3. notify the command RX characteristic when response_length == 16;
 *   4. execute effects through board-specific callbacks;
 *   5. keep Data UART history responses disabled until separately modeled.
 */

struct ry02_bluex_callbacks {
    void (*set_time)(const struct ry02_datetime *value);
    void (*flash_led)(void);
    void (*shutdown)(void);
    void (*heart_period_changed)(bool enabled, uint8_t period);
    void (*realtime_changed)(bool active, uint8_t measurement_type);
    int (*notify_command)(const uint8_t *bytes, size_t length);
    int (*notify_data)(const uint8_t *bytes, size_t length);
};

struct ry02_bluex_context {
    struct ry02_protocol_state protocol;
    struct ry02_bluex_callbacks callbacks;
};

enum ry02_status ry02_bluex_on_command_write(
    struct ry02_bluex_context *context,
    const uint8_t *bytes,
    size_t length
);

enum ry02_status ry02_bluex_on_data_write(
    struct ry02_bluex_context *context,
    const uint8_t *bytes,
    size_t length
);

#endif
