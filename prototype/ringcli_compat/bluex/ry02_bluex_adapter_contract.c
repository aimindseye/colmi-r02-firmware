#include "ry02_bluex_adapter_contract.h"

#include <string.h>

enum ry02_status ry02_bluex_on_command_write(
    struct ry02_bluex_context *context,
    const uint8_t *bytes,
    size_t length
) {
    if (context == NULL || bytes == NULL) {
        return RY02_STATUS_BAD_PAYLOAD;
    }

    uint8_t response[RY02_COMMAND_PACKET_SIZE];
    memset(response, 0, sizeof(response));

    const struct ry02_result result = ry02_handle_command(
        &context->protocol,
        bytes,
        length,
        response
    );

    if (result.status != RY02_STATUS_OK) {
        return result.status;
    }

    switch (result.effect) {
        case RY02_EFFECT_TIME_SET:
            if (context->callbacks.set_time != NULL) {
                context->callbacks.set_time(&context->protocol.last_time);
            }
            break;

        case RY02_EFFECT_FLASH_LED:
            if (context->callbacks.flash_led != NULL) {
                context->callbacks.flash_led();
            }
            break;

        case RY02_EFFECT_SHUTDOWN:
            if (context->callbacks.shutdown != NULL) {
                context->callbacks.shutdown();
            }
            break;

        case RY02_EFFECT_HEART_PERIOD_SET:
            if (context->callbacks.heart_period_changed != NULL) {
                context->callbacks.heart_period_changed(
                    context->protocol.heart_period_enabled,
                    context->protocol.heart_period
                );
            }
            break;

        case RY02_EFFECT_REALTIME_START:
        case RY02_EFFECT_REALTIME_CONTINUE:
        case RY02_EFFECT_REALTIME_STOP:
            if (context->callbacks.realtime_changed != NULL) {
                context->callbacks.realtime_changed(
                    context->protocol.realtime_active,
                    context->protocol.realtime_type
                );
            }
            break;

        case RY02_EFFECT_NONE:
        default:
            break;
    }

    if (result.response_length > 0u
        && context->callbacks.notify_command != NULL) {
        const int notify_status = context->callbacks.notify_command(
            response,
            result.response_length
        );

        if (notify_status != 0) {
            return RY02_STATUS_UNSUPPORTED;
        }
    }

    return RY02_STATUS_OK;
}

enum ry02_status ry02_bluex_on_data_write(
    struct ry02_bluex_context *context,
    const uint8_t *bytes,
    size_t length
) {
    (void)context;

    uint8_t request_id = 0u;
    const enum ry02_status status = ry02_parse_data_request(
        bytes,
        length,
        &request_id
    );

    if (status != RY02_STATUS_OK) {
        return status;
    }

    /*
     * History response encoding is intentionally not implemented in r1.
     * The request is recognized so the BLE adapter can reject it cleanly.
     */
    (void)request_id;
    return RY02_STATUS_UNSUPPORTED;
}
