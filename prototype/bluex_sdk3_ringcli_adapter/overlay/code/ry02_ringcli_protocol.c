#include "ry02_ringcli_protocol.h"

#include <string.h>

static bool is_valid_bcd(uint8_t value) {
    return (value & 0x0Fu) <= 9u && ((value >> 4u) & 0x0Fu) <= 9u;
}

static uint8_t bcd_to_u8(uint8_t value) {
    return (uint8_t)(((value >> 4u) * 10u) + (value & 0x0Fu));
}

static bool is_valid_datetime_payload(const uint8_t *payload) {
    if (payload == NULL) {
        return false;
    }

    for (size_t index = 0; index < 6u; ++index) {
        if (!is_valid_bcd(payload[index])) {
            return false;
        }
    }

    const uint8_t month = bcd_to_u8(payload[1]);
    const uint8_t day = bcd_to_u8(payload[2]);
    const uint8_t hour = bcd_to_u8(payload[3]);
    const uint8_t minute = bcd_to_u8(payload[4]);
    const uint8_t second = bcd_to_u8(payload[5]);

    return month >= 1u && month <= 12u
        && day >= 1u && day <= 31u
        && hour <= 23u
        && minute <= 59u
        && second <= 59u;
}

static bool is_supported_realtime_type(uint8_t type) {
    return type == RY02_RT_HEART_RATE_BATCH
        || type == RY02_RT_BLOOD_OXYGEN
        || type == RY02_RT_HEART_RATE_CONTINUOUS
        || type == RY02_RT_HRV;
}

uint8_t ry02_checksum(const uint8_t *bytes, size_t length) {
    uint8_t value = 0u;

    if (bytes == NULL) {
        return value;
    }

    for (size_t index = 0; index < length; ++index) {
        value = (uint8_t)(value + bytes[index]);
    }

    return value;
}

bool ry02_verify_command_packet(
    const uint8_t packet[RY02_COMMAND_PACKET_SIZE]
) {
    if (packet == NULL) {
        return false;
    }

    return ry02_checksum(packet, RY02_COMMAND_PACKET_SIZE - 1u)
        == packet[RY02_COMMAND_PACKET_SIZE - 1u];
}

void ry02_make_command_packet(
    uint8_t command,
    const uint8_t *payload,
    size_t payload_length,
    uint8_t out[RY02_COMMAND_PACKET_SIZE]
) {
    if (out == NULL) {
        return;
    }

    memset(out, 0, RY02_COMMAND_PACKET_SIZE);
    out[0] = command;

    if (payload != NULL && payload_length > 0u) {
        if (payload_length > RY02_COMMAND_PAYLOAD_SIZE) {
            payload_length = RY02_COMMAND_PAYLOAD_SIZE;
        }

        memcpy(&out[1], payload, payload_length);
    }

    out[RY02_COMMAND_PACKET_SIZE - 1u] =
        ry02_checksum(out, RY02_COMMAND_PACKET_SIZE - 1u);
}

void ry02_make_data_request(
    uint8_t request_id,
    uint8_t out[RY02_DATA_REQUEST_SIZE]
) {
    if (out == NULL) {
        return;
    }

    out[0] = 0xBCu;
    out[1] = request_id;
    out[2] = 0x00u;
    out[3] = 0x00u;
    out[4] = 0xFFu;
    out[5] = 0xFFu;
}

enum ry02_status ry02_parse_data_request(
    const uint8_t *request,
    size_t request_length,
    uint8_t *request_id
) {
    if (request == NULL || request_length != RY02_DATA_REQUEST_SIZE) {
        return RY02_STATUS_BAD_LENGTH;
    }

    if (request[0] != 0xBCu
        || request[2] != 0x00u
        || request[3] != 0x00u
        || request[4] != 0xFFu
        || request[5] != 0xFFu) {
        return RY02_STATUS_BAD_PAYLOAD;
    }

    if (request[1] != RY02_DATA_SLEEP
        && request[1] != RY02_DATA_OXYGEN) {
        return RY02_STATUS_UNSUPPORTED;
    }

    if (request_id != NULL) {
        *request_id = request[1];
    }

    return RY02_STATUS_OK;
}

static struct ry02_result result(
    enum ry02_status status,
    enum ry02_effect effect,
    size_t response_length
) {
    struct ry02_result value;
    value.status = status;
    value.effect = effect;
    value.response_length = response_length;
    return value;
}

struct ry02_result ry02_handle_command(
    struct ry02_protocol_state *state,
    const uint8_t *request,
    size_t request_length,
    uint8_t response[RY02_COMMAND_PACKET_SIZE]
) {
    if (state == NULL || request == NULL || response == NULL) {
        return result(RY02_STATUS_BAD_PAYLOAD, RY02_EFFECT_NONE, 0u);
    }

    if (request_length != RY02_COMMAND_PACKET_SIZE) {
        return result(RY02_STATUS_BAD_LENGTH, RY02_EFFECT_NONE, 0u);
    }

    if (!ry02_verify_command_packet(request)) {
        return result(RY02_STATUS_BAD_CHECKSUM, RY02_EFFECT_NONE, 0u);
    }

    const uint8_t command = request[0];

    switch (command) {
        case RY02_CMD_BATTERY_INFO: {
            const uint8_t payload[2] = {
                state->battery_level,
                state->charging ? 1u : 0u
            };
            ry02_make_command_packet(command, payload, sizeof(payload), response);
            return result(
                RY02_STATUS_OK,
                RY02_EFFECT_NONE,
                RY02_COMMAND_PACKET_SIZE
            );
        }

        case RY02_CMD_SET_TIME: {
            const uint8_t *payload = &request[1];

            if (!is_valid_datetime_payload(payload)) {
                return result(
                    RY02_STATUS_BAD_PAYLOAD,
                    RY02_EFFECT_NONE,
                    0u
                );
            }

            state->last_time.year =
                (uint16_t)(2000u + bcd_to_u8(payload[0]));
            state->last_time.month = bcd_to_u8(payload[1]);
            state->last_time.day = bcd_to_u8(payload[2]);
            state->last_time.hour = bcd_to_u8(payload[3]);
            state->last_time.minute = bcd_to_u8(payload[4]);
            state->last_time.second = bcd_to_u8(payload[5]);
            state->last_time.language = payload[6];

            ry02_make_command_packet(command, NULL, 0u, response);
            return result(
                RY02_STATUS_OK,
                RY02_EFFECT_TIME_SET,
                RY02_COMMAND_PACKET_SIZE
            );
        }

        case RY02_CMD_FLASH_LED:
            ry02_make_command_packet(command, NULL, 0u, response);
            return result(
                RY02_STATUS_OK,
                RY02_EFFECT_FLASH_LED,
                RY02_COMMAND_PACKET_SIZE
            );

        case RY02_CMD_SHUTDOWN:
            if (request[1] != 0x01u) {
                return result(
                    RY02_STATUS_BAD_PAYLOAD,
                    RY02_EFFECT_NONE,
                    0u
                );
            }

            /*
             * RingCLI does not expect a response because the stock ring powers
             * down before a notification is observed.
             */
            return result(
                RY02_STATUS_OK,
                RY02_EFFECT_SHUTDOWN,
                0u
            );

        case RY02_CMD_HEART_RATE_PERIOD:
            if (request[1] == 0x01u) {
                const uint8_t payload[3] = {
                    0x01u,
                    state->heart_period_enabled ? 1u : 0u,
                    state->heart_period
                };
                ry02_make_command_packet(
                    command,
                    payload,
                    sizeof(payload),
                    response
                );
                return result(
                    RY02_STATUS_OK,
                    RY02_EFFECT_NONE,
                    RY02_COMMAND_PACKET_SIZE
                );
            }

            if (request[1] == 0x02u) {
                state->heart_period_enabled = request[2] != 0u;
                state->heart_period = request[3];

                const uint8_t payload[3] = {
                    0x02u,
                    state->heart_period_enabled ? 1u : 0u,
                    state->heart_period
                };
                ry02_make_command_packet(
                    command,
                    payload,
                    sizeof(payload),
                    response
                );
                return result(
                    RY02_STATUS_OK,
                    RY02_EFFECT_HEART_PERIOD_SET,
                    RY02_COMMAND_PACKET_SIZE
                );
            }

            return result(
                RY02_STATUS_BAD_PAYLOAD,
                RY02_EFFECT_NONE,
                0u
            );

        case RY02_CMD_REALTIME_START_CONTINUE: {
            const uint8_t type = request[1];
            const uint8_t action = request[2];

            if (!is_supported_realtime_type(type)) {
                return result(
                    RY02_STATUS_UNSUPPORTED,
                    RY02_EFFECT_NONE,
                    0u
                );
            }

            if (action == RY02_RT_ACTION_START) {
                state->realtime_active = true;
                state->realtime_type = type;
                ry02_make_command_packet(command, &request[1], 2u, response);
                return result(
                    RY02_STATUS_OK,
                    RY02_EFFECT_REALTIME_START,
                    RY02_COMMAND_PACKET_SIZE
                );
            }

            if (action == RY02_RT_ACTION_CONTINUE) {
                state->realtime_active = true;
                state->realtime_type = type;
                ry02_make_command_packet(command, &request[1], 2u, response);
                return result(
                    RY02_STATUS_OK,
                    RY02_EFFECT_REALTIME_CONTINUE,
                    RY02_COMMAND_PACKET_SIZE
                );
            }

            return result(
                RY02_STATUS_BAD_PAYLOAD,
                RY02_EFFECT_NONE,
                0u
            );
        }

        case RY02_CMD_REALTIME_STOP:
            if (!is_supported_realtime_type(request[1])) {
                return result(
                    RY02_STATUS_UNSUPPORTED,
                    RY02_EFFECT_NONE,
                    0u
                );
            }

            state->realtime_active = false;
            state->realtime_type = 0u;
            ry02_make_command_packet(command, &request[1], 1u, response);
            return result(
                RY02_STATUS_OK,
                RY02_EFFECT_REALTIME_STOP,
                RY02_COMMAND_PACKET_SIZE
            );

        default:
            return result(
                RY02_STATUS_UNSUPPORTED,
                RY02_EFFECT_NONE,
                0u
            );
    }
}

void ry02_make_realtime_value_notification(
    uint8_t measurement_type,
    uint8_t value,
    uint8_t out[RY02_COMMAND_PACKET_SIZE]
) {
    const uint8_t payload[3] = {
        measurement_type,
        0x00u,
        value
    };

    ry02_make_command_packet(
        RY02_CMD_REALTIME_START_CONTINUE,
        payload,
        sizeof(payload),
        out
    );
}
