#ifndef RY02_RINGCLI_PROTOCOL_H
#define RY02_RINGCLI_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RY02_COMMAND_PACKET_SIZE 16u
#define RY02_COMMAND_PAYLOAD_SIZE 14u
#define RY02_DATA_REQUEST_SIZE 6u

enum ry02_command {
    RY02_CMD_SET_TIME = 0x01,
    RY02_CMD_BATTERY_INFO = 0x03,
    RY02_CMD_SHUTDOWN = 0x08,
    RY02_CMD_FLASH_LED = 0x10,
    RY02_CMD_HEART_RATE_READ = 0x15,
    RY02_CMD_HEART_RATE_PERIOD = 0x16,
    RY02_CMD_ACTIVITY = 0x43,
    RY02_CMD_REALTIME_START_CONTINUE = 0x69,
    RY02_CMD_REALTIME_STOP = 0x6A,
    RY02_CMD_ACTIVITY_UNKNOWN = 0x73,
    RY02_CMD_ERROR = 0xFF
};

enum ry02_data_request_id {
    RY02_DATA_SLEEP = 0x27,
    RY02_DATA_OXYGEN = 0x2A
};

enum ry02_realtime_type {
    RY02_RT_HEART_RATE_BATCH = 0x01,
    RY02_RT_BLOOD_OXYGEN = 0x03,
    RY02_RT_HEART_RATE_CONTINUOUS = 0x06,
    RY02_RT_HRV = 0x0A
};

enum ry02_realtime_action {
    RY02_RT_ACTION_START = 0x01,
    RY02_RT_ACTION_PAUSE = 0x02,
    RY02_RT_ACTION_CONTINUE = 0x03,
    RY02_RT_ACTION_STOP = 0x04
};

enum ry02_status {
    RY02_STATUS_OK = 0,
    RY02_STATUS_BAD_LENGTH,
    RY02_STATUS_BAD_CHECKSUM,
    RY02_STATUS_BAD_PAYLOAD,
    RY02_STATUS_UNSUPPORTED
};

enum ry02_effect {
    RY02_EFFECT_NONE = 0,
    RY02_EFFECT_TIME_SET,
    RY02_EFFECT_FLASH_LED,
    RY02_EFFECT_SHUTDOWN,
    RY02_EFFECT_HEART_PERIOD_SET,
    RY02_EFFECT_REALTIME_START,
    RY02_EFFECT_REALTIME_CONTINUE,
    RY02_EFFECT_REALTIME_STOP
};

struct ry02_datetime {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t language;
};

struct ry02_protocol_state {
    uint8_t battery_level;
    bool charging;

    bool heart_period_enabled;
    uint8_t heart_period;

    bool realtime_active;
    uint8_t realtime_type;

    struct ry02_datetime last_time;
};

struct ry02_result {
    enum ry02_status status;
    enum ry02_effect effect;
    size_t response_length;
};

uint8_t ry02_checksum(const uint8_t *bytes, size_t length);

bool ry02_verify_command_packet(
    const uint8_t packet[RY02_COMMAND_PACKET_SIZE]
);

void ry02_make_command_packet(
    uint8_t command,
    const uint8_t *payload,
    size_t payload_length,
    uint8_t out[RY02_COMMAND_PACKET_SIZE]
);

void ry02_make_data_request(
    uint8_t request_id,
    uint8_t out[RY02_DATA_REQUEST_SIZE]
);

enum ry02_status ry02_parse_data_request(
    const uint8_t *request,
    size_t request_length,
    uint8_t *request_id
);

struct ry02_result ry02_handle_command(
    struct ry02_protocol_state *state,
    const uint8_t *request,
    size_t request_length,
    uint8_t response[RY02_COMMAND_PACKET_SIZE]
);

void ry02_make_realtime_value_notification(
    uint8_t measurement_type,
    uint8_t value,
    uint8_t out[RY02_COMMAND_PACKET_SIZE]
);

#ifdef __cplusplus
}
#endif

#endif
