#include "ry02_ringcli_protocol.h"
#include "ry02_bluex_adapter_contract.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t BATTERY_REQUEST[16] = {
    0x03,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03
};
static const uint8_t TIME_REQUEST[16] = {
    0x01,0x25,0x04,0x09,0x12,0x34,0x56,0x01,0,0,0,0,0,0,0,0xD0
};
static const uint8_t LED_REQUEST[16] = {
    0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};
static const uint8_t SHUTDOWN_REQUEST[16] = {
    0x08,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0x09
};
static const uint8_t RT_START[16] = {
    0x69,0x01,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0x6B
};
static const uint8_t RT_STOP[16] = {
    0x6A,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0x6B
};
static const uint8_t SLEEP_REQUEST[6] = {
    0xBC,0x27,0x00,0x00,0xFF,0xFF
};

static void test_fixtures(void) {
    uint8_t packet[16];
    uint8_t data[6];

    ry02_make_command_packet(RY02_CMD_BATTERY_INFO, NULL, 0, packet);
    assert(memcmp(packet, BATTERY_REQUEST, sizeof(packet)) == 0);

    const uint8_t shutdown_payload[] = {0x01};
    ry02_make_command_packet(
        RY02_CMD_SHUTDOWN,
        shutdown_payload,
        sizeof(shutdown_payload),
        packet
    );
    assert(memcmp(packet, SHUTDOWN_REQUEST, sizeof(packet)) == 0);

    ry02_make_data_request(RY02_DATA_SLEEP, data);
    assert(memcmp(data, SLEEP_REQUEST, sizeof(data)) == 0);
}

static void test_battery(void) {
    struct ry02_protocol_state state = {
        .battery_level = 78,
        .charging = false
    };
    uint8_t response[16];
    struct ry02_result result = ry02_handle_command(
        &state,
        BATTERY_REQUEST,
        sizeof(BATTERY_REQUEST),
        response
    );

    assert(result.status == RY02_STATUS_OK);
    assert(result.effect == RY02_EFFECT_NONE);
    assert(result.response_length == 16);
    assert(response[0] == RY02_CMD_BATTERY_INFO);
    assert(response[1] == 78);
    assert(response[2] == 0);
    assert(ry02_verify_command_packet(response));
}

static void test_time(void) {
    struct ry02_protocol_state state = {0};
    uint8_t response[16];

    const struct ry02_result result = ry02_handle_command(
        &state,
        TIME_REQUEST,
        sizeof(TIME_REQUEST),
        response
    );

    assert(result.status == RY02_STATUS_OK);
    assert(result.effect == RY02_EFFECT_TIME_SET);
    assert(result.response_length == 16);
    assert(state.last_time.year == 2025);
    assert(state.last_time.month == 4);
    assert(state.last_time.day == 9);
    assert(state.last_time.hour == 12);
    assert(state.last_time.minute == 34);
    assert(state.last_time.second == 56);
    assert(state.last_time.language == 1);
    assert(response[0] == RY02_CMD_SET_TIME);
}

static void test_effects(void) {
    struct ry02_protocol_state state = {0};
    uint8_t response[16];

    struct ry02_result result = ry02_handle_command(
        &state,
        LED_REQUEST,
        sizeof(LED_REQUEST),
        response
    );
    assert(result.effect == RY02_EFFECT_FLASH_LED);
    assert(result.response_length == 16);

    result = ry02_handle_command(
        &state,
        SHUTDOWN_REQUEST,
        sizeof(SHUTDOWN_REQUEST),
        response
    );
    assert(result.effect == RY02_EFFECT_SHUTDOWN);
    assert(result.response_length == 0);

    result = ry02_handle_command(
        &state,
        RT_START,
        sizeof(RT_START),
        response
    );
    assert(result.effect == RY02_EFFECT_REALTIME_START);
    assert(state.realtime_active);
    assert(state.realtime_type == RY02_RT_HEART_RATE_BATCH);

    result = ry02_handle_command(
        &state,
        RT_STOP,
        sizeof(RT_STOP),
        response
    );
    assert(result.effect == RY02_EFFECT_REALTIME_STOP);
    assert(!state.realtime_active);
    assert(state.realtime_type == 0);
}

static void test_rejections(void) {
    struct ry02_protocol_state state = {0};
    uint8_t response[16];
    uint8_t broken[16];

    memcpy(broken, BATTERY_REQUEST, sizeof(broken));
    broken[15] ^= 0x01;

    struct ry02_result result = ry02_handle_command(
        &state,
        broken,
        sizeof(broken),
        response
    );
    assert(result.status == RY02_STATUS_BAD_CHECKSUM);

    uint8_t request_id = 0;
    assert(
        ry02_parse_data_request(
            SLEEP_REQUEST,
            sizeof(SLEEP_REQUEST),
            &request_id
        ) == RY02_STATUS_OK
    );
    assert(request_id == RY02_DATA_SLEEP);
}

static void test_realtime_notification(void) {
    uint8_t packet[16];

    ry02_make_realtime_value_notification(
        RY02_RT_HEART_RATE_BATCH,
        72,
        packet
    );

    assert(packet[0] == RY02_CMD_REALTIME_START_CONTINUE);
    assert(packet[1] == RY02_RT_HEART_RATE_BATCH);
    assert(packet[2] == 0);
    assert(packet[3] == 72);
    assert(ry02_verify_command_packet(packet));
}

int main(void) {
    test_fixtures();
    test_battery();
    test_time();
    test_effects();
    test_rejections();
    test_realtime_notification();

    puts("RY02 RingCLI protocol skeleton tests: PASS");
    return 0;
}
