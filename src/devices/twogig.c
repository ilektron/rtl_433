/** @file
    2GIG Door/Window Sensors, keyfobs, and keypads (345Mhz).

    Copyright (C) 2016 adam1010
    Copyright (C) 2019 Christian W. Zuckschwerdt <zany@triq.net>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "data.h"
#include "decoder.h"

/**
2GIG Door/Window Sensors, keyfobs, and keypads (345Mhz).

Tested with 2GIG-KEY2-345, 2GIG-PAD1-345

64 bit packets, repeated multiple times per open/close event.

Data layout:

    PP PP C IIIII EE SS SS

- P: 16bit Preamble and sync bit (always ff fe)
- C: 4bit Counter or constant
- I: 20bit Device serial number
- E: 8bit Event, changes based on device
- S: 16bit CRC

Demodulated as raw PCM (half-bit width ~136 us) with the preamble and
Manchester decoding done explicitly in decode_fn, rather than relying on
OOK_PULSE_MANCHESTER_ZEROBIT's own pulse-level auto-decode. That demod has
no preamble-alignment step of its own -- any noise before the real signal
starts (seen on some 5816/5820L/2GIG units at close range, where receiver
AGC overload makes the pre-message "gap" noisy) throws off its bit count
from the very first edge, corrupting the whole message even though the
underlying pulse train is intact. Searching for the preamble explicitly at
the raw level, as done here, recovers those messages: confirmed against
real captures in https://github.com/merbanan/rtl_433/issues/2015 that
decoded 0 of 6 repeats with the old demod and 6 of 6 with this one.
*/
static int twogig_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    // full preamble is 0xFFFE decoded, i.e. 0x555556 (24 bits) raw Manchester
    // before decoding -- searched for at the raw level (see file header) so
    // that noise before the real signal starts can't misalign the decode.
    // The preamble is a repeating 01 pattern until its final 10, so a naive
    // single bitbuffer_search() can latch onto an earlier, spurious 24-bit
    // match within that run at the wrong (off-by-one-bit) alignment -- loop
    // over every match and validate by CRC instead of trusting the first.
    uint8_t const preamble_pattern[3] = {0x55, 0x55, 0x56};

    int row = 0; // we expect a single row only. reduce collisions
    if (bitbuffer->num_rows != 1 || bitbuffer->bits_per_row[row] < 120) {
        return DECODE_ABORT_LENGTH;
    }

    int raw_len      = bitbuffer->bits_per_row[row];
    uint8_t b[10]    = {0};
    int channel      = 0;
    int device_id    = 0;
    int crc          = 0;
    int len          = 0;
    unsigned raw_pos = 0;
    int found        = 0;

    while ((raw_pos = bitbuffer_search(bitbuffer, row, raw_pos, preamble_pattern, 24)) + 24 < (unsigned)raw_len) {
        bitbuffer_t decoded = {0};
        bitbuffer_manchester_decode(bitbuffer, row, raw_pos + 24, &decoded, 96);
        raw_pos += 1; // try the next possible (possibly off-by-one) match too

        len = decoded.bits_per_row[0];
        if (len < 48) {
            continue;
        }
        memcpy(b, decoded.bb[0], 10);

        channel   = b[0] >> 4;
        device_id = ((b[0] & 0xf) << 16) | (b[1] << 8) | b[2];
        crc       = (b[4] << 8) | b[5];

        if (device_id == 0 && crc == 0) {
            continue; // Reduce collisions
        }

        uint16_t crc_calculated;

        if (channel == 0x80) {
            crc_calculated = crc16(b, 4, 0x8005, 0);
            if (crc == crc_calculated) {
                found = 1;
                break;
            }
        }

        // 2GIG brand, also Type 0xC for Tilt Sensor
        crc_calculated = crc16(b, 4, 0x8050, 0);
        if (crc == crc_calculated) {

            found = 1;

            break;
        }
    }

    if (!found) {
        return DECODE_FAIL_MIC; // Not a valid packet
    }

    //
    if (len > 50) { // Newer 96 bit format
        decoder_log_bitrow(decoder, 1, __func__, b, (len > 80 ? 80 : len), "Long format");
    }

    int event = b[3];
    // NOTE: not sure if these apply to all device types

    data_t *data = NULL;

    char id_str[9];
    snprintf(id_str, sizeof(id_str), "%03u-%04u", device_id/10000, device_id % 10000);

    if ((event & 0x0f) == 0x1) {
        // Keypad
        int key = (event >> 4) & 0x0f;

        // * == 10
        // 0 == 11
        // # == 12
        int arm_stay = key == 13;
        int arm_away = key == 14;
        int fire     = key == 15;
        int police   = key == 0;

        /* clang-format off */
        data = data_make(
              "model",        "",             DATA_STRING, "2GIG-PAD1-345",
              "id",           "",             DATA_STRING, id_str,
              "counter",      "",             DATA_INT,    channel,
              "event",        "",             DATA_FORMAT, "%02x", DATA_INT, event,
              "key",          "",             DATA_INT, key,
              "arm_away",     "",             DATA_INT, arm_away,       
              "arm_stay",     "",             DATA_INT, arm_stay,       
              "fire",         "",             DATA_INT, fire,       
              "police",       "",             DATA_INT, police,       
              "mic",          "Integrity",    DATA_STRING, "CRC",
              NULL);
        /* clang-format on */
    }
    else if ((event & 0xf) == 0xa) {
        // Keyfob
        int aux    = (event & 0x80) >> 7;
        int arm_stay = (event & 0x40) >> 6;
        int disarm   = (event & 0x20) >> 5;
        int arm_away = (event & 0x10) >> 4;
        /* clang-format off */
        data = data_make(
              "model",        "",             DATA_STRING, "2GIG-KEY2-345",
              "id",           "",             DATA_STRING, id_str,
              "channel",      "",             DATA_INT,    channel,
              "event",        "",             DATA_FORMAT, "%02x", DATA_INT, event,
              "arm_away",     "",             DATA_INT, arm_away,       
              "disarm",       "",             DATA_INT, disarm,       
              "arm_stay",     "",             DATA_INT, arm_stay,       
              "aux",          "",             DATA_INT, aux,       
              "mic",          "Integrity",    DATA_STRING, "CRC",
              NULL);
        /* clang-format on */
    }
    else {
        // Generic Honeywell compliant device
        // decoded event bits: CTRABHUU
        int loop1       = (event & 0x80) >> 7;
        int tamper      = (event & 0x40) >> 6;
        int loop2       = (event & 0x20) >> 5;
        int alarm       = (event & 0x10) >> 4;
        int battery_low = (event & 0x08) >> 3;
        int heartbeat   = (event & 0x04) >> 2;

        /* clang-format off */
        data = data_make(
              "model",        "",             DATA_STRING, "Honeywell-Security",
              "id",           "",             DATA_STRING, id_str,
              "channel",      "",             DATA_INT,    channel,
              "event",        "",             DATA_FORMAT, "%02x", DATA_INT, event,
              "loop1",        "",             DATA_INT,    loop1,
              "tamper",       "",             DATA_INT,    tamper,
              "loop2",        "",             DATA_INT,    loop2,
              "alarm",        "",             DATA_INT,    alarm,
              "battery_ok",   "Battery",      DATA_INT,    !battery_low,
              "heartbeat",    "",             DATA_INT,    heartbeat,
              "mic",          "Integrity",    DATA_STRING, "CRC",
              NULL);
        /* clang-format on */
    }
    if (data) {
        decoder_output_data(decoder, data);
        return 1;
    }

    return DECODE_FAIL_OTHER;
}

static char const *const output_fields[] = {
        "model",
        "id",
        "channel",
        "counter",
        "event",
        "loop1",
        "tamper",
        "loop2",
        "alarm",
        "battery_ok",
        "heartbeat",
        "key",
        "police",
        "fire",
        "arm_away",
        "arm_stay",
        "disarm",
        "aux",
        "mic",
        NULL,
};

r_device const twogig = {
        .name        = "2GIG KEY2 and PAD1",
        .modulation  = OOK_PULSE_PCM,
        .short_width = 136,
        .long_width  = 136,
        .reset_limit = 408,
        .decode_fn   = &twogig_decode,
        .fields      = output_fields,
};
