/** @file
    Vivint Door/Window Sensors (345 MHz).

    Copyright (C) 2026 Benjamin Larsson <banan@ludd.ltu.se>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "decoder.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define VIVINT_MSG_BIT_LEN 80
#define VIVINT_MAX_SENSORS 8
#define VIVINT_CACHED_COUNTERS 8
#define VIVINT_ENTRY_COUNTER 0x17
#define VIVINT_RABBIT_CIPHER_SIZE 48

/**
Vivint Door/Window Sensors (345.0 MHz).

Tested with the Vivint V-DW21R-345 door/window sensor and Vivint V-DW11-345 Door Sensor.

OOK Manchester (zerobit), 0xFFFE preamble, 96 bit (12 byte) packet. Decoded
payload (80 data bits, 10 bytes) after the preamble:

    TT CC CC FF II II II II RR RR

- T: 8 bit frame subtype: 0x7a = DW11 door/window, 0x79 = GB2 glass-break,
     0x74 = PIR2 motion, 0x72/0x73/0x76 = other sensor families,
     0xd0 = power-on/startup beacon
- C: 16 bit counter, increments every transmission
- F: 8 bit status byte. The low 2 bits are always zero; the rest (including
     bit 7, open/closed for 0x7a) are XORed with a per-device keystream,
     see below
- I: 32 bit device identifier
- R: 16 bit CRC

I is the sensor's printed TXID: split into a 12 bit and a 20 bit decimal
number, e.g. 0x0137beda -> 19, 507610 -> "0019-0507610" (label
"0019-050-7610"). Exposed as the `id` field. Same scheme as Honeywell/2GIG
(issue #1261).

Non-0xd0 subtypes use a packed 12-bit CRC:
  - CRC-16 poly 0x8050 over b[0..7] + top_nibble(b[8])  (9 bytes)
  - check12 = crc16 >> 4; stored12 = (low_nibble(b[8]) << 8) | b[9]
  - valid when check12 == stored12

0xd0 frames use standard CRC-16 poly 0x8050 over b[0..7].

Per-device keystream (F field, 0x7a, 0x74, 0x79 frames only):

Each sensor has a 16 bit per-device seed, not transmitted over the air,
that keys a Rabbit stream cipher core (RFC 4503) advancing every
transmission (keyed off the 16 bit counter) to produce a keystream byte
XORed into F; bit 7 of the decrypted byte is the door contact (1 = open).
The auth nibble in byte 10 of the on-air frame is `(c3 ^ 0x10) & 0xf0`.

Since the seed is only a 16 bit value and the cipher is designed to have
a high volatility of all the cipher bits per single bit change of the cipher
key, to determine the seed you need around 5 frames from a sensor with
different packet counters and about 20 bits of the resulting cipher.

The seed cannot be derived from a single frame or from this decoder alone;
it must be obtained externally from several frames at known low counters
(ideally right after a power-cycle). Once known, supply it at registration
time to decrypt F:

    rtl_433 -R 342:0019-0507610=05c9,0019-0507743=dda9

Without a matching seed, `state`/`contact_open` are omitted and the raw
payload is reported in `data` instead.

See https://github.com/merbanan/rtl_433/issues/1504
*/

/* Rabbit stream cipher core (RFC 4503). Inner state: eight 32-bit state
   words X0..X7, eight 32-bit counter words C0..C7,
   modeled as a flat byte window. Custom to this protocol (not part of
   RFC 4503): a 16-bit seed in place of Rabbit's 128-bit key/IV, and a
   per-packet schedule keyed off the transmission counter. */
/* Technically, we could just cache the key and the secrets. The states
   are generated every 12 packets */
typedef struct {
    uint32_t C[8];
    uint32_t X[8];
    uint16_t S[8];
    uint16_t K[8];
    uint32_t b;
} vivint_rabbit_t;

/* Rabbit concat two 16 bit values */
static uint32_t vivint_rabbit_concat(uint16_t a, uint16_t b)
{
    return (((uint32_t)a) << 16) | (uint32_t)b;
}

/* Rabbit rotate a 32bit value to the left */
static uint32_t vivint_rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t vivint_rabbit_g(uint32_t u, uint32_t v)
{
    uint64_t sq = u + v;
    sq = sq * sq;
    return ((sq >> 32) & 0x00000000ffffffff) ^ (sq & 0x00000000ffffffff);
}

/* RFC 4503 SS2.5 counter-update constants A0..A7. */
/* Expands the 16-bit seed into the 8 words vivint_rabbit_key_setup()
   interleaves into X and C. */
static void vivint_expand_key(vivint_rabbit_t *g, uint16_t seed)
{
    // TODO decide if this should be xord with 8 or not
    g->K[0]        = seed;
    g->K[1]        = (uint16_t)(seed + 0x25);
    g->K[2]        = (uint16_t)(seed - 0x04);
    g->K[3]        = (uint16_t)(seed + 0x2c);
    g->K[4]        = (uint16_t)(seed - 0x09);
    g->K[5]        = (uint16_t)(seed - 0x1d);
    g->K[6]        = seed ^ 0x00f9;
    g->K[7]        = seed ^ 0x0022;
}

/* Derives X0..X7 and C0..C7 (RFC 4503 SS2.2) from the 8 seed-expanded words,
   analogous to RFC 4503 SS2.3 key setup but with this protocol's own
   permutation, re-derived from the counter each call. */
static void vivint_rabbit_key_setup(vivint_rabbit_t *g)
{
    /* 2.3.  Key Setup Scheme
    
     The counter carry bit b is initialized to zero.  The state and
     counter words are derived from the key K[127..0].
    
     The key is divided into subkeys K0 = K[15..0], K1 = K[31..16], ... K7
     = K[127..112].  The initial state is initialized as follows:
    
       for j=0 to 7:
         if j is even:
           Xj = K(j+1 mod 8) || Kj
           Cj = K(j+4 mod 8) || K(j+5 mod 8)
         else:
           Xj = K(j+5 mod 8) || K(j+4 mod 8)
           Cj = Kj || K(j+1 mod 8)
    */

    g->b = 0;
    for (int j = 0u; j < 8; j++)
    {
      if (j % 2 == 0)
      {
        /* EVEN */
        g->X[j] = vivint_rabbit_concat(g->K[(j + 1) % 8], g->K[j]);
        g->C[j] = vivint_rabbit_concat(g->K[(j + 4) % 8], g->K[(j + 5) % 8]);
      } else {
        /* ODD */
        g->X[j] = vivint_rabbit_concat(g->K[(j + 5) % 8], g->K[(j + 4) % 8]);
        g->C[j] = vivint_rabbit_concat(g->K[j], g->K[(j + 1) % 8]);
      }
    }

}

static void vivint_rabbit_update_counters(vivint_rabbit_t *g)
{
     /* 2.5.  Counter System

      Before each execution of the next-state function (Section 2.6), the
      counter system has to be updated.  This system uses constants
      A1,...,A7, as follows:

      A0 = 0x4D34D34D         A1 = 0xD34D34D3
      A2 = 0x34D34D34         A3 = 0x4D34D34D
      A4 = 0xD34D34D3         A5 = 0x34D34D34
      A6 = 0x4D34D34D         A7 = 0xD34D34D3

      It also uses the counter carry bit b to update the counter system, as
      follows:

      for j=0 to 7:
       temp = Cj + Aj + b
       b    = temp div WORDSIZE
       Cj   = temp mod WORDSIZE

      Note that on exiting this loop, the variable b has to be preserved
      for the next iteration of the system.  */

    const uint32_t A[8] = {0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3};

    for (int j=0u; j<8; j++) 
    {
        uint64_t temp = (uint64_t)(g->C[j]) + (uint64_t)(A[j]) + (uint64_t)(g->b);
        g->b = temp / 0x100000000;
        g->C[j] = temp & 0xffffffff;
    }
}

/* Counter update (RFC 4503 SS2.5) and next-state function (RFC 4503 SS2.6).
   The g-function's 64-bit square is built from 16-bit-limb partial
   products. */
static void vivint_rabbit_next_state(vivint_rabbit_t *g)
{
    /* 2.6.  Next-State Function

      The core of the Rabbit algorithm is the next-state function.  It is
      based on the function g, which transforms two 32-bit inputs into one
      32-bit output, as follows:

        g(u,v) = LSW(square(u+v)) ^ MSW(square(u+v))

      where square(u+v) = ((u+v mod WORDSIZE) * (u+v mod WORDSIZE)).

      Using this function, the algorithm updates the inner state as
      follows:

        for j=0 to 7:
          Gj = g(Xj,Cj)

    */

    uint32_t G[8];
    for (int j=0u; j<8; j++)
    {
      G[j] = vivint_rabbit_g(g->X[j], g->C[j]);
    }

    // X0 = G0 + (G7 <<< 16) + (G6 <<< 16) mod WORDSIZE
    g->X[0] = G[0] + vivint_rotl32(G[7], 16) + vivint_rotl32(G[6], 16);
    // X1 = G1 + (G0 <<<  8) +  G7         mod WORDSIZE
    g->X[1] = G[1] + vivint_rotl32(G[0], 8) + G[7];
    // X2 = G2 + (G1 <<< 16) + (G0 <<< 16) mod WORDSIZE
    g->X[2] = G[2] + vivint_rotl32(G[1], 16) + vivint_rotl32(G[0], 16);
    // X3 = G3 + (G2 <<<  8) +  G1         mod WORDSIZE
    g->X[3] = G[3] + vivint_rotl32(G[2], 8) + G[1];
    // X4 = G4 + (G3 <<< 16) + (G2 <<< 16) mod WORDSIZE
    g->X[4] = G[4] + vivint_rotl32(G[3], 16) + vivint_rotl32(G[2], 16);
    // X5 = G5 + (G4 <<<  8) +  G3         mod WORDSIZE
    g->X[5] = G[5] + vivint_rotl32(G[4], 8) + G[3];
    // X6 = G6 + (G5 <<< 16) + (G4 <<< 16) mod WORDSIZE
    g->X[6] = G[6] + vivint_rotl32(G[5], 16) + vivint_rotl32(G[4], 16);
    // X7 = G7 + (G6 <<<  8) +  G5         mod WORDSIZE
    g->X[7] = G[7] + vivint_rotl32(G[6], 8) + G[5];

}

static void vivint_rabbit_reinitialize_counters(vivint_rabbit_t *g)
{
    for (int j = 0u; j < 8; j++)
    {
      g->C[j] ^= g->X[(j+4) % 8];
    }
}


/* Reduced extraction: RFC 4503 SS2.7 derives a full 128 bit block; this
   protocol only needs the status keystream byte (c1) and the auth byte
   (c3), selecting a different X-word combination per counter mod 4. */
static void vivint_rabbit_extract(vivint_rabbit_t *g)
{
    //  2.7.  Extraction Scheme

    //  After the key and IV setup are concluded, the algorithm is iterated
    //  in order to produce one 128-bit output block, S, per round.  Each
    //  round consists of executing steps 2.5 and 2.6 and then extracting an
    //  output S[127..0] as follows:

    //    S[15..0]    = X0[15..0]  ^ X5[31..16]
    g->S[0] = (g->X[0] & 0xffff) ^ ((g->X[5] >> 16) & 0xffff);
    //    S[31..16]   = X0[31..16] ^ X3[15..0]
    g->S[1] = ((g->X[0] >> 16) & 0xffff) ^ (g->X[3] & 0xffff);
    //    S[47..32]   = X2[15..0]  ^ X7[31..16]
    g->S[2] = (g->X[2] & 0xffff) ^ ((g->X[7] >> 16) & 0xffff);
    //    S[63..48]   = X2[31..16] ^ X5[15..0]
    g->S[3] = ((g->X[2] >> 16) & 0xffff) ^ (g->X[5] & 0xffff);
    //    S[79..64]   = X4[15..0]  ^ X1[31..16]
    g->S[4] = (g->X[4] & 0xffff) ^ ((g->X[1] >> 16) & 0xffff);
    //    S[95..80]   = X4[31..16] ^ X7[15..0]
    g->S[5] = ((g->X[4] >> 16) & 0xffff) ^ (g->X[7] & 0xffff);
    //    S[111..96]  = X6[15..0]  ^ X3[31..16]
    g->S[6] = (g->X[6] & 0xffff) ^ ((g->X[3] >> 16) & 0xffff);
    //    S[127..112] = X6[31..16] ^ X1[15..0]
    g->S[7] = ((g->X[6] >> 16) & 0xffff) ^ (g->X[1] & 0xffff);

}

// Generate the 48 bytes of cipher given a specific key
// out should be a uint8_t[48]
static void vivint_rabbit_gen_cipher(vivint_rabbit_t *g, uint8_t *out)
{
  
    vivint_rabbit_key_setup(g);
  
    // Iterate 4 times before extracting secrets
    for (int i=0; i < 4; i++)
    {
        vivint_rabbit_update_counters(g);
        vivint_rabbit_next_state(g);
    }
    // Necessary step before extracting the secrets
    vivint_rabbit_reinitialize_counters(g);
    
    // Now we pull out all 48 bytes of data for the cipher
    // auto out = ret.begin();
    for (int i=0; i<3; i++)
    {

        vivint_rabbit_update_counters(g);
        vivint_rabbit_next_state(g);
        vivint_rabbit_extract(g);

        for (int j = 0; j < 8; j++)
        {
            *out = g->S[j] & 0x00ff;
            out++;
            *out = (g->S[j] >> 8) & 0x00ff;
            out++;
        }
    }
}

// Customization to the rabbit cipher that modifies the 128bit key based on the packet counter
static void vivint_gen_rabbit_key(vivint_rabbit_t *g, uint16_t seed, uint16_t counter)
{
    uint16_t i = 24;
    do
    {
        if (i > 0xfff7) { i = 0; }
        if (i == 24) { vivint_expand_key(g, seed); }
        int mod = i % 7;
        g->K[mod] =  i + mod + g->K[mod];
        g->K[7] = g->K[7] ^ mod;
        i+=12;
    } while(i <= counter);
}


/* Per-device decode state: advanced incrementally as packets with
   increasing counters arrive, re-synced from the entry counter on a
   backward jump (sensor power-cycle). */
typedef struct {
    uint32_t id;
    uint16_t seed;
    uint16_t last_counter;
    uint8_t cipher[VIVINT_RABBIT_CIPHER_SIZE];
    int counter_idx;
    uint16_t counters[VIVINT_CACHED_COUNTERS];
    uint8_t cipher_cache[VIVINT_CACHED_COUNTERS];
} vivint_sensor_t;

typedef struct {
    unsigned count;
    vivint_sensor_t sensors[VIVINT_MAX_SENSORS];
} vivint_ctx_t;

static vivint_sensor_t *vivint_ctx_find(vivint_ctx_t *ctx, uint32_t id)
{
    if (!ctx) {
        return NULL;
    }
    for (unsigned i = 0; i < ctx->count; ++i) {
        if (ctx->sensors[i].id == id) {
            return &ctx->sensors[i];
        }
    }
    return NULL;
}

extern r_device const vivint;

static char *vivint_strtok(char *str, char const *delim, char **saveptr)
{
#ifdef _MSC_VER
    return strtok_s(str, delim, saveptr);
#else
    return strtok_r(str, delim, saveptr);
#endif
}

/* Parses a comma separated "NNNN-NNNNNNN=hexseed" list (the same TXID
   format this decoder prints), e.g. -R N:0019-0507610=05c9,0019-0507743=dda9 */
static r_device *vivint_create(char const *args)
{
    r_device *dev = decoder_create(&vivint, sizeof(vivint_ctx_t));
    if (!dev) {
        return NULL;
    }

    vivint_ctx_t *ctx = (vivint_ctx_t *)decoder_user_data(dev);
    ctx->count        = 0;

    if (!args || !*args) {
        return dev;
    }

    char *work = strdup(args);
    if (!work) {
        return dev;
    }

    char *saveptr = NULL;
    char *tok     = vivint_strtok(work, ",", &saveptr);
    while (tok) {
        unsigned p1;
        unsigned p2;
        unsigned seed;
        if (ctx->count < VIVINT_MAX_SENSORS
                && sscanf(tok, "%u-%u=%x", &p1, &p2, &seed) == 3) {
            vivint_sensor_t *s = &ctx->sensors[ctx->count++];
            s->id            = ((p1 & 0xfff) << 20) | (p2 & 0xfffff);
            s->seed          = (uint16_t)seed;
        }
        tok = vivint_strtok(NULL, ",", &saveptr);
    }

    free(work);
    return dev;
}

static void vivint_rabbit_advance_cipher(vivint_sensor_t *s, uint16_t counter)
{
    // Need to check to see if we need to regenerate our cipher output
    int diff = counter - s->last_counter;
    if ((s->last_counter == 0xffff) ||
        (counter % 12 == 0) || (diff > 12) || (diff < -12) ||
        (counter % 12 < s->last_counter % 12))
    {
      // We need to regenerate
      // Could make static to take it off of the stack
      vivint_rabbit_t rabbit;
      vivint_gen_rabbit_key(&rabbit, s->seed, counter);
      vivint_rabbit_gen_cipher(&rabbit, s->cipher);
    }
    s->last_counter = counter;
}

/* The other 4 bits of bytes 8 and 9 in the data contain 4 bits of the raw cipher data xor'd with 0x10 */
static int vivint_validate_rabbit_nibble(vivint_sensor_t *s, uint8_t check, uint16_t counter)
{
    int mod = counter % 12;
    uint8_t mac_byte = s->cipher[mod*4 + 2] & 0xf0;

    return mac_byte == (check ^ 0x10);
}

/* Returns the decrypted message data */
static int vivint_decrypt_flags(vivint_sensor_t *s, int flags, uint16_t counter)
{
    int mod = counter % 12;

    int decrypt_byte = s->cipher[mod*4];

    // The last 2 bits are always 0 in encrypted messages
    return (flags ^ decrypt_byte) & 0xfc;
}

/* Iterates through cached data from a sensor to determine the seed */
static int vivint_determine_seed(vivint_sensor_t *s)
{
    int num_matches = 0;
    uint16_t matched_seed = 0xffff;
    for (uint16_t seed = 1; seed < 0xffff; seed++)
    {
        s->last_counter = 0xffff;
        for (int i = 0; i < 6; i++)
        {
            s->seed = seed;
            vivint_rabbit_advance_cipher(s, s->counters[i]);
            if (!vivint_validate_rabbit_nibble(s, s->cipher_cache[i], s->counters[i]))
            {
                // if (i > 0) {
                  // printf("Not this seed after: %d\n", i);
                // }
                break;
            }
            if (i == 5)
            {
                matched_seed = seed;
                num_matches++;
            }
        }
    }

    if (num_matches == 1)
    {
        printf("Determined seed: %x\n", matched_seed);
        s->seed = matched_seed;
        return 1;
    } else {
        s->seed = 0xffff;
        return 0;
    }

}

static int vivint_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    uint8_t const preamble_pattern[2] = {0xff, 0xe0}; /* 12 bits of 0xFFFE */

    if (bitbuffer->num_rows != 1) {
        return DECODE_ABORT_EARLY;
    }
    int row = 0;

    decoder_log_bitrow(decoder, 2, __func__, bitbuffer->bb[row], bitbuffer->bits_per_row[row], "MSG");

    bitbuffer_invert(bitbuffer);

    int pos = bitbuffer_search(bitbuffer, row, 0, preamble_pattern, 12) + 12;
    int len = bitbuffer->bits_per_row[row] - pos;
    if (len < VIVINT_MSG_BIT_LEN) {
        decoder_logf(decoder, 2, __func__, "Too short (%d bits after preamble)", len);
        return DECODE_ABORT_LENGTH;
    }

    uint8_t b[VIVINT_MSG_BIT_LEN / 8 + 1];
    bitbuffer_extract_bytes(bitbuffer, row, pos, b, VIVINT_MSG_BIT_LEN);
    decoder_log_bitrow(decoder, 2, __func__, b, VIVINT_MSG_BIT_LEN, "MSG (inverted, aligned)");

    int event_type  = b[0];
    int counter     = (b[1] << 8) | b[2];
    int flags       = b[3];
    unsigned id     = ((unsigned)b[4] << 24) | ((unsigned)b[5] << 16) | ((unsigned)b[6] << 8) | b[7];
    int crc         = (b[8] << 8) | b[9];
    int cipher_nibble = b[8] & 0xf0;

    if (id == 0 || id == 0xffffffff) {
        decoder_logf(decoder, 2, __func__, "Id sanity check failed (%08x)", id);
        return DECODE_FAIL_SANITY;
    }

    int crc_valid = 0;
    // TODO add the other packet types that don't use the 12bit crc
    if (event_type == 0xd0) {
        if (crc == crc16(b, 8, 0x8050, 0)) crc_valid = 1;
    }
    else {
        uint8_t b8_full = b[8];
        b[8] &= 0xF0;
        int crc_full = crc16(b, 9, 0x8050, 0);
        b[8]         = b8_full;
        int check12  = crc_full >> 4;
        int stored12 = ((b8_full & 0x0F) << 8) | b[9];
        if (check12 == stored12) crc_valid = 1;
    }

    if (!crc_valid) {
        decoder_logf(decoder, 2, __func__, "CRC check failed");
        return DECODE_FAIL_MIC;
    }

    char id_str[13];
    snprintf(id_str, sizeof(id_str), "%04u-%07u", (id >> 20) & 0xfff, id & 0xfffff);

    int has_valid_flags  = 0;

    int loop1_bit       = 0;    // Loop 1, PIR motion, external contact for DW11, and reed for DW21R
    int tamper_bit      = 0;    // Case open tamper
    int loop2_bit       = 0;    // Loop 2, or reed for DW11
    int alarm_bit       = 0;    // Unused
    int battery_low_bit = 0;    // Tested
    int heartbeat_bit   = 0;    // Bit that toggles at a timed interval based on sum of 797

    // TODO: Should work on other packets as well.
    if (event_type == 0x7a || event_type == 0x74 || event_type == 0x79) {

        // TODO Should check bit 1 of the event data to see if this packet is encrypted
        vivint_sensor_t *s = vivint_ctx_find((vivint_ctx_t *)decoder_user_data(decoder), id);

        // If we don't know about this TXID, let's add it to our list if we have room and try to crack the seed
        if (!s)
        {
            vivint_ctx_t *ctx = (vivint_ctx_t *)decoder_user_data(decoder);
            if (ctx->count < VIVINT_MAX_SENSORS) {
                s = &ctx->sensors[ctx->count++];
                s->id            = id;
                s->seed          = 0xffff;
                s->last_counter  = 0xffff;
                s->counter_idx   = 0;
            }
        }
        if (s) {
            // Let's see if we can determine the seed
            if (s->seed == 0xffff || s->seed == 0x0000)
            {
                // Store the data we need to determine the seed
                // Prevent duplicates
                if (counter != s->last_counter)
                {
                    int idx = s->counter_idx % VIVINT_RABBIT_CIPHER_SIZE;
                    s->cipher_cache[idx] = cipher_nibble;
                    s->counters[idx] = counter;
                    s->counter_idx++;
                    // Check if we have enough data to determine the seed
                    if (s->counter_idx >= 6)
                    {
                        printf("Attempting to crack seed\n");
                        vivint_determine_seed(s);
                    }
                }
                s->last_counter = counter;
            } else {
                // This is where we try to decode the message
                // We also need to check the high nibble of byte 8 to check if 
                // the cipher is correct
                vivint_rabbit_advance_cipher(s, counter);
                if (vivint_validate_rabbit_nibble(s, cipher_nibble, counter))
                {
                    has_valid_flags  = 1;
                    flags = vivint_decrypt_flags(s, flags, counter);
                    /* Extract DW11 event bits (CTRABHEZ layout):
                       C=contact(7), T=tamper(6), R=reed(5), A=alarm(4),
                       B=battery_low(3), H=heartbeat(2), E=Encrypted(1),
                       Z=zero(0) */
                    loop1_bit       = flags & 0x80 ? 1 : 0;
                    tamper_bit      = flags & 0x40 ? 1 : 0;
                    loop2_bit       = flags & 0x20 ? 1 : 0;
                    alarm_bit       = flags & 0x10 ? 1 : 0;
                    battery_low_bit = flags & 0x08 ? 1 : 0;
                    heartbeat_bit   = flags & 0x04 ? 1 : 0;
                } else {
                    decoder_logf(decoder, 2, __func__, "Invalid Rabbit cipher check nibble");
                }
            }
        } else {
        }
    }

    char payload[21];
    if (!has_valid_flags) {
        for (int i = 0; i < 10; ++i)
            snprintf(&payload[i * 2], 3, "%02x", b[i]);
    }

    /* clang-format off */
    data_t *data = data_make(
            "model",        "",              DATA_STRING, "Vivint-Security",
            "id",           "",              DATA_STRING, id_str,
            "counter",      "",              DATA_FORMAT, "%04x", DATA_INT, counter,
            "flags",        "",              DATA_FORMAT, "%02x", DATA_INT, flags,
            "event_type",   "",              DATA_FORMAT, "%02x", DATA_INT, event_type,
            "state",        "",              DATA_COND, has_valid_flags,  DATA_STRING, loop1_bit ? "open" : "closed",
            "loop1",        "",              DATA_COND, has_valid_flags,  DATA_INT,     loop1_bit,
            "tamper",       "",              DATA_COND, has_valid_flags,  DATA_INT,     tamper_bit,
            "loop2",        "",              DATA_COND, has_valid_flags,  DATA_INT,     loop2_bit,
            "alarm",        "",              DATA_COND, has_valid_flags,  DATA_INT,     alarm_bit,
            "battery_low",  "Battery",       DATA_COND, has_valid_flags,  DATA_INT,     battery_low_bit,
            "heartbeat",    "",              DATA_COND, has_valid_flags,  DATA_INT,     heartbeat_bit,
            "data",         "",              DATA_COND, !has_valid_flags, DATA_STRING, payload,
            "mic",          "Integrity",     DATA_STRING, "CRC",
            NULL);
    /* clang-format on */

    decoder_output_data(decoder, data);
    return 1;
}

static char const *const output_fields[] = {
        "model",
        "id",
        "counter",
        "flags",
        "event_type",
        "state",
        "loop1",
        "tamper",
        "loop2",
        "alarm",
        "battery_low",
        "heartbeat",
        "data",
        "mic",
        NULL,
};

r_device const vivint = {
        .name        = "Vivint Door/Window Sensor, V-DW21R-345/V-DW11-345",
        .modulation  = OOK_PULSE_MANCHESTER_ZEROBIT,
        .short_width = 150,
        .long_width  = 0,
        .reset_limit = 300,
        .decode_fn   = &vivint_decode,
        .create_fn   = &vivint_create,
        .fields      = output_fields,
};
