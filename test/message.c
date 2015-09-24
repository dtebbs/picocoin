/* Copyright 2015 BitPay, Inc.
 * Copyright 2015 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <assert.h>
#include <ccoin/message.h>

static void check_buffer(const cstring *buffer,
                         const void *expected_data,
                         const size_t expected_size)
{
    if (buffer->len != expected_size) {
        fprintf(stderr, "Expected msg size: %d, saw size: %d\n",
                (int )expected_size, (int )(buffer->len));
    }
    assert(buffer->len == expected_size);

    if (0 != memcmp(buffer->str, expected_data, expected_size)) {
        const uint8_t *buffer_data = (const uint8_t *)buffer->str;
        const uint8_t *expect = (const uint8_t *)expected_data;
        int i;

        for (i = 0 ; i < expected_size ; ++i) {
            fprintf(stderr, "%03d: expected: %02x saw: %02x",
                    i, expect[i], buffer_data[i]);
            if (buffer_data[i] != expect[i]) {
                fprintf(stderr, " ***\n");
            } else {
                fputs("\n", stderr);
            }
        }
    }

    assert(0 == memcmp(buffer->str, expected_data, expected_size));
}

static void serialize_version_and_check(const struct msg_version *mv,
                                        const void *expected_data,
                                        const size_t expected_size)
{
    cstring *s = ser_msg_version(mv);
    check_buffer(s, expected_data, expected_size);
    cstr_free(s, true);
}

static void test_version()
{
    /*
    Example from protocol documentation wiki:
     https://en.bitcoin.it/wiki/Protocol_documentation

    Message Header:
      F9 BE B4 D9                                - Main network magic bytes
      76 65 72 73 69 6F 6E 00 00 00 00 00        - "version" command
      64 00 00 00                                - Payload is 100 bytes long
      3B 64 8D 5A                                - payload checksum

    Version message:
     24: 62 EA 00 00                             - protocol version 60002
     28: 01 00 00 00 00 00 00 00                 - 1 (NODE_NETWORK services)
     36: 11 B2 D0 50 00 00 00 00                 - Tue Dec 18 10:12:33 PST 2012
     44: 01 00 00 00 00 00 00 00
     52: 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00
     68: 00 00                                   - Recipient address info
     70: 01 00 00 00 00 00 00 00
     78: 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00
     94: 00 00                                   - Sender address info
     96: 3B 2E B3 5D 8C E6 17 65                 - Node ID
    104: 0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F
                                                 - "/Satoshi:0.7.2/" sub-version
    120: C0 3E 03 00                             - Last block: #212672
    */

    /*
    NOTE: wiki entry is broken (as of Sept 22, 2015).  The data above
    is correct if addrFrom.nServices = 1 (from offset 70), but in the
    raw data, addrFrom.nServices = 0,
    */

    const uint8_t expectIP[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
    };

    {
        const uint8_t expected[] = {
            0x62, 0xea, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x11, 0xb2, 0xd0, 0x50,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65,
            0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f,
            0xc0, 0x3e, 0x03, 0x00
        };

        /* serialize */
        {
            struct msg_version mv;

            msg_version_init(&mv);
            mv.nVersion = 60002;
            mv.nServices = 1;
            mv.nTime = 0x50d0b211;
            mv.addrTo.nServices = 1;
            mv.addrTo.ip[10] = mv.addrTo.ip[11] = 255;
            mv.addrFrom.nServices = 0;
            mv.addrFrom.ip[10] = mv.addrFrom.ip[11] = 255;
            mv.nonce = 0x6517e68c5db32e3b;
            strcpy(mv.strSubVer, "/Satoshi:0.7.2/");
            mv.nStartingHeight = 212672;

            serialize_version_and_check(&mv, expected, sizeof(expected));
            msg_version_free(&mv);
        }

        /* deserialize */
        {
            struct msg_version mv;
            msg_version_init(&mv);

            struct const_buffer buf = { expected, sizeof(expected) };
            assert(deser_msg_version(&mv, &buf));

            assert(60002 == mv.nVersion);
            assert(1 == mv.nServices);
            assert(0x50d0b211 == mv.nTime);
            assert(1 == mv.addrTo.nServices);
            assert(0 == memcmp(mv.addrTo.ip, expectIP, sizeof(expectIP)));
            assert(0 == mv.addrFrom.nServices);
            assert(0 == memcmp(mv.addrFrom.ip, expectIP, sizeof(expectIP)));
            assert(0x6517e68c5db32e3b == mv.nonce);
            assert(0 == strcmp(mv.strSubVer, "/Satoshi:0.7.2/"));
            assert(212672 == mv.nStartingHeight);

            msg_version_free(&mv);
        }
    }

    /* Equivalent message, but protocol version 70001 ('relay' == 1 by */
    /* default) */

    {
        const uint8_t expected[] = {
            /* version */
            0x71, 0x11, 0x01, 0x00,
            /* services */
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            /* timestamp */
            0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00,
            /* addr_recv */
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            /* addr_from */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            /* nonce */
            0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65,
            /* user_agent */
            0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f,
            /* start_height */
            0xc0, 0x3e, 0x03, 0x00,
            /* relay */
            0x01
        };

        /* serialize */
        {
            struct msg_version mv;

            msg_version_init(&mv);
            mv.nVersion = 70001;
            mv.nServices = 1;
            mv.nTime = 0x50d0b211;
            mv.addrTo.nServices = 1;
            mv.addrTo.ip[10] = mv.addrTo.ip[11] = 255;
            mv.addrFrom.nServices = 0;
            mv.addrFrom.ip[10] = mv.addrFrom.ip[11] = 255;
            mv.nonce = 0x6517e68c5db32e3b;
            strcpy(mv.strSubVer, "/Satoshi:0.7.2/");
            mv.nStartingHeight = 212672;

            serialize_version_and_check(&mv, expected, sizeof(expected));

            msg_version_free(&mv);
        }

        /* deserialize */
        {
            struct msg_version mv;
            msg_version_init(&mv);

            struct const_buffer buf = { expected, sizeof(expected) };
            assert(deser_msg_version(&mv, &buf));

            assert(70001 == mv.nVersion);
            assert(1 == mv.nServices);
            assert(0x50d0b211 == mv.nTime);
            assert(1 == mv.addrTo.nServices);
            assert(0 == memcmp(mv.addrTo.ip, expectIP, sizeof(expectIP)));
            assert(0 == mv.addrFrom.nServices);
            assert(0 == memcmp(mv.addrFrom.ip, expectIP, sizeof(expectIP)));
            assert(0x6517e68c5db32e3b == mv.nonce);
            assert(0 == strcmp(mv.strSubVer, "/Satoshi:0.7.2/"));
            assert(212672 == mv.nStartingHeight);
            assert(mv.bRelay);

            msg_version_free(&mv);
        }
    }

    /* Protocol version 70001 with 'relay' explicitly set to false */

    {
        const uint8_t expected[] = {
            /* version */
            0x71, 0x11, 0x01, 0x00,
            /* services */
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            /* timestamp */
            0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00,
            /* addr_recv */
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            /* addr_from */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            /* nonce */
            0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65,
            /* user_agent */
            0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f,
            /* start_height */
            0xc0, 0x3e, 0x03, 0x00,
            /* relay */
            0x00
        };

        /* serialize */
        {
            struct msg_version mv;

            msg_version_init(&mv);
            mv.nVersion = 70001;
            mv.nServices = 1;
            mv.nTime = 0x50d0b211;
            mv.addrTo.nServices = 1;
            mv.addrTo.ip[10] = mv.addrTo.ip[11] = 255;
            mv.addrFrom.nServices = 0;
            mv.addrFrom.ip[10] = mv.addrFrom.ip[11] = 255;
            mv.nonce = 0x6517e68c5db32e3b;
            strcpy(mv.strSubVer, "/Satoshi:0.7.2/");
            mv.nStartingHeight = 212672;
            mv.bRelay = false;

            serialize_version_and_check(&mv, expected, sizeof(expected));

            msg_version_free(&mv);
        }

        /* deserialize */
        {
            struct msg_version mv;
            struct const_buffer buf = { expected, sizeof(expected) };
            assert(deser_msg_version(&mv, &buf));

            assert(70001 == mv.nVersion);
            assert(1 == mv.nServices);
            assert(0x50d0b211 == mv.nTime);
            assert(1 == mv.addrTo.nServices);
            assert(0 == memcmp(mv.addrTo.ip, expectIP, sizeof(expectIP)));
            assert(0 == mv.addrFrom.nServices);
            assert(0 == memcmp(mv.addrFrom.ip, expectIP, sizeof(expectIP)));
            assert(0x6517e68c5db32e3b == mv.nonce);
            assert(0 == strcmp(mv.strSubVer, "/Satoshi:0.7.2/"));
            assert(212672 == mv.nStartingHeight);
            assert(!mv.bRelay);

            msg_version_free(&mv);
        }
    }
}

static void serialize_getheaders_and_check(const struct msg_getblocks *mgh,
                                           const void *expected_data,
                                           const size_t expected_size)
{
    cstring *s = ser_msg_getblocks(mgh);
    check_buffer(s, expected_data, expected_size);
    cstr_free(s, true);
}

static void test_getheaders()
{
    const char genesis[] =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    {
        bu256_t genesis_hash;
        hex_bu256(&genesis_hash, genesis);

        const uint8_t expected[] = {
            /* version */
            0x71, 0x11, 0x01, 0x00,
            /* hash_count */
            0x01,
            /* hashes */
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
            0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
            0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
            0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
            /* hash_stop */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        /* serialize */
        {
            struct msg_getblocks mgh;
            msg_getblocks_init(&mgh);

            msg_getblocks_init(&mgh);
            mgh.locator.nVersion = 70001;
            mgh.locator.vHave = parr_new(1, NULL);
            parr_add(mgh.locator.vHave, &genesis_hash);
            memset(&mgh.hash_stop, 0, sizeof(bu256_t));

            serialize_getheaders_and_check(&mgh, expected, sizeof(expected));

            msg_getblocks_free(&mgh);
        }

        /* deserialize */
        {
            struct msg_getblocks mgh;
            msg_getblocks_init(&mgh);

            struct const_buffer buf = { expected, sizeof(expected) };
            assert(deser_msg_getblocks(&mgh, &buf));

            assert(70001 == mgh.locator.nVersion);
            assert(1 == mgh.locator.vHave->len);
            assert(0 == memcmp(parr_idx(mgh.locator.vHave, 0),
                               &genesis_hash, sizeof(genesis_hash)));

            msg_getblocks_free(&mgh);
        }
    }

}

int main(int argc, char **argv)
{
    test_version();
    test_getheaders();

    return 0;
}
