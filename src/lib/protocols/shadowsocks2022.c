/*
 * shadowsocks2022.c
 *
 * Copyright (C) 2011-22 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SHADOWSOCKS2022

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_ss22_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SHADOWSOCKS2022, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

// https://tls12.xargs.org/#client-hello
static void ndpi_search_shadowsocks2022(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
    double SS22_ENTROPY = 0.98370826;

    struct ndpi_packet_struct *packet = &ndpi_struct->packet;
    const u_int8_t *payload = packet->payload;
    u_int32_t payload_len = packet->payload_packet_len;

    /**
     * min amount of bytes for TLS is 6 ~ header
     */
    if (payload_len < 6) return;

    NDPI_LOG_DBG(ndpi_struct, "search shadowsocks2022\n");

    // =======================
    // === protocol header ===

    bool isTLSHandShake = payload[0] == 0x16;
    bool isTLSApplication = payload[0] == 0x17;
    bool isTLSCloseNotify = payload[0] == 0x15;
    bool isTLSChangeCipherSpec = payload[0] == 0x14;

    /** extract bytes as readable parameters*/
    int TLSFingerPrint = payload[1];
    int TLSVersion = payload[2];
    bool isCorrectTLSVersion = TLSFingerPrint == 0x03 &&
                               (TLSVersion == 0x01 ||
                                TLSVersion == 0x02 ||
                                TLSVersion == 0x03);

    // =======================
    // ==== protocol meta ====

    /**
     * @todo add more bytes to check according to header, to make impossible to block TLS connection
     * payload[5]: client_hello (0x01), server_hello (0x02), new_session (0x04), key_exchange (0x10)
     */

    // int tlsMetaData = flow->packet.payload[5];
    // bool isCorrectTLSMetaData = tlsMetaData == 0x01 ||
    //                             tlsMetaData == 0x02 ||
    //                             tlsMetaData == 0x04 ||
    //                             tlsMetaData == 0x10;
    // test if packet payload got attributes of TLS

    if ((isTLSHandShake || isTLSApplication || isTLSChangeCipherSpec || isTLSCloseNotify) && isCorrectTLSVersion) {
        // ...
    } else {
        if (flow->entropy > SS22_ENTROPY) {
            NDPI_LOG_INFO(ndpi_struct, "found ShadowSocks22 (or VPN): DSI\n");
            ndpi_int_ss22_add_connection(ndpi_struct, flow);
            return;
        }
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_shadowsocks2022_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
    ndpi_set_bitmask_protocol_detection("ShadowSocks2022", ndpi_struct, *id,
                                        NDPI_PROTOCOL_SHADOWSOCKS2022,
                                        ndpi_search_shadowsocks2022,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);

    *id += 1;
}

/*
16 03 01 02 00 01 00 01  fc 03 03 46 67 58 eb c5
06 8a ab 7c d7 45 16 95  a1 d9 11 39 e4 e5 ce 4b
fc 3c c6 93 6a 34 23 ae  b8 68 b7 20 a0 07 5f 4a
0f 15 9f 4a c6 9d e2 f8  8d 2e 07 18 51 35 1a e8
33 2f 6b 31 c4 2e 62 85  33 eb 53 0a 00 22 13 01
13 03 13 02 c0 2b c0 2f  cc a9 cc a8 c0 2c c0 30
c0 0a c0 09 c0 13 c0 14  00 9c 00 9d 00 2f 00 35
01 00 01 91 00 00 00 12  00 10 00 00 0d 74 61 67
6c 69 74 69 63 73 2e 63  6f 6d 00 17 00 00 ff 01
00 01 00 00 0a 00 0e 00  0c 00 1d 00 17 00 18 00
19 01 00 01 01 00 0b 00  02 01 00 00 23 00 00 00
10 00 0e 00 0c 02 68 32  08 68 74 74 70 2f 31 2e
31 00 05 00 05 01 00 00  00 00 00 22 00 0a 00 08
04 03 05 03 06 03 02 03  00 33 00 6b 00 69 00 1d
00 20 ba 7a 82 4f 09 80  b4 11 08 eb 09 8a ac b5
2a 39 01 33 a7 83 9b 39  15 20 34 f3 a1 05 9b 0d
f6 60 00 17 00 41 04 a2  4e 77 ef e6 bd 6a e3 fd
2d 18 2d 65 de ab 97 b3  bf ae 0c e2 ae 4e 99 ce
77 0a 76 9a 16 47 ea dc  bc 0c 5c 2c 00 81 7a 0a
d0 10 a4 78 17 d3 6d a3  99 0c b0 d9 3a 77 0f a1
9d 59 0a 66 60 3c 2d 00  2b 00 05 04 03 04 03 03
00 0d 00 18 00 16 04 03  05 03 06 03 08 04 08 05
08 06 04 01 05 01 06 01  02 03 02 01 00 2d 00 02
01 01 00 1c 00 02 40 01  00 15 00 89 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00
*/