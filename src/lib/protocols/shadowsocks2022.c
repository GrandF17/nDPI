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

#include <math.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <stdio.h>

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_shadowsocks2022_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SHADOWSOCKS2022, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static double count_entropy(const uint8_t *data, uint16_t len) {
    static const uint8_t bit_count_table[256] = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

    size_t filled_bits = 0;

    for (uint16_t i = 0; i < len; ++i) {
        filled_bits += bit_count_table[data[i]];
    }

    size_t total_bits = len * 8;
    size_t empty_bits = total_bits - filled_bits;

    if (filled_bits == 0 || empty_bits == 0) return 0.0;

    double empty_probability = (double)empty_bits / total_bits;
    double filled_probability = (double)filled_bits / total_bits;
    double entropy = -empty_probability * log2(empty_probability) - filled_probability * log2(filled_probability);

    return entropy;
}

static void ndpi_search_shadowsocks2022(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
    if (ndpi_struct->packet->payload_packet_len < 32) return;

    double SS22_ENTROPY = 0.98370826;
    const uint8_t *payload = ndpi_struct->packet->payload;

    /**
     * count entropy for first 32 bytes of information
     */
    double entropy = count_entropy(payload, 32);

    /* Found Protocol */
    if (entropy > SS22_ENTROPY) {
        NDPI_LOG(ndpi_struct, "probably found ShadowSocks22 (or VPN)\n");
        ndpi_int_shadowsocks2022_add_connection(ndpi_struct, flow);
        return;
    }

    /* Exclude Protocol */
    NDPI_LOG(NDPI_PROTOCOL_SHADOWSOCKS2022, ndpi_struct, NDPI_LOG_DEBUG, "exclude ShadowSocks22 protocol.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SHADOWSOCKS2022);
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