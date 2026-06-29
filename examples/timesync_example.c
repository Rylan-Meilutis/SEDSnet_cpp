#include "sedsnet.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static SedsResult tx_send(const uint8_t * bytes, size_t len, void * user)
{
    (void)bytes;
    (void)len;
    (void)user;
    return SEDS_OK;
}

static SedsResult on_packet(const SedsPacketView * pkt, void * user)
{
    (void)user;
    const int32_t len = seds_pkt_to_string_len(pkt);
    if (len <= 0)
    {
        return SEDS_ERR;
    }
    char text[512];
    if ((size_t)len <= sizeof(text) && seds_pkt_to_string(pkt, text, sizeof(text)) == SEDS_OK)
    {
        printf("%s\n", text);
    }
    return SEDS_OK;
}

int main(void)
{
    SedsEndpointRef radio;
    SedsEndpointRef sd_card;
    SedsTypeRef gps_data;
    SedsTypeRef message_data;
    if (seds_endpoint_ref_by_name(SEDS_NAME_LITERAL("RADIO"), &radio) != SEDS_OK ||
        seds_endpoint_ref_by_name(SEDS_NAME_LITERAL("SD_CARD"), &sd_card) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("GPS_DATA"), &gps_data) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("MESSAGE_DATA"), &message_data) != SEDS_OK)
    {
        fprintf(stderr, "seed a runtime schema containing RADIO, SD_CARD, GPS_DATA, and MESSAGE_DATA\n");
        return 1;
    }

    const SedsLocalEndpointDesc locals[] = {
        {.endpoint = radio.id, .packet_handler = on_packet, .serialized_handler = NULL, .user = NULL},
        {.endpoint = sd_card.id, .packet_handler = on_packet, .serialized_handler = NULL, .user = NULL},
    };
    SedsRouter * router = seds_router_new(Seds_RM_Sink, NULL, NULL, locals, 2);
    if (router == NULL)
    {
        return 1;
    }

    (void)seds_router_add_side_packed(router, "TX", 2, tx_send, NULL, true);
    (void)seds_router_configure_timesync(router, true, 1, 10, 5000, 1000, 1000);
    (void)seds_router_set_local_network_datetime_millis(router, 2026, 1, 1, 12, 0, 0, 0);

    const float gps[3] = {37.7749f, -122.4194f, 30.0f};
    (void)seds_router_log_f32(router, gps_data.id, gps, 3);
    (void)seds_router_log_cstr(router, message_data.id, "hello from the C++ port");
    (void)seds_router_periodic(router, 0);

    uint64_t network_ms = 0;
    if (seds_router_get_network_time_ms(router, &network_ms) == SEDS_OK)
    {
        printf("network_time_ms=%llu\n", (unsigned long long)network_ms);
    }

    seds_router_free(router);
    return 0;
}
