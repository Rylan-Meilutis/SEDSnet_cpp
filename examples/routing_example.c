#include "sedsnet.h"

#include <stdio.h>

static SedsResult print_packet(const SedsPacketView * pkt, void * user)
{
    const char * label = (const char *)user;
    char text[256];
    if (seds_pkt_to_string(pkt, text, sizeof(text)) == SEDS_OK)
    {
        printf("[%s] %s\n", label, text);
    }
    return SEDS_OK;
}

int main(void)
{
    SedsTypeRef gps_data;
    if (seds_type_ref_by_name(SEDS_NAME_LITERAL("GPS_DATA"), &gps_data) != SEDS_OK)
    {
        fprintf(stderr, "seed a runtime schema containing GPS_DATA\n");
        return 1;
    }

    SedsRouter * router = seds_router_new(Seds_RM_Sink, NULL, NULL, NULL, 0);
    if (router == NULL)
    {
        return 1;
    }

    const int32_t side_a = seds_router_add_side_packet(router, "WAN_A", 5, print_packet, "WAN_A", false);
    const int32_t side_b = seds_router_add_side_packet(router, "WAN_B", 5, print_packet, "WAN_B", false);

    (void)seds_router_set_source_route_mode(router, -1, Seds_RSM_Weighted);
    (void)seds_router_set_route_weight(router, -1, side_a, 3);
    (void)seds_router_set_route_weight(router, -1, side_b, 1);

    const float gps[3] = {1.0f, 2.0f, 3.0f};
    (void)seds_router_log_f32(router, gps_data.id, gps, 3);
    (void)seds_router_log_f32(router, gps_data.id, gps, 3);

    (void)seds_router_set_typed_route(router, -1, gps_data.id, side_a, true);
    (void)seds_router_set_typed_route(router, -1, gps_data.id, side_b, true);
    (void)seds_router_log_f32(router, gps_data.id, gps, 3);

    seds_router_free(router);
    return 0;
}
