#include "sedsnet_c_wrapper.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned hits;
    uint8_t last[512];
    size_t last_len;
} Capture;

static uint64_t now_ms(void * user) {
    (void)user;
    return 1000;
}

static SedsResult capture_tx(const uint8_t * bytes, size_t len, void * user) {
    Capture * cap = (Capture *)user;
    assert(cap != NULL);
    assert(len <= sizeof(cap->last));
    memcpy(cap->last, bytes, len);
    cap->last_len = len;
    cap->hits++;
    return SEDS_OK;
}

int main(void) {
    SedsWrapperRouter router = {0};
    SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
    cfg.mode = Seds_RM_Sink;
    cfg.now_ms = now_ms;
    cfg.announce_discovery = false;
    cfg.sender = seds_name_cstr("WRAPPER_CPP");
    assert(seds_wrapper_router_init(&router, &cfg) == SEDS_OK);
    assert(seds_wrapper_router_handle(&router) != NULL);
    assert(seds_wrapper_router_init_error(&router) == SEDS_OK);

    Capture cap = {0};
    SedsSideRef side = seds_wrapper_router_add_packed_side(&router,
                                                          seds_name_cstr("packed"),
                                                          capture_tx,
                                                          &cap,
                                                          false);
    assert(seds_side_is_valid(side));

    SedsTypeRef gps = {0};
    assert(seds_type_ref_by_name(seds_name_cstr("GPS_DATA"), &gps) == SEDS_OK);
    const float values[3] = {1.0f, 2.0f, 3.0f};
    assert(seds_wrapper_router_log_typed(&router,
                                         gps,
                                         values,
                                         3,
                                         sizeof(float),
                                         SEDS_EK_FLOAT,
                                         NULL,
                                         1) == SEDS_OK);
    assert(seds_wrapper_router_process(&router, 0) == SEDS_OK);
    assert(cap.hits == 1);
    assert(cap.last_len > 0);
    seds_wrapper_router_free(&router);
    assert(seds_wrapper_router_handle(&router) == NULL);

    SedsWrapperRelay relay = {0};
    SedsWrapperRelayConfig relay_cfg = seds_wrapper_relay_default_config();
    relay_cfg.now_ms = now_ms;
    relay_cfg.announce_discovery = false;
    relay_cfg.sender = seds_name_cstr("WRAPPER_RELAY");
    assert(seds_wrapper_relay_init(&relay, &relay_cfg) == SEDS_OK);
    assert(seds_wrapper_relay_handle(&relay) != NULL);
    SedsSideRef relay_side = seds_wrapper_relay_add_packed_side(&relay,
                                                               seds_name_cstr("relay"),
                                                               capture_tx,
                                                               &cap,
                                                               false);
    assert(seds_side_is_valid(relay_side));
    seds_wrapper_relay_free(&relay);

    printf("c wrapper api ok\n");
    return 0;
}
