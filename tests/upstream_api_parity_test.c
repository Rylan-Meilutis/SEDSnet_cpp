#include "sedsnet_c_wrapper.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned hits;
    uint8_t last[1024];
    size_t last_len;
} Capture;

typedef struct {
    unsigned hits;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source_address;
    uint8_t payload[128];
    size_t payload_len;
} P2pCapture;

typedef struct {
    unsigned accepted;
    unsigned connected;
    unsigned data;
    unsigned closed;
    uint32_t stream_id;
    uint32_t peer_stream_id;
    uint8_t payload[128];
    size_t payload_len;
} P2pStreamCapture;

static uint32_t g_gps_ty;
static uint32_t g_sd_ep;
static uint32_t g_radio_ep;

static SedsResult capture_tx(const uint8_t *bytes, size_t len, void *user) {
    Capture *cap = (Capture *)user;
    assert(cap != NULL);
    assert(len < sizeof(cap->last));
    memcpy(cap->last, bytes, len);
    cap->last_len = len;
    cap->hits++;
    return SEDS_OK;
}

static SedsResult packet_count(const SedsPacketView *pkt, void *user) {
    unsigned *count = (unsigned *)user;
    assert(pkt != NULL);
    assert(count != NULL);
    (*count)++;
    return SEDS_OK;
}

static SedsResult managed_update_count(const SedsPacketView *pkt, void *user) {
    unsigned *count = (unsigned *)user;
    assert(pkt != NULL);
    assert(pkt->ty == g_gps_ty);
    (*count)++;
    return SEDS_OK;
}

static SedsResult p2p_capture(const SedsP2pMessageView *msg, void *user) {
    P2pCapture *cap = (P2pCapture *)user;
    assert(msg != NULL);
    assert(cap != NULL);
    assert(msg->payload_len <= sizeof(cap->payload));
    cap->hits++;
    cap->source_port = msg->source_port;
    cap->destination_port = msg->destination_port;
    cap->source_address = msg->source_address;
    cap->payload_len = msg->payload_len;
    memcpy(cap->payload, msg->payload, msg->payload_len);
    return SEDS_OK;
}

static SedsResult p2p_stream_capture(const SedsP2pStreamEventView *event, void *user) {
    P2pStreamCapture *cap = (P2pStreamCapture *)user;
    assert(event != NULL);
    assert(cap != NULL);
    if (event->kind == 1) {
        cap->accepted++;
    } else if (event->kind == 2) {
        cap->connected++;
    } else if (event->kind == 3) {
        cap->data++;
    } else if (event->kind == 4) {
        cap->closed++;
    }
    cap->stream_id = event->stream_id;
    cap->peer_stream_id = event->peer_stream_id;
    assert(event->payload_len <= sizeof(cap->payload));
    cap->payload_len = event->payload_len;
    memcpy(cap->payload, event->payload, event->payload_len);
    return SEDS_OK;
}

#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
typedef struct {
    int seals;
    int opens;
} CryptoState;

static SedsResult crypto_seal(uint32_t key_id,
                              const uint8_t *nonce,
                              size_t nonce_len,
                              const uint8_t *aad,
                              size_t aad_len,
                              const uint8_t *plaintext,
                              size_t plaintext_len,
                              uint8_t *ciphertext_out,
                              size_t ciphertext_cap,
                              size_t *ciphertext_len_out,
                              uint8_t *tag_out,
                              size_t tag_cap,
                              size_t *tag_len_out,
                              void *user) {
    CryptoState *state = (CryptoState *)user;
    (void)key_id;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    assert(ciphertext_cap >= plaintext_len);
    memcpy(ciphertext_out, plaintext, plaintext_len);
    *ciphertext_len_out = plaintext_len;
    assert(tag_cap > 0);
    tag_out[0] = 7;
    *tag_len_out = 1;
    state->seals++;
    return SEDS_OK;
}

static SedsResult crypto_open(uint32_t key_id,
                              const uint8_t *nonce,
                              size_t nonce_len,
                              const uint8_t *aad,
                              size_t aad_len,
                              const uint8_t *ciphertext,
                              size_t ciphertext_len,
                              const uint8_t *tag,
                              size_t tag_len,
                              uint8_t *plaintext_out,
                              size_t plaintext_cap,
                              size_t *plaintext_len_out,
                              void *user) {
    CryptoState *state = (CryptoState *)user;
    (void)key_id;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)tag;
    (void)tag_len;
    assert(plaintext_cap >= ciphertext_len);
    memcpy(plaintext_out, ciphertext, ciphertext_len);
    *plaintext_len_out = ciphertext_len;
    state->opens++;
    return SEDS_OK;
}
#endif

static void init_schema_refs(void) {
    SedsDataTypeInfo ty = {0};
    SedsEndpointInfo ep = {0};
    assert(seds_dtype_get_info_by_name("GPS_DATA", strlen("GPS_DATA"), NULL, 0, &ty) == SEDS_OK);
    assert(ty.exists);
    g_gps_ty = ty.id;
    assert(seds_endpoint_get_info_by_name("SD_CARD", strlen("SD_CARD"), &ep) == SEDS_OK);
    assert(ep.exists);
    g_sd_ep = ep.id;
    assert(seds_endpoint_get_info_by_name("RADIO", strlen("RADIO"), &ep) == SEDS_OK);
    assert(ep.exists);
    g_radio_ep = ep.id;
}

static void test_name_and_metadata_helpers(void) {
    SedsName literal = SEDS_NAME_LITERAL("GPS_DATA");
    SedsName cstr = seds_name_cstr("SD_CARD");
    SedsTypeRef ty_ref = SEDS_TYPE_REF(g_gps_ty);
    SedsEndpointRef ep_ref = SEDS_ENDPOINT_REF(g_sd_ep);
    SedsSideRef side_ref = SEDS_SIDE_REF(2);

    assert(literal.len == 8);
    assert(cstr.len == 7);
    assert((uint32_t)ty_ref.id == g_gps_ty);
    assert((uint32_t)ep_ref.id == g_sd_ep);
    assert(seds_side_is_valid(side_ref));
    assert(!seds_side_is_valid(SEDS_SIDE_INVALID));

    assert(seds_dtype_exists(g_gps_ty));
    assert(seds_endpoint_exists(g_sd_ep));
    assert(!seds_dtype_exists(999999u));
    assert(!seds_endpoint_exists(999999u));

    SedsEndpointInfo ep_info;
    assert(seds_endpoint_get_info(g_sd_ep, &ep_info) == SEDS_OK);
    assert(ep_info.exists);
    assert(ep_info.id == g_sd_ep);
    assert(ep_info.name_len == strlen("SD_CARD"));
    assert(memcmp(ep_info.name, "SD_CARD", ep_info.name_len) == 0);

    SedsEndpointInfo ep_by_name;
    assert(seds_endpoint_get_info_by_name(cstr.ptr, cstr.len, &ep_by_name) == SEDS_OK);
    assert(ep_by_name.exists);
    assert(ep_by_name.id == 100u);

    uint32_t endpoints[4] = {0};
    SedsDataTypeInfo ty_info;
    assert(seds_dtype_get_info(g_gps_ty, endpoints, 4, &ty_info) == SEDS_OK);
    assert(ty_info.exists);
    assert(ty_info.id == g_gps_ty);
    assert(ty_info.fixed_size == 12);
    assert(ty_info.num_endpoints == 2);
    assert((endpoints[0] == g_sd_ep || endpoints[1] == g_sd_ep));
    assert((endpoints[0] == g_radio_ep || endpoints[1] == g_radio_ep));

    SedsDataTypeInfo ty_by_name;
    assert(seds_dtype_get_info_by_name(literal.ptr, literal.len, endpoints, 4, &ty_by_name) == SEDS_OK);
    assert(ty_by_name.exists);
    assert(ty_by_name.id == 100u);

    SedsTypeRef found_ty;
    SedsEndpointRef found_ep;
    assert(seds_type_ref_by_name(literal, &found_ty) == SEDS_OK);
    assert((uint32_t)found_ty.id == 100u);
    assert(seds_endpoint_ref_by_name(cstr, &found_ep) == SEDS_OK);
    assert((uint32_t)found_ep.id == 100u);
    assert(seds_type_ref_exists(found_ty));
    assert(seds_endpoint_ref_exists(found_ep));
    assert(seds_type_ref_expected_size(found_ty) == 12);
}

static void test_packed_aliases_and_lifecycle(void) {
    unsigned local_hits = 0;
    const SedsLocalEndpointDesc handlers[] = {
        {.endpoint = g_sd_ep, .packet_handler = packet_count, .packed_handler = NULL, .user = &local_hits},
    };
    Capture tx = {0};
    SedsRouter *router = seds_router_new_ex(Seds_RM_Sink, NULL, NULL, handlers, 1,
                                            SEDS_ROUTER_E2E_DISABLED, 0);
    assert(router != NULL);
    assert(seds_router_set_sender_id(router, "CPP", 3) == SEDS_OK);
    assert(seds_router_announce_leave(router) == SEDS_OK);

    const int32_t side = seds_router_add_side_packed(router, "BUS", 3, capture_tx, &tx, false);
    assert(side >= 0);
    const int32_t small = seds_router_add_side_packed_small_packets(router, "SMALL", 5, capture_tx, &tx, false, 256);
    assert(small >= 0);
    const int32_t prof = seds_router_add_side_packed_profile(router, "PROF", 4, capture_tx, &tx, false,
                                                            SEDS_SIDE_TRANSPORT_PROFILE_CANONICAL, 0, 0, 0);
    assert(prof >= 0);

    const float gps[3] = {1.0f, 2.0f, 3.0f};
    assert(seds_router_log_f32(router, (SedsDataType)g_gps_ty, gps, 3) == SEDS_OK);
    assert(local_hits == 1);
    assert(tx.hits == 3);
    assert(seds_pkt_validate_packed(tx.last, tx.last_len) == SEDS_OK);

    SedsOwnedPacket *owned = seds_pkt_unpack_owned(tx.last, tx.last_len);
    assert(owned != NULL);
    SedsPacketView view;
    assert(seds_owned_pkt_view(owned, &view) == SEDS_OK);
    assert(view.ty == g_gps_ty);
    const int32_t pack_len = seds_pkt_pack_len(&view);
    assert(pack_len > 0);
    uint8_t repacked[1024];
    assert(seds_pkt_pack(&view, repacked, sizeof(repacked)) == pack_len);
    assert(seds_pkt_validate_packed(repacked, (size_t)pack_len) == SEDS_OK);
    seds_owned_pkt_free(owned);

    assert(seds_router_receive_packed(router, repacked, (size_t)pack_len) == SEDS_OK);
    assert(seds_router_rx_packed_packet_to_queue_from_side(router, (uint32_t)side, repacked, (size_t)pack_len) == SEDS_OK);
    assert(seds_router_process_all_queues(router) == SEDS_OK);

    assert(seds_router_bind_p2p_port(router, 10, NULL, NULL) == SEDS_BAD_ARG);
    assert(seds_router_set_network_variable_packed(router, repacked, (size_t)pack_len) == SEDS_OK);
    assert(seds_router_cached_managed_variable_packed_len(router, (SedsDataType)g_gps_ty) == pack_len);
    assert(seds_router_enable_managed_variable(router, (SedsDataType)g_gps_ty) == SEDS_OK);

    seds_router_free(router);
}

static void test_relay_packed_aliases(void) {
    Capture a = {0};
    Capture b = {0};
    SedsRelay *relay = seds_relay_new(NULL, NULL);
    assert(relay != NULL);
    assert(seds_relay_set_sender_id(relay, "REL", 3) == SEDS_OK);
    assert(seds_relay_announce_leave(relay) == SEDS_OK);

    const int32_t side_a = seds_relay_add_side_packed(relay, "A", 1, capture_tx, &a, false);
    const int32_t side_b = seds_relay_add_side_packed_profile(relay, "B", 1, capture_tx, &b, false,
                                                              SEDS_SIDE_TRANSPORT_PROFILE_CANONICAL, 0, 0, 0);
    assert(side_a >= 0);
    assert(side_b >= 0);

    uint32_t endpoints[] = {g_sd_ep};
    const float gps[3] = {4.0f, 5.0f, 6.0f};
    SedsPacketView pkt = {
        .ty = g_gps_ty,
        .data_size = sizeof(gps),
        .sender = "SRC",
        .sender_len = 3,
        .endpoints = endpoints,
        .num_endpoints = 1,
        .timestamp = 10,
        .payload = (const uint8_t *)gps,
        .payload_len = sizeof(gps),
    };
    uint8_t wire[1024];
    const int32_t wire_len = seds_pkt_pack(&pkt, wire, sizeof(wire));
    assert(wire_len > 0);
    assert(seds_relay_rx_packed_from_side(relay, (uint32_t)side_a, wire, (size_t)wire_len) == SEDS_OK);
    assert(seds_relay_process_all_queues(relay) == SEDS_OK);
    assert(b.hits == 1);

    seds_relay_free(relay);
}

static void test_runtime_schema_mutation(void) {
    assert(seds_endpoint_register_ex(777u, "X", 1, "endpoint x", strlen("endpoint x"), true) == SEDS_OK);
    SedsEndpointInfo ep = {0};
    assert(seds_endpoint_get_info_by_name("X", 1, &ep) == SEDS_OK);
    assert(ep.exists && ep.id == 777u);
    assert(ep.link_local_only);
    assert(ep.description_len == strlen("endpoint x"));
    assert(strncmp(ep.description, "endpoint x", ep.description_len) == 0);

    const uint32_t endpoints[] = {777u};
    assert(seds_dtype_register(778u, "Y", 1, true, 4, 2, 0, 1, 9, endpoints, 1) == SEDS_OK);
    SedsDataTypeInfo ty = {0};
    uint32_t out_eps[2] = {0};
    assert(seds_dtype_get_info_by_name("Y", 1, out_eps, 2, &ty) == SEDS_OK);
    assert(ty.exists && ty.id == 778u && ty.num_endpoints == 1u && out_eps[0] == 777u);
    assert(ty.priority == 9u);

    assert(seds_dtype_register(778u, "Y", 1, true, 4, 2, 0, 1, 9, endpoints, 1) == SEDS_OK);
    assert(seds_dtype_register(778u, "Y", 1, true, 5, 2, 0, 1, 9, endpoints, 1) == SEDS_BAD_ARG);
    assert(seds_dtype_register(779u, "Y", 1, true, 4, 2, 0, 1, 9, endpoints, 1) == SEDS_BAD_ARG);
    assert(seds_dtype_register(779u, "Z", 1, true, 4, 2, 0, 1, 9, NULL, 1) == SEDS_BAD_ARG);
    const uint32_t missing_endpoint[] = {999999u};
    assert(seds_dtype_register(779u, "Z", 1, true, 4, 2, 0, 1, 9, missing_endpoint, 1) == SEDS_BAD_ARG);
    assert(seds_endpoint_register_ex(777u, "X", 1, "endpoint x", strlen("endpoint x"), true) == SEDS_OK);
    assert(seds_endpoint_register(777u, "XX", 2, false) == SEDS_BAD_ARG);
    assert(seds_endpoint_register(779u, "X", 1, false) == SEDS_BAD_ARG);
    assert(seds_endpoint_remove(SEDS_EP_DISCOVERY) == SEDS_BAD_ARG);
    assert(seds_dtype_remove(SEDS_DT_DISCOVERY_ANNOUNCE) == SEDS_BAD_ARG);

    const char json[] =
        "{\"endpoints\":[{\"rust\":\"JsonEp\",\"name\":\"JSON_EP\",\"description\":\"json endpoint\",\"broadcast_mode\":\"Never\"}],"
        "\"types\":[{\"rust\":\"JsonTy\",\"name\":\"JSON_TY\",\"doc\":\"json type\",\"priority\":77,\"reliable\":true,"
        "\"class\":\"Warning\",\"element\":{\"kind\":\"Static\",\"data_type\":\"UInt8\",\"count\":2},"
        "\"endpoints\":[\"JsonEp\"]}]}";
    assert(seds_schema_register_json_bytes((const uint8_t *)json, sizeof(json) - 1) == SEDS_OK);
    assert(seds_endpoint_get_info_by_name("JSON_EP", 7, &ep) == SEDS_OK);
    assert(ep.exists && ep.id >= 100u);
    assert(ep.link_local_only);
    assert(ep.description_len == strlen("json endpoint"));
    assert(seds_dtype_get_info_by_name("JSON_TY", 7, out_eps, 2, &ty) == SEDS_OK);
    assert(ty.exists && ty.id >= 100u && ty.fixed_size == 2u);
    assert(ty.priority == 77u);
    assert(ty.reliable == 1u);
    assert(ty.message_class == 2u);
    assert(ty.description_len == strlen("json type"));
    assert(seds_schema_register_json_file("schema.json", 11) == SEDS_IO);
    assert(seds_dtype_remove_by_name("Y", 1) == SEDS_OK);
    assert(!seds_dtype_exists(778u));
    assert(seds_endpoint_remove_by_name("X", 1) == SEDS_OK);
    assert(!seds_endpoint_exists(777u));
    assert(seds_endpoint_remove_by_name("X", 1) == SEDS_OK);
    assert(seds_endpoint_remove_by_name(NULL, 0) == SEDS_BAD_ARG);
    assert(seds_dtype_remove_by_name(NULL, 0) == SEDS_BAD_ARG);
}

static void test_runtime_stats_and_memory_layout_exports(void) {
    Capture cap = {0};
    SedsRouter *router = seds_router_new(Seds_RM_Sink, NULL, NULL, NULL, 0);
    assert(router != NULL);
    int32_t side = seds_router_add_side_packed_profile(router,
                                                       "UPLINK",
                                                       strlen("UPLINK"),
                                                       capture_tx,
                                                       &cap,
                                                       true,
                                                       SEDS_SIDE_TRANSPORT_PROFILE_IPV4_LIKE,
                                                       128,
                                                       0,
                                                       2);
    assert(side >= 0);
    assert(seds_router_set_source_route_mode(router, -1, Seds_RSM_Weighted) == SEDS_OK);
    assert(seds_router_set_route_weight(router, -1, side, 3) == SEDS_OK);
    assert(seds_router_set_route_priority(router, -1, side, 7) == SEDS_OK);

    int32_t len = seds_router_export_runtime_stats_len(router);
    assert(len > 0 && len < 8192);
    char json[8192];
    assert(seds_router_export_runtime_stats(router, json, (size_t)len) == SEDS_OK);
    assert(strstr(json, "\"sides\":[") != NULL);
    assert(strstr(json, "\"side_name\":\"UPLINK\"") != NULL);
    assert(strstr(json, "\"reliable_enabled\":true") != NULL);
    assert(strstr(json, "\"header_template_enabled\":true") != NULL);
    assert(strstr(json, "\"compact_header_target_bytes\":20") != NULL);
    assert(strstr(json, "\"max_side_transport_templates\":2") != NULL);
    assert(strstr(json, "\"side_transport_profile\":\"ipv4_like\"") != NULL);
    assert(strstr(json, "\"route_modes\":[") != NULL);
    assert(strstr(json, "\"selection_mode\":\"Weighted\"") != NULL);
    assert(strstr(json, "\"route_weights\":[") != NULL);
    assert(strstr(json, "\"weight\":3") != NULL);
    assert(strstr(json, "\"route_priorities\":[") != NULL);
    assert(strstr(json, "\"priority\":7") != NULL);
    assert(strstr(json, "\"queues\":{") != NULL);
    assert(strstr(json, "\"reliable\":{") != NULL);
    assert(strstr(json, "\"discovery\":{") != NULL);

    len = seds_router_export_memory_layout_len(router);
    assert(len > 0 && len < 4096);
    assert(seds_router_export_memory_layout(router, json, (size_t)len) == SEDS_OK);
    assert(strstr(json, "\"kind\":\"router\"") != NULL);
    assert(strstr(json, "\"shared_queue_bytes_allocated\":") != NULL);
    assert(strstr(json, "\"rx_queue_bytes_used\":") != NULL);
    assert(strstr(json, "\"tx_queue_bytes_allocated\":") != NULL);
    assert(strstr(json, "\"network_variable_cache_bytes_used\":") != NULL);
    seds_router_free(router);

    SedsRelay *relay = seds_relay_new(NULL, NULL);
    assert(relay != NULL);
    side = seds_relay_add_side_packed_profile(relay,
                                              "RELAY_UP",
                                              strlen("RELAY_UP"),
                                              capture_tx,
                                              &cap,
                                              false,
                                              SEDS_SIDE_TRANSPORT_PROFILE_TEMPLATE,
                                              64,
                                              0,
                                              3);
    assert(side >= 0);
    len = seds_relay_export_runtime_stats_len(relay);
    assert(len > 0 && len < 8192);
    assert(seds_relay_export_runtime_stats(relay, json, (size_t)len) == SEDS_OK);
    assert(strstr(json, "\"side_name\":\"RELAY_UP\"") != NULL);
    assert(strstr(json, "\"side_transport_profile\":\"template\"") != NULL);
    assert(strstr(json, "\"header_template_enabled\":true") != NULL);
    len = seds_relay_export_memory_layout_len(relay);
    assert(len > 0 && len < 4096);
    assert(seds_relay_export_memory_layout(relay, json, (size_t)len) == SEDS_OK);
    assert(strstr(json, "\"kind\":\"relay\"") != NULL);
    assert(strstr(json, "\"replay_queue_bytes_allocated\":") != NULL);
    seds_relay_free(relay);
}

static void test_runtime_tuning_and_memory_config(void) {
    SedsRuntimeTuningConfig cfg = {0};
    assert(seds_get_runtime_tuning_config(&cfg) == SEDS_OK);
    assert(cfg.payload_compress_threshold == 128u);
    assert(cfg.static_string_length == 1024u);
    assert(cfg.static_hex_length == 1024u);
    assert(cfg.string_precision == 8u);
    assert(cfg.max_handler_retries == 3u);
    assert(cfg.reliable_retransmit_ms == 200u);
    assert(cfg.reliable_max_retries == 8u);
    assert(cfg.reliable_max_pending == 32u);
    assert(cfg.reliable_max_return_routes == 128u);
    assert(cfg.reliable_max_end_to_end_pending == 32u);
    assert(cfg.reliable_max_end_to_end_ack_cache == 128u);

    SedsRuntimeTuningConfig custom = cfg;
    custom.payload_compress_threshold = 0u;
    custom.string_precision = 0u;
    custom.static_string_length = 64u;
    custom.static_hex_length = 96u;
    custom.max_handler_retries = 4u;
    custom.reliable_retransmit_ms = 50u;
    custom.reliable_max_retries = 5u;
    custom.reliable_max_pending = 6u;
    custom.reliable_max_return_routes = 7u;
    custom.reliable_max_end_to_end_pending = 8u;
    custom.reliable_max_end_to_end_ack_cache = 9u;
    assert(seds_set_runtime_tuning_config(&custom) == SEDS_OK);
    SedsRuntimeTuningConfig got = {0};
    assert(seds_get_runtime_tuning_config(&got) == SEDS_OK);
    assert(got.payload_compress_threshold == 0u);
    assert(got.string_precision == 0u);
    assert(got.static_string_length == 64u);
    assert(got.reliable_max_end_to_end_ack_cache == 9u);
    assert(seds_set_runtime_tuning_config(&cfg) == SEDS_OK);

    custom.static_string_length = 0u;
    assert(seds_set_runtime_tuning_config(&custom) == SEDS_BAD_ARG);
    assert(seds_get_runtime_tuning_config(NULL) == SEDS_BAD_ARG);
    assert(seds_set_runtime_tuning_config(NULL) == SEDS_BAD_ARG);

    const SedsRuntimeMemoryConfig memory = {
        .max_queue_budget = 4096u,
        .max_recent_rx_ids = 8u,
        .starting_queue_size = 512u,
        .queue_grow_step = 2.0,
    };
    SedsRouter *router = seds_router_new_with_memory(Seds_RM_Sink, NULL, NULL, NULL, 0,
                                                     SEDS_ROUTER_E2E_PREFERRED, 0, &memory);
    assert(router != NULL);
    char json[4096];
    int32_t len = seds_router_export_memory_layout_len(router);
    assert(len > 0 && len < (int32_t)sizeof(json));
    assert(seds_router_export_memory_layout(router, json, (size_t)len) == SEDS_OK);
    assert(strstr(json, "\"shared_queue_bytes_allocated\":4096") != NULL);
    assert(strstr(json, "\"recent_rx_bytes_allocated\":64") != NULL);
    uint32_t address = 0;
    assert(seds_router_configure_address(router, 2u, 0x10203040u) == SEDS_OK);
    assert(seds_router_current_address(router, &address) == SEDS_OK);
    assert(address == 0x10203040u);
    assert(seds_router_configure_address(router, 1u, 0u) == SEDS_OK);
    assert(seds_router_current_address(router, &address) == SEDS_OK);
    assert(address == 1u);
    assert(seds_router_configure_address(router, 9u, 0u) == SEDS_BAD_ARG);
    seds_router_free(router);

    SedsRelay *relay = seds_relay_new_with_memory(NULL, NULL, &memory);
    assert(relay != NULL);
    len = seds_relay_export_memory_layout_len(relay);
    assert(len > 0 && len < (int32_t)sizeof(json));
    assert(seds_relay_export_memory_layout(relay, json, (size_t)len) == SEDS_OK);
    assert(strstr(json, "\"shared_queue_bytes_allocated\":4096") != NULL);
    assert(strstr(json, "\"recent_rx_bytes_allocated\":64") != NULL);
    seds_relay_free(relay);

    SedsRuntimeMemoryConfig bad = memory;
    bad.max_queue_budget = 0u;
    assert(seds_router_new_with_memory(Seds_RM_Sink, NULL, NULL, NULL, 0,
                                       SEDS_ROUTER_E2E_PREFERRED, 0, &bad) == NULL);
    assert(seds_relay_new_with_memory(NULL, NULL, &bad) == NULL);
    bad = memory;
    bad.queue_grow_step = 1.0;
    assert(seds_relay_new_with_memory(NULL, NULL, &bad) == NULL);
    assert(seds_router_new_with_memory(Seds_RM_Sink, NULL, NULL, NULL, 0, 9u, 0, &memory) == NULL);
}

static void test_handler_registration_creates_missing_endpoint(void) {
    const uint32_t endpoint = 9249u;
    (void)seds_endpoint_remove(endpoint);
    assert(!seds_endpoint_exists(endpoint));
    unsigned hits = 0;
    SedsLocalEndpointDesc handler = {
        .endpoint = endpoint,
        .packet_handler = packet_count,
        .packed_handler = NULL,
        .user = &hits,
    };
    SedsRouter *router = seds_router_new(Seds_RM_Sink, NULL, NULL, &handler, 1);
    assert(router != NULL);
    assert(seds_endpoint_exists(endpoint));
    SedsEndpointInfo info = {0};
    assert(seds_endpoint_get_info(endpoint, &info) == SEDS_OK);
    assert(info.exists && info.name_len == strlen("ENDPOINT_9249"));
    assert(strncmp(info.name, "ENDPOINT_9249", info.name_len) == 0);
    assert(seds_endpoint_get_info_by_name("ENDPOINT_9249", strlen("ENDPOINT_9249"), &info) == SEDS_OK);
    assert(info.exists && info.id == endpoint);
    seds_router_free(router);
    assert(seds_endpoint_remove(endpoint) == SEDS_OK);
}

static void test_managed_network_variables(void) {
    SedsRouter *router = seds_router_new(Seds_RM_Sink, NULL, NULL, NULL, 0);
    assert(router != NULL);
    assert(seds_router_enable_network_variable(router, (SedsDataType)g_gps_ty, true, false) == SEDS_OK);

    uint32_t endpoints[] = {g_radio_ep};
    const float gps[3] = {7.0f, 8.0f, 9.0f};
    SedsPacketView pkt = {
        .ty = g_gps_ty,
        .data_size = sizeof(gps),
        .sender = "SRC",
        .sender_len = 3,
        .endpoints = endpoints,
        .num_endpoints = 1,
        .timestamp = 55,
        .payload = (const uint8_t *)gps,
        .payload_len = sizeof(gps),
    };
    uint8_t packed[1024];
    const int32_t packed_len = seds_pkt_pack(&pkt, packed, sizeof(packed));
    assert(packed_len > 0);
    assert(seds_router_set_network_variable_packed(router, packed, (size_t)packed_len) == SEDS_PERMISSION_DENIED);
    assert(seds_router_seed_managed_variable_packed(router, packed, (size_t)packed_len) == SEDS_OK);
    assert(seds_router_cached_managed_variable_packed_len(router, (SedsDataType)g_gps_ty) == packed_len);
    uint8_t copied[1024];
    assert(seds_router_cached_managed_variable_packed(router, (SedsDataType)g_gps_ty,
                                                     copied, sizeof(copied)) == packed_len);
    SedsOwnedPacket *cached = seds_pkt_unpack_owned(copied, (size_t)packed_len);
    assert(cached != NULL);
    SedsPacketView cached_view = {0};
    assert(seds_owned_pkt_view(cached, &cached_view) == SEDS_OK);
    assert(cached_view.ty == g_gps_ty);
    assert(cached_view.payload_len == sizeof(gps));
    seds_owned_pkt_free(cached);
    assert(seds_router_get_network_variable_packed(router, (SedsDataType)g_gps_ty, 0,
                                                   copied, sizeof(copied)) == packed_len);

    assert(seds_router_enable_network_variable(router, (SedsDataType)g_gps_ty, true, true) == SEDS_OK);
    unsigned updates = 0;
    assert(seds_router_on_network_variable_update(router, (SedsDataType)g_gps_ty,
                                                  managed_update_count, &updates) == SEDS_OK);
    assert(seds_router_set_network_variable_packed(router, packed, (size_t)packed_len) == SEDS_OK);
    assert(updates == 1u);

    Capture tx = {0};
    const int32_t side = seds_router_add_side_packed(router, "BUS", 3, capture_tx, &tx, false);
    assert(side >= 0);
    assert(seds_router_request_managed_variable(router, (SedsDataType)g_gps_ty) == SEDS_OK);
    assert(seds_router_process_all_queues(router) == SEDS_OK);
    assert(tx.hits >= 1u);

    SedsRouter *requester = seds_router_new(Seds_RM_Sink, NULL, NULL, NULL, 0);
    assert(requester != NULL);
    Capture reply = {0};
    const int32_t request_side = seds_router_add_side_packed(router, "REQ", 3, capture_tx, &reply, false);
    assert(request_side >= 0);
    const int32_t requester_side = seds_router_add_side_packed(requester, "OWN", 3, capture_tx, &tx, false);
    assert(requester_side >= 0);
    assert(seds_router_enable_network_variable(requester, (SedsDataType)g_gps_ty, true, false) == SEDS_OK);
    assert(seds_router_get_network_variable_packed_len(requester, (SedsDataType)g_gps_ty, 0) == 0);
    assert(seds_router_process_all_queues(requester) == SEDS_OK);
    assert(tx.hits >= 2u);
    assert(seds_router_receive_packed_from_side(router, (uint32_t)request_side, tx.last, tx.last_len) == SEDS_OK);
    assert(seds_router_process_all_queues(router) == SEDS_OK);
    assert(reply.hits >= 1u);

    seds_router_free(requester);
    seds_router_free(router);
}

static void test_p2p_datagram_and_stream_api(void) {
    Capture a_tx = {0};
    Capture b_tx = {0};
    P2pCapture b_datagram = {0};
    P2pStreamCapture a_stream = {0};
    P2pStreamCapture b_stream = {0};

    SedsRouter *a = seds_router_new(Seds_RM_Sink, NULL, NULL, NULL, 0);
    SedsRouter *b = seds_router_new(Seds_RM_Sink, NULL, NULL, NULL, 0);
    assert(a != NULL && b != NULL);
    assert(seds_router_set_sender_id(a, "client-node", strlen("client-node")) == SEDS_OK);
    assert(seds_router_set_sender_id(b, "server-node", strlen("server-node")) == SEDS_OK);
    const int32_t a_side = seds_router_add_side_packed(a, "to-b", 4, capture_tx, &a_tx, false);
    const int32_t b_side = seds_router_add_side_packed(b, "to-a", 4, capture_tx, &b_tx, false);
    assert(a_side >= 0 && b_side >= 0);

    uint32_t b_address = 0;
    assert(seds_router_current_address(b, &b_address) == SEDS_OK);
    assert(b_address != 0);
    assert(seds_router_bind_p2p_port(b, 80, p2p_capture, &b_datagram) == SEDS_OK);

    /* Teach A about B using a normal P2P packet from B. */
    const uint8_t hello[] = "self-advertise";
    assert(seds_router_send_p2p_to_address(b, b_address, 1, 2, hello, sizeof(hello) - 1) == SEDS_OK);
    assert(seds_router_process_tx_queue(b) == SEDS_OK);
    assert(b_tx.hits == 1);
    assert(seds_router_receive_packed(a, b_tx.last, b_tx.last_len) == SEDS_OK);

    uint32_t resolved_b = 0;
    assert(seds_router_resolve_hostname_address(a, "server-node", strlen("server-node"), &resolved_b) == SEDS_OK);
    assert(resolved_b == b_address);

    const uint8_t get[] = "GET /status HTTP/1.1\r\n\r\n";
    assert(seds_router_send_p2p_to_hostname(a, "server-node", strlen("server-node"), 80, 49152,
                                            get, sizeof(get) - 1) == SEDS_OK);
    assert(seds_router_process_tx_queue(a) == SEDS_OK);
    assert(seds_router_receive_packed(b, a_tx.last, a_tx.last_len) == SEDS_OK);
    assert(b_datagram.hits == 1);
    assert(b_datagram.source_port == 49152);
    assert(b_datagram.destination_port == 80);
    assert(b_datagram.payload_len == sizeof(get) - 1);
    assert(memcmp(b_datagram.payload, get, sizeof(get) - 1) == 0);

    assert(seds_router_bind_p2p_stream_port(a, 49200, p2p_stream_capture, &a_stream) == SEDS_OK);
    assert(seds_router_bind_p2p_stream_port(b, 8080, p2p_stream_capture, &b_stream) == SEDS_OK);
    uint32_t client_stream = 0;
    assert(seds_router_open_p2p_stream_to_hostname(a, "server-node", strlen("server-node"), 8080, 49200,
                                                   &client_stream) == SEDS_OK);
    assert(client_stream != 0);
    assert(seds_router_process_tx_queue(a) == SEDS_OK);
    assert(seds_router_receive_packed(b, a_tx.last, a_tx.last_len) == SEDS_OK);
    assert(b_stream.accepted == 1);
    assert(b_stream.stream_id != 0);
    assert(seds_router_process_tx_queue(b) == SEDS_OK);
    assert(seds_router_receive_packed(a, b_tx.last, b_tx.last_len) == SEDS_OK);
    assert(a_stream.connected == 1);

    const uint8_t stream_payload[] = "GET /stream HTTP/1.1\r\n\r\n";
    assert(seds_router_send_p2p_stream(a, client_stream, stream_payload, sizeof(stream_payload) - 1) == SEDS_OK);
    assert(seds_router_process_tx_queue(a) == SEDS_OK);
    assert(seds_router_receive_packed(b, a_tx.last, a_tx.last_len) == SEDS_OK);
    assert(b_stream.data == 1);
    assert(b_stream.payload_len == sizeof(stream_payload) - 1);
    assert(memcmp(b_stream.payload, stream_payload, sizeof(stream_payload) - 1) == 0);

    assert(seds_router_close_p2p_stream(a, client_stream) == SEDS_OK);
    assert(seds_router_process_tx_queue(a) == SEDS_OK);
    assert(seds_router_receive_packed(b, a_tx.last, a_tx.last_len) == SEDS_OK);
    assert(b_stream.closed == 1);

    seds_router_free(a);
    seds_router_free(b);
}

static void test_crypto_api_surface(void) {
#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
    CryptoState state = {0};
    const uint8_t key[] = "software key material for parity";
    const uint8_t nonce[] = {9};
    const uint8_t aad[] = {8};
    const uint8_t plaintext[] = {4, 5, 6};
    uint8_t ciphertext[8] = {0};
    uint8_t opened[8] = {0};
    uint8_t tag[32] = {0};
    size_t ciphertext_len = 0;
    size_t tag_len = 0;
    size_t opened_len = 0;
    assert(seds_crypto_register_provider(crypto_seal, crypto_open, &state) == SEDS_OK);
    assert(seds_crypto_register_software_key(12u, key, sizeof(key)) == SEDS_OK);
    assert(seds_crypto_seal(12u, nonce, sizeof(nonce), aad, sizeof(aad),
                            plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext),
                            &ciphertext_len, tag, sizeof(tag), &tag_len) == SEDS_OK);
    assert(ciphertext_len == sizeof(plaintext));
    assert(tag_len == 1u && tag[0] == 7u);
    assert(seds_crypto_open(12u, nonce, sizeof(nonce), aad, sizeof(aad),
                            ciphertext, ciphertext_len, tag, tag_len,
                            opened, sizeof(opened), &opened_len) == SEDS_OK);
    assert(opened_len == sizeof(plaintext));
    assert(memcmp(opened, plaintext, sizeof(plaintext)) == 0);
    assert(state.seals == 1 && state.opens == 1);
    seds_crypto_clear_provider();

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(opened, 0, sizeof(opened));
    memset(tag, 0, sizeof(tag));
    ciphertext_len = 0;
    tag_len = 0;
    opened_len = 0;
    assert(seds_crypto_register_software_key(77u, key, sizeof(key) - 1) == SEDS_OK);
    assert(seds_crypto_seal(77u, nonce, sizeof(nonce), aad, sizeof(aad),
                            plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext),
                            &ciphertext_len, tag, sizeof(tag), &tag_len) == SEDS_OK);
    assert(ciphertext_len == sizeof(plaintext));
    assert(tag_len == 16u);
    assert(memcmp(ciphertext, plaintext, sizeof(plaintext)) != 0);
    assert(seds_crypto_open(77u, nonce, sizeof(nonce), aad, sizeof(aad),
                            ciphertext, ciphertext_len, tag, tag_len,
                            opened, sizeof(opened), &opened_len) == SEDS_OK);
    assert(opened_len == sizeof(plaintext));
    assert(memcmp(opened, plaintext, sizeof(plaintext)) == 0);
    tag[0] ^= 0x40u;
    assert(seds_crypto_open(77u, nonce, sizeof(nonce), aad, sizeof(aad),
                            ciphertext, ciphertext_len, tag, tag_len,
                            opened, sizeof(opened), &opened_len) == SEDS_HANDLER_ERROR);
    tag[0] ^= 0x40u;

    uint8_t credential[80] = {0};
    size_t credential_len = 0;
    SedsManagedCredentialInfo info = {0};
    const uint8_t root_key[] = "root credential key material for parity";
    assert(seds_crypto_issue_managed_credential(root_key, sizeof(root_key) - 1,
                                                0x1122334455667788ull, 99u, 7u,
                                                1000u, 5000u, 0x55aau,
                                                credential, sizeof(credential),
                                                &credential_len) == SEDS_OK);
    assert(credential_len == sizeof(credential));
    assert(seds_crypto_verify_managed_credential(root_key, sizeof(root_key) - 1,
                                                 credential, credential_len, 2500u,
                                                 &info) == SEDS_OK);
    assert(info.subject_id == 0x1122334455667788ull);
    assert(info.key_id == 99u);
    assert(info.epoch == 7u);
    assert(info.not_before_ms == 1000u);
    assert(info.not_after_ms == 5000u);
    assert(info.permissions == 0x55aau);
    credential[20] ^= 1u;
    assert(seds_crypto_verify_managed_credential(root_key, sizeof(root_key) - 1,
                                                 credential, credential_len, 2500u,
                                                 &info) == SEDS_HANDLER_ERROR);
    credential[20] ^= 1u;
    assert(seds_crypto_verify_managed_credential(root_key, sizeof(root_key) - 1,
                                                 credential, credential_len, 5001u,
                                                 &info) == SEDS_HANDLER_ERROR);
    seds_crypto_clear_software_keys();
#endif
}

int main(void) {
    init_schema_refs();
    test_name_and_metadata_helpers();
    test_packed_aliases_and_lifecycle();
    test_relay_packed_aliases();
    test_runtime_schema_mutation();
    test_runtime_stats_and_memory_layout_exports();
    test_runtime_tuning_and_memory_config();
    test_handler_registration_creates_missing_endpoint();
    test_managed_network_variables();
    test_p2p_datagram_and_stream_api();
    test_crypto_api_surface();
    printf("upstream api parity ok\n");
    return 0;
}
