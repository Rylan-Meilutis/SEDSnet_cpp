#include "sedsnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_json(const char * label, int32_t len, SedsResult (*fill)(char *, size_t))
{
    if (len <= 0)
    {
        return;
    }
    char * buf = (char *)malloc((size_t)len);
    if (buf == NULL)
    {
        return;
    }
    if (fill(buf, (size_t)len) == SEDS_OK)
    {
        printf("%s: %s\n", label, buf);
    }
    free(buf);
}

static SedsRouter * g_router_for_memory_example;
static SedsRelay * g_relay_for_memory_example;

static SedsResult fill_router_memory(char * buf, size_t len)
{
    return seds_router_export_memory_layout(g_router_for_memory_example, buf, len);
}

static SedsResult fill_relay_memory(char * buf, size_t len)
{
    return seds_relay_export_memory_layout(g_relay_for_memory_example, buf, len);
}

int main(void)
{
    (void)seds_set_runtime_device_identifier("GROUND_STATION", strlen("GROUND_STATION"));

    SedsRuntimeTuningConfig tuning;
    if (seds_get_runtime_tuning_config(&tuning) == SEDS_OK)
    {
        tuning.payload_compress_threshold = 24;
        tuning.static_string_length = 512;
        tuning.static_hex_length = 512;
        tuning.string_precision = 6;
        tuning.max_handler_retries = 4;
        tuning.reliable_retransmit_ms = 300;
        tuning.reliable_max_retries = 10;
        tuning.reliable_max_pending = 96;
        tuning.reliable_max_return_routes = 96;
        tuning.reliable_max_end_to_end_pending = 96;
        tuning.reliable_max_end_to_end_ack_cache = 256;
        (void)seds_set_runtime_tuning_config(&tuning);
    }

    const SedsRuntimeMemoryConfig memory = {
        .max_queue_budget = 65536,
        .max_recent_rx_ids = 256,
        .starting_queue_size = 512,
        .queue_grow_step = 2.0,
    };

    SedsRouter * router = seds_router_new_with_memory(
        Seds_RM_Sink, NULL, NULL, NULL, 0, SEDS_ROUTER_E2E_DISABLED, 0, &memory);
    SedsRelay * relay = seds_relay_new_with_memory(NULL, NULL, &memory);
    if (router == NULL || relay == NULL)
    {
        fprintf(stderr, "failed to create router or relay\n");
        seds_router_free(router);
        seds_relay_free(relay);
        return 1;
    }

    (void)seds_router_set_sender_id(router, "FC26_MAIN", strlen("FC26_MAIN"));
    (void)seds_relay_set_sender_id(relay, "RF_RELAY", strlen("RF_RELAY"));
    (void)seds_router_configure_address(router, 2, 0x10203041u);
    (void)seds_router_configure_timesync(router, true, 1, 10, 5000, 1000, 1000);

    uint32_t address = 0;
    if (seds_router_current_address(router, &address) == SEDS_OK)
    {
        printf("router_address=0x%08x\n", address);
    }

    g_router_for_memory_example = router;
    g_relay_for_memory_example = relay;
    print_json("router_memory", seds_router_export_memory_layout_len(router), fill_router_memory);
    print_json("relay_memory", seds_relay_export_memory_layout_len(relay), fill_relay_memory);

    seds_router_free(router);
    seds_relay_free(relay);
    return 0;
}
