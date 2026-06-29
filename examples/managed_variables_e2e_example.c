#include "sedsnet_c_wrapper.h"

#include <stdint.h>

static SedsResult radio_tx(const uint8_t * bytes, size_t len, void * user)
{
    (void)bytes;
    (void)len;
    (void)user;
    return SEDS_OK;
}

#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
static SedsResult seal_cb(uint32_t key_id,
                          const uint8_t * nonce,
                          size_t nonce_len,
                          const uint8_t * aad,
                          size_t aad_len,
                          const uint8_t * plaintext,
                          size_t plaintext_len,
                          uint8_t * ciphertext_out,
                          size_t ciphertext_cap,
                          size_t * ciphertext_len_out,
                          uint8_t * tag_out,
                          size_t tag_cap,
                          size_t * tag_len_out,
                          void * user)
{
    (void)key_id;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext_out;
    (void)ciphertext_cap;
    (void)ciphertext_len_out;
    (void)tag_out;
    (void)tag_cap;
    (void)tag_len_out;
    (void)user;
    return SEDS_ERR;
}

static SedsResult open_cb(uint32_t key_id,
                          const uint8_t * nonce,
                          size_t nonce_len,
                          const uint8_t * aad,
                          size_t aad_len,
                          const uint8_t * ciphertext,
                          size_t ciphertext_len,
                          const uint8_t * tag,
                          size_t tag_len,
                          uint8_t * plaintext_out,
                          size_t plaintext_cap,
                          size_t * plaintext_len_out,
                          void * user)
{
    (void)key_id;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)tag_len;
    (void)plaintext_out;
    (void)plaintext_cap;
    (void)plaintext_len_out;
    (void)user;
    return SEDS_ERR;
}
#endif

int main(void)
{
    const uint32_t radio_endpoint = 101;
    const uint32_t flight_state_type = 3100;
    const uint32_t endpoints[] = {radio_endpoint};
    const uint8_t state = 3;

    (void)seds_endpoint_register(radio_endpoint, "RADIO", 5, false);
    (void)seds_dtype_register(flight_state_type,
                              "FLIGHT_STATE",
                              12,
                              true,
                              1,
                              0,
                              0,
                              0,
                              90,
                              endpoints,
                              1);
    (void)seds_dtype_set_e2e_encryption_policy(flight_state_type, SEDS_E2E_REQUIRE_ON);

#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
    (void)seds_crypto_register_provider(seal_cb, open_cb, NULL);
#endif

    SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
    cfg.sender = SEDS_NAME_LITERAL("FLIGHT_COMPUTER");
    cfg.e2e_mode = SEDS_ROUTER_E2E_REQUIRED_ONLY;
    cfg.e2e_key_id = 7;
    if (seds_global_router_init(&cfg) != SEDS_OK)
    {
        return 1;
    }

    (void)seds_global_router_add_packed_small_side(SEDS_NAME_LITERAL("RADIO"), radio_tx, NULL, false, 64);
    (void)seds_global_router_enable_managed_variable(SEDS_TYPE_REF(flight_state_type));
    (void)seds_global_router_log_typed(
        SEDS_TYPE_REF(flight_state_type), &state, 1, sizeof(state), SEDS_EK_UNSIGNED, NULL, 1);
    (void)seds_global_router_request_managed_variable(SEDS_TYPE_REF(flight_state_type));
    (void)seds_global_router_process(0);
    seds_global_router_free();
    return 0;
}
