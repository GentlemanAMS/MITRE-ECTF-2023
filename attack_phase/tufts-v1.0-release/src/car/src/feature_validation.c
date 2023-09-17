#include <stdbool.h>
#include <stdint.h>

#include "aes.h"
#include "sha256.h"

#include "feature_validation.h"
#include "secrets.h"

const char *feature_key = CAR_SECRET;

struct validate_result validate_feature(uint8_t feature[FEATURE_PACKAGE_LEN])
{
    struct AES_ctx aes_ctx;
    SHA256_CTX sha_ctx;
    volatile struct validate_result result;
    uint8_t hash[32];

    /** Decrypt package **/
    AES_init_ctx(&aes_ctx, feature_key);
    // Modify feature buffer in place
    AES_ECB_decrypt(&aes_ctx, feature);

    /** Read feature number **/
    // Last byte is feature number
    result.feat_num = feature[FEATURE_PACKAGE_LEN - 1];

    /** Calculate correct hash **/
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, &(result.feat_num), 1);
    sha256_final(&sha_ctx, hash);

    /** Validate hash **/
    result.valid = true;
    for (unsigned i = 0; i < (FEATURE_PACKAGE_LEN - 1); i++) {
        result.valid &= (hash[i] == feature[i]);
    }

    return result;
}