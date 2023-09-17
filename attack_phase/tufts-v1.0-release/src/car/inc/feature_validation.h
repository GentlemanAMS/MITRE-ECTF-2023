#ifndef FEAT_VALIDATE_H
#define FEAT_VALIDATE_H

#include <stdint.h>
#include <stdbool.h>

/* Struct containing feature validation result */
struct validate_result {
    uint8_t feat_num;
    bool valid;
};

#define FEATURE_PACKAGE_LEN 16

/*
 * Validate a feature package.
 * Arguments:
 *     feature: Pointer to 16-byte feature message (will be modified)
 * Returns:
 *     The feature number and whether the feature was valid
 */
struct validate_result validate_feature(uint8_t feature[FEATURE_PACKAGE_LEN]);

#endif