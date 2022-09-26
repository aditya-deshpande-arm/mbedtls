#include <stdio.h>
#include "p256-m_driver_interface.h"
#include "p256-m/p256-m.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

psa_status_t p256m_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length )
{
    fprintf( stderr, "\n Key Buffer Size: %zu \n", key_buffer_size );
    fprintf( stderr, "\n Signature Size: %zu \n", signature_size );
    fprintf( stderr, "\n Signature Length: %zu \n", (*signature_length) );

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t p256m_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length )
{
    fprintf( stderr, "\n Key Buffer Size: %zu \n", key_buffer_size );
    fprintf( stderr, "\n Signature Length: %zu \n", (signature_length) );

    return PSA_ERROR_NOT_SUPPORTED;
}