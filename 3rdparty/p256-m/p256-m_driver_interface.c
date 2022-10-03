// #include <bits/stdint-uintn.h>
// #include <stdio.h>
#include "mbedtls/platform.h"
#include "p256-m_driver_interface.h"
#include "p256-m/p256-m.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
//#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"

psa_status_t p256m_to_psa_error( int ret )
{
    switch( ret )
    {
        case P256_SUCCESS:
            return( PSA_SUCCESS );
        case P256_INVALID_PUBKEY:
        case P256_INVALID_PRIVKEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case P256_INVALID_SIGNATURE:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case P256_RANDOM_FAILED:
        default:
            return( PSA_ERROR_GENERIC_ERROR );
    }
}

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
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
    if( key_buffer_size != 32 || signature_size != 64)
        return( status );

    status = p256m_to_psa_error(
        p256_ecdsa_sign(signature, key_buffer, hash, hash_length)
    );
    if( status == PSA_SUCCESS )
        *signature_length = 64;
    
    return status;
}

psa_status_t p256m_verify_hash_with_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length )
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
    if( key_buffer_size != 65 || signature_length != 64 || *key_buffer != 0x04 )
        return status;
        
    const uint8_t *public_key_buffer = key_buffer + 1;
    status = p256m_to_psa_error(
        p256_ecdsa_verify( signature, public_key_buffer, hash, hash_length)
    );

    return status;
}

psa_status_t p256m_verify_hash_with_key_pair(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length )
{
    psa_status_t status;
    uint8_t *public_key_buffer = NULL;
    size_t public_key_buffer_size = 65;
    public_key_buffer = mbedtls_calloc( 1, public_key_buffer_size);
    if( public_key_buffer == NULL)
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    size_t *public_key_length = NULL;
    public_key_length = mbedtls_calloc( 1, sizeof(size_t) );
    if( public_key_length == NULL)
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    *public_key_length = 65;

    status = mbedtls_to_psa_error(
                mbedtls_psa_ecp_export_public_key(
                        attributes,
                        key_buffer,
                        key_buffer_size,
                        public_key_buffer,
                        public_key_buffer_size,
                        public_key_length) );
    if( status != PSA_SUCCESS )
        goto exit;

    status = p256m_verify_hash_with_public_key(
                attributes,
                public_key_buffer,
                public_key_buffer_size,
                alg,
                hash,
                hash_length,
                signature,
                signature_length );

exit:
    free( public_key_buffer );
    free( public_key_length );
    return ( status );
}
