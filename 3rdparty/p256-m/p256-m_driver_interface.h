#ifndef P256M_DRIVER_INTERFACE_H
#define P256M_DRIVER_INTERFACE_H

#include "psa/crypto_types.h"

psa_status_t p256m_to_psa_error( int ret );

psa_status_t p256m_generate_key(
    uint8_t *key_buffer, 
    size_t key_buffer_size, 
    size_t *key_buffer_length );

psa_status_t p256m_ecdh(
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length );

psa_status_t p256m_sign_hash(
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length );

psa_status_t p256m_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length );

psa_status_t p256m_verify_hash_with_public_key(
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length );

#endif /* P256M_DRIVER_INTERFACE_H */