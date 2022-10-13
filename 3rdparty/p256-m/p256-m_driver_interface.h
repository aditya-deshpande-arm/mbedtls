#ifndef P256M_DRIVER_INTERFACE_H
#define P256M_DRIVER_INTERFACE_H

#include "psa/crypto_types.h"

/** Convert an internal p256-m error code to a PSA error code
 *
 * \param ret           An error code thrown by p256-m
 *
 * \return              The corresponding PSA error code
 */
psa_status_t p256m_to_psa_error( int ret );


/** Generate SECP256R1 ECC Key Pair. 
 *  Interface function which calls the p256-m key generation function and
 *  places it in the key buffer provided by the caller (mbed TLS) in the
 *  correct format. For a SECP256R1 curve this is the 32 bit private key.
 *
 * \param[out]  key_buffer          The buffer to contain the key data in
 *                                  output format upon successful return.
 * \param[in]   key_buffer_size     Size of the \p key_buffer buffer in bytes.
 * \param[out]  key_buffer_length   The length of the data written in \p
 *                                  key_buffer in bytes.
 *
 * \retval  #PSA_SUCCESS
 *          Success. Keypair generated and stored in buffer.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_GENERIC_ERROR
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t p256m_generate_key(
    uint8_t *key_buffer, 
    size_t key_buffer_size, 
    size_t *key_buffer_length );

/** Perform raw key agreement using p256-m's ECDH implementation
 *
 * \param[in]  key_buffer           The buffer containing the private key
 *                                  in the format specified by PSA.
 * \param[in]  key_buffer_size      Size of the \p key_buffer buffer in bytes.

 * \param[in]  peer_key             The buffer containing the peer's public
 *                                  key in format specified by PSA. 
 * \param[in]  peer_key_length      Size of the \p peer_key buffer in 
 *                                  bytes.
 * \param[out] shared_secret        The buffer to which the shared secret
 *                                  is to be written.
 * \param[in]  shared_secret_size   Size of the \p shared_secret buffer in
 *                                  bytes.
 * \param[out] shared_secret_length On success, the number of bytes that
 *                                  make up the returned shared secret.
 * \retval #PSA_SUCCESS
 *         Success. Shared secret successfully calculated.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 */
psa_status_t p256m_ecdh(
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length );

/** Sign an already-calculated hash with a private key using p256-m's ECDSA
 *  implementation
 *
 * \param[in]  key_buffer           The buffer containing the private key
 *                                  in the format specified by PSA.
 * \param[in]  key_buffer_size      Size of the \p key_buffer buffer in bytes.
 * \param[in]  hash                 The hash to sign.
 * \param[in]  hash_length          Size of the \p hash buffer in bytes.
 * \param[out] signature            Buffer where the signature is to be written.
 * \param[in]  signature_size       Size of the \p signature buffer in bytes.
 * \param[out] signature_length     On success, the number of bytes
 *                                  that make up the returned signature value.
 *
 * \retval #PSA_SUCCESS
 *          Success. Hash was signed successfully.
 *         respectively of the key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 */
psa_status_t p256m_sign_hash(
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length );

/** Verify the signature of a hash using a SECP256R1 public key using p256-m's
 *  ECDSA implementation.
 *
 * \note p256-m expects a 64 byte public key, but the contents of the key
         buffer may be the 32 byte keypair representation or the 65 byte
         public key representation. As a result, this function calls
         psa_driver_wrapper_export_public_key() to ensure the public key
         can be passed to p256-m.
 *
 * \param[in]  key_buffer       The buffer containing the key
 *                              in the format specified by PSA.
 * \param[in]  key_buffer_size  Size of the \p key_buffer buffer in bytes.
 * \param[in]  hash             The hash whose signature is to be
 *                              verified.
 * \param[in]  hash_length      Size of the \p hash buffer in bytes.
 * \param[in]  signature        Buffer containing the signature to verify.
 * \param[in]  signature_length Size of the \p signature buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The signature is valid.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The calculation was performed successfully, but the passed
 *         signature is not a valid signature.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 */
psa_status_t p256m_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length );


#endif /* P256M_DRIVER_INTERFACE_H */