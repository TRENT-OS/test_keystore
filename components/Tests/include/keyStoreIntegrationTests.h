/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file keyStoreIntegrationTests.h
 *
 * @brief collection of integration tests for the KeyStore
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Keystore.h"
#include "OS_Crypto.h"

#include <stdbool.h>

/**
 * @weakgroup KeyStore_AES_test_cases
 * @{
 *
 * @brief               Test scenario which performs integration tests for the
 *                      interaction between the keystore and the crypto api on the
 *                      example of a simple AES use case
 *
 * @param hKeystore     handle to the keyStore, it can represent a local instance
 *                      of the key store library, or a handle to the context which
 *                      is created in a separate camkes component
 *
 * @param hCrypto       handle to the crypto library, it can represent a local instance
 *                      of the library, or a handle to the context which is created in a
 *                      separate camkes component
 *
 *
 * @test \b TestKeyStore_testCase_04    Generate a key from the crypto api (InitKey + GenerateKey) and
 *                                      encrypt an example string with the generated key
 *
 * @test \b TestKeyStore_testCase_05    Export the key from the crypto api and import it into the keystore
 *                                      after which remove the key from the crypto api
 *
 * @test \b TestKeyStore_testCase_06    Get the key from the keystore and import it into the crypto api
 *                                      (InitKey + ImportKey)
 *
 * @test \b TestKeyStore_testCase_07    Decrypt the previously encrypted string with the fetched key and check
 *                                      if the decrypted buffer is the same as the initial one
 *
 * @test \b TestKeyStore_testCase_08    Wipe the keystore and test that the key is deleted
 *
 * @}
 *
 */
void testKeyStoreAES(
    OS_Keystore_Handle_t hKeystore,
    OS_Crypto_Handle_t   hCrypto);
/**
 * @weakgroup KeyStore_KeyPair_test_cases
 * @{
 *
 * @brief               Test scenario which performs integration tests for the
 *                      interaction between the keystore and the crypto api on the
 *                      example of an RSA and Diffie-Hellman key-pair generation
 *
 * @param hKeystore     handle to the keyStore, it can represent a local instance
 *                      of the key store library, or a handle to the context which
 *                      is created in a separate camkes component
 *
 * @param hCrypto       handle to the crypto library, it can represent a local instance
 *                      of the library, or a handle to the context which is created in a
 *                      separate camkes component
 *
 *
 *
 * @test \b TestKeyStore_testCase_09    Generate a key-pair from the crypto api (InitKey + GenerateKeyPair)
 *
 * @test \b TestKeyStore_testCase_10    Export both keys from the crypto api and import them into the keystore
 *
 * @test \b TestKeyStore_testCase_11    Delete both keys from the keystore and test that the keys are actually
 *                                      deleted by trying to fetch them
 *
 * @}
 *
 */
void testKeyStoreKeyPair(
    OS_Keystore_Handle_t hKeystore,
    OS_Crypto_Handle_t   hCrypto);

///@}

