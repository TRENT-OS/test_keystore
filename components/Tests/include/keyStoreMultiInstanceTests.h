/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file keyStoreMultiInstanceTests.h
 *
 * @brief   collection of tests that test interaction between
 *          multiple KeyStore instances
 *
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Keystore.h"
#include "OS_Crypto.h"

#include <stdbool.h>

/**
 * @weakgroup KeyStore_MultiInstance_test_cases
 * @{
 *
 * @brief               Test scenario which performs tests for the  interaction
 *                      between 2 instances of the keystore by copying a
 *                      key from the source keystore into the destination keystore
 *
 * @param hSrcKeystore  handle to the source keyStore, it can represent a local
 *                      instance of the key store library, or a handle to the
 *                      context which is created in a separate camkes component
 *
 * @param hDstKeystore  handle to the destination keyStore, it can represent a local
 *                      instance of the key store library, or a handle to the context
 *                      which is created in a separate camkes component
 *
 * @param hCrypto       handle to the crypto library, it can represent a local instance
 *                      of the library, or a handle to the context which is created in a
 *                      separate camkes component
 *
 *
 *
 * @test \b TestKeyStore_testCase_12    Generate a key and import it into the source keystore
 *
 * @test \b TestKeyStore_testCase_13    Verify that there is no key with with the same name in the destination keystore
 *
 * @test \b TestKeyStore_testCase_14    Copy the key into the destination keystore and verify that it is actually there
 *
 * @}
 *
 */
void keyStoreCopyKeyTest(
    OS_Keystore_Handle_t hSrcKeystore, OS_Keystore_Handle_t hDstKeystore, OS_Crypto_Handle_t hCrypto);
/**
 * @weakgroup KeyStore_MultiInstance_test_cases
 * @{
 *
 * @brief               Test scenario which performs tests for the interaction
 *                      between 2 instances of the keystore by moving a
 *                      key from the source keystore into the destination keystore
 *
 * @param hSrcKeystore  handle to the source keyStore, it can represent a local
 *                      instance of the key store library, or a handle to the
 *                      context which is created in a separate camkes component
 *
 * @param hDstKeystore  handle to the destination keyStore, it can represent a local
 *                      instance of the key store library, or a handle to the context
 *                      which is created in a separate camkes component
 *
 * @param hCrypto       handle to the crypto library, it can represent a local instance
 *                      of the library, or a handle to the context which is created in a
 *                      separate camkes component
 *
 *
 *
 * @test \b TestKeyStore_testCase_15    Generate a key and import it into the source keystore
 *
 * @test \b TestKeyStore_testCase_16    Verify that there is no key with with the same
 *                                      name in the destination keystore
 *
 * @test \b TestKeyStore_testCase_17    Move the key into the destination keystore, verify that
 *                                      it is actually there and verify that it is no longer in
 *                                      the source keystore
 *
 * @}
 *
 */
void keyStoreMoveKeyTest(
    OS_Keystore_Handle_t hSrcKeystore, OS_Keystore_Handle_t hDstKeystore, OS_Crypto_Handle_t hCrypto);

///@}

