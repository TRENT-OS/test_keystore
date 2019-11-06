/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file keyStoreMultiInstanceTests.h
 *
 * @brief   collection of tests that test interaction between 
 *          multiple KeyStore instances
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosKeyStoreCtx.h"
#include "SeosCryptoCtx.h"

/**
 * @weakgroup KeyStore_MultiInstance_test_cases
 * @{
 *
 * @brief               Test scenario for the key store which performs tests for the 
 *                      interaction between 2 instances of the keystore by copying a 
 *                      key from the source keystore into the destination keystore
 *
 * @param srcKeyStore   handle to the source keyStore, it can represent a local 
 *                      instance of the key store library, or a handle to the 
 *                      context which is created in a separate camkes component
 * 
 * @param dstKeyStore   handle to the destination keyStore, it can represent a local
 *                      instance of the key store library, or a handle to the context 
 *                      which is created in a separate camkes component
 * 
 * @param cryptoCtx     handle to the crypto library, it can represent a local instance
 *                      of the library, or a handle to the context which is created in a
 *                      separate camkes component
 *
 * @return              true => test scenario passed
 *                      false => test scenario failed
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
bool keyStoreCopyKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, SeosCryptoCtx* cryptoCtx);
/**
 * @weakgroup KeyStore_MultiInstance_test_cases
 * @{
 *
 * @brief               Test scenario for the key store which performs tests for the 
 *                      interaction between 2 instances of the keystore by moving a 
 *                      key from the source keystore into the destination keystore
 *
 * @param srcKeyStore   handle to the source keyStore, it can represent a local 
 *                      instance of the key store library, or a handle to the 
 *                      context which is created in a separate camkes component
 * 
 * @param dstKeyStore   handle to the destination keyStore, it can represent a local
 *                      instance of the key store library, or a handle to the context 
 *                      which is created in a separate camkes component
 * 
 * @param cryptoCtx     handle to the crypto library, it can represent a local instance
 *                      of the library, or a handle to the context which is created in a
 *                      separate camkes component
 *
 * @return              true => test scenario passed
 *                      false => test scenario failed
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
bool keyStoreMoveKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, SeosCryptoCtx* cryptoCtx);

///@}

