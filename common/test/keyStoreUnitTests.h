/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file keyStoreUnitTests.h
 *
 * @brief collection of unit tests for the KeyStore
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosKeyStoreCtx.h"

/**
 * @weakgroup KeyStore_UnitTest_test_cases
 * @{
 *
 * @brief               Test scenario for the key store which performs unit tests
 *                      (positive/negative cases) for the most basic operations of
 *                      the keystore
 *
 * @param keyStoreCtx   handle to the keyStore, it can represent a local instance
 *                      of the key store library, or a handle to the context which
 *                      is created in a separate camkes component
 *
 * @return              true => test scenario passed
 *                      false => test scenario failed
 *
 * 
 * @test \b TestKeyStore_testCase_01    \n <b> 1) Positive cases: </b>
 *                                      \n          Import a key with dummy key data into the keystore
 *                                      \n <b> 2) Negative cases (check for proper error codes): </b>
 *                                      \n          Try to import a key with a too long name
 *                                      \n          Try to import a key with an empty name
 *                                      \n          Try to import a key with a name that already exists
 *                                      \n          Try to import a too large key
 *                                      \n          Try to import an empty key
 *                                      \n          Try to import a key with name = NULL
 *                                      \n          Try to import a key with data = NULL
 *
 * @test \b TestKeyStore_testCase_02    \n <b> 1) Positive cases: </b>
 *                                      \n          Retreive an existing key from the keystore and verify 
 *                                                  that the retrieved data corresponds to the dummy data 
 *                                                  imported in the keystore
 *                                      \n <b> 2) Negative cases (check for proper error codes): </b>
 *                                      \n          Try to retreive a key while setting the expected keysize to 0
 *                                      \n          Try to retreive a key that doesn't exist
 *                                      \n          Try to import a key with an empty name
 *                                      \n          Try to import a key with a too long name
 *                                      \n          Try to import a key with data buffer = NULL
 *                                      \n          Try to import a key with keysize = NULL
 *                                      \n          Try to import a key with name = NULL
 *
 * @test \b TestKeyStore_testCase_01    \n <b> 1) Positive cases: </b>
 *                                      \n          Delete an existing key from the keystore
 *                                      \n <b> 2) Negative cases (check for proper error codes): </b>
 *                                      \n          Try to delete a key that doesn't exist
 *                                      \n          Try to delete a key with a too long name
 *                                      \n          Try to delete a key with an empty name
 *                                      \n          Try to import a key with name = NULL
 *
 * @}
 *
 */
bool keyStoreUnitTests(SeosKeyStoreCtx* keyStoreCtx);

///@}

