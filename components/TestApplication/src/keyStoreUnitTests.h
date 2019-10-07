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
 * 
 * @test \b TestKeyStore_testCase_01    Unit tests for the import function
 *
 * @test \b TestKeyStore_testCase_02    Unit tests for the get function
 *
 * @test \b TestKeyStore_testCase_03    Unit tests for the delete function
 *
 * @}
 *
 */
bool keyStoreUnitTests(SeosKeyStoreCtx* keyStoreCtx);

///@}

