/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file keyStoreUnitTests.h
 *
 * @brief collection of unit tests for the KeyStore
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Keystore.h"

#include <stdbool.h>

/**
 * @weakgroup KeyStore_UnitTest_test_cases
 * @{
 *
 * @brief               Test scenario which performs unit tests (positive/negative cases)
 *                      for the most basic operations of the keystore
 *
 * @param hKeystore     handle to the keyStore, it can represent a local instance
 *                      of the key store library, or a handle to the context which
 *                      is created in a separate camkes component
 * @}
 *
 */
void keyStoreUnitTests(
    OS_Keystore_Handle_t hKeystore);

///@}

