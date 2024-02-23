/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file keyStoreUnitTests.h
 *
 * @brief collection of unit tests for the KeyStore
 *
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
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

/**
 * Performs unit tests special cases dedicated to the OS_KeystoreRamFV
 * implementation.
 *
 * @param[in]   hKeystore           Handle to the keystore. The precondition
 *                                  that the implementation behind the handle is
 *                                  an OS_KeystoreRamFV must be known and grant
 *                                  by the caller.
 * @param[in]   keyStoreCapacity    Maximum number of keys that the keystore can
 *                                  store.
*/
void keyStoreRamFVUnitTests(
    OS_Keystore_Handle_t hKeystore,
    int keyStoreCapacity);

///@}

