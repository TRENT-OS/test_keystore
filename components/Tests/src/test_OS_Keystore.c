/**
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 */

#include "OS_Keystore.h"
#include "OS_Crypto.h"
#include "OS_FileSystem.h"

#include "LibDebug/Debug.h"

#include "keyStoreIntegrationTests.h"
#include "keyStoreMultiInstanceTests.h"
#include "keyStoreUnitTests.h"

#include <string.h>

#include <camkes.h>

static OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.entropy = OS_CRYPTO_ASSIGN_EntropySource(
        entropySource_rpc_read,
        entropySource_dp),
};
static OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_STORAGE_MAX,
    .storage = OS_FILESYSTEM_ASSIGN_Storage(
        storage_rpc,
        storage_dp),
};

int run(
    void)
{
    OS_FileSystem_Handle_t hFs;
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystore1, hKeystore2;
    OS_Error_t err = OS_ERROR_GENERIC;

    // Init FS and Crypto
    err = OS_FileSystem_init(&hFs, &cfgFs);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_FileSystem_init failed with error code %d!", err);
    err = OS_FileSystem_format(hFs);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_FileSystem_format failed with error code %d!", err);
    err = OS_FileSystem_mount(hFs);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_FileSystem_mount failed with error code %d!", err);
    err = OS_Crypto_init(&hCrypto, &cfgCrypto);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Crypto_init failed with error code %d!", err);

    // Create two keystores
    err = OS_Keystore_init(
              &hKeystore1,
              hFs,
              hCrypto,
              "keystore1");
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_init failed with error code %d!", err);
    err = OS_Keystore_init(
              &hKeystore2,
              hFs,
              hCrypto,
              "keystore2");
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_init failed with error code %d!", err);

    Debug_LOG_INFO("\n\n\n\n**************************** Starting 'TestKeyStore_scenario_1' ****************************\n");
    if (!keyStoreUnitTests(hKeystore1))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_1 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_1 succeeded!\n\n\n\n");
    }
    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_3' ****************************\n");
    if (!testKeyStoreAES(hKeystore1, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_3 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_3 succeeded!\n\n\n\n");
    }
    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_5' ****************************\n");
    if (!testKeyStoreKeyPair(hKeystore1, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_5 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_5 succeeded!\n\n\n\n");
    }
    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_7' ****************************\n");
    if (!keyStoreCopyKeyTest(hKeystore1, hKeystore2, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_7 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_7 succeeded!\n\n\n\n");
    }
    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_9' ****************************\n");
    if (!keyStoreMoveKeyTest(hKeystore1, hKeystore2, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_9 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_9 succeeded!\n\n\n\n");
    }

    // Cleanup
    OS_Keystore_free(hKeystore1);
    OS_Crypto_free(hCrypto);
    OS_FileSystem_unmount(hFs);
    OS_FileSystem_free(hFs);

    return 0;
}