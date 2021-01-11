/**
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 */

#include "OS_Keystore.h"
#include "OS_Crypto.h"
#include "OS_FileSystem.h"

#include "LibDebug/Debug.h"
#include "LibMacros/Test.h"

#include "keyStoreIntegrationTests.h"
#include "keyStoreMultiInstanceTests.h"
#include "keyStoreUnitTests.h"

#include <string.h>

#include <camkes.h>

static OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
};
static OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_USE_STORAGE_MAX,
    .storage = IF_OS_STORAGE_ASSIGN(
        storage_rpc,
        storage_dp),
};

int run(
    void)
{
    TEST_START();

    OS_FileSystem_Handle_t hFs;
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystore1, hKeystore2;
    OS_Error_t err = OS_ERROR_GENERIC;

    // Init FS and Crypto
    err = OS_FileSystem_init(&hFs, &cfgFs);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_FileSystem_format(hFs);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_FileSystem_mount(hFs);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Crypto_init(&hCrypto, &cfgCrypto);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Create two keystores
    err = OS_Keystore_init(
              &hKeystore1,
              hFs,
              hCrypto,
              "keystore1");
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_init(
              &hKeystore2,
              hFs,
              hCrypto,
              "keystore2");
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    keyStoreUnitTests(hKeystore1);
    testKeyStoreAES(hKeystore1, hCrypto);
    testKeyStoreKeyPair(hKeystore1, hCrypto);
    keyStoreCopyKeyTest(hKeystore1, hKeystore2, hCrypto);
    keyStoreMoveKeyTest(hKeystore1, hKeystore2, hCrypto);

    // Cleanup
    OS_Keystore_free(hKeystore1);
    OS_Crypto_free(hCrypto);
    OS_FileSystem_unmount(hFs);
    OS_FileSystem_free(hFs);

    TEST_FINISH();

    return 0;
}
