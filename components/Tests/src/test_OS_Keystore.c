/**
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_FileSystem.h"

#include "OS_KeystoreFile.h"
#include "OS_KeystoreRamFV.h"

#include "lib_debug/Debug.h"
#include "lib_macros/Test.h"

#include "keyStoreIntegrationTests.h"
#include "keyStoreMultiInstanceTests.h"
#include "keyStoreUnitTests.h"

#include <string.h>

#include <camkes.h>

#define KEYSTORE_NAME_MAX_LEN   "keystore1_12345"
#define KEYSTORE_NAME_TOO_LARGE "keystore1_123456"


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
        storage_port),
};

int run(
    void)
{
    TEST_START();

    OS_FileSystem_Handle_t hFs;
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystoreFile1;
    OS_Keystore_Handle_t hKeystoreFile2;
#define NUM_ELEMENTS_KEYSTORE_RAM 10
    static char keystoreRam1Buf[
        OS_KeystoreRamFV_SIZE_OF_BUFFER(NUM_ELEMENTS_KEYSTORE_RAM)];
    static char keystoreRam2Buf[
        OS_KeystoreRamFV_SIZE_OF_BUFFER(NUM_ELEMENTS_KEYSTORE_RAM)];
    OS_Keystore_Handle_t hKeystoreRamFV1;
    OS_Keystore_Handle_t hKeystoreRamFV2;

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

    // Test KeystoreFile name too large
    err = OS_KeystoreFile_init(
              &hKeystoreFile1,
              hFs,
              hCrypto,
              KEYSTORE_NAME_TOO_LARGE);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Create 1st KeystoreFile with max len name
    err = OS_KeystoreFile_init(
              &hKeystoreFile1,
              hFs,
              hCrypto,
              KEYSTORE_NAME_MAX_LEN);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Create 2nd KeystoreFile
    err = OS_KeystoreFile_init(
              &hKeystoreFile2,
              hFs,
              hCrypto,
              "keystore2");
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Create 1st KeystoreRamFV
    err = OS_KeystoreRamFV_init(
        &hKeystoreRamFV1,
        keystoreRam1Buf,
        sizeof(keystoreRam1Buf));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Create 2nd KeystoreRamFV
    err = OS_KeystoreRamFV_init(
        &hKeystoreRamFV2,
        keystoreRam2Buf,
        sizeof(keystoreRam2Buf));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    keyStoreUnitTests(hKeystoreFile1);
    keyStoreUnitTests(hKeystoreRamFV1);
    keyStoreRamFVUnitTests(hKeystoreRamFV1,NUM_ELEMENTS_KEYSTORE_RAM);
    testKeyStoreAES(hKeystoreFile1, hCrypto);
    testKeyStoreAES(hKeystoreRamFV1, hCrypto);
    testKeyStoreKeyPair(hKeystoreFile1, hCrypto);
    testKeyStoreKeyPair(hKeystoreRamFV1, hCrypto);
    keyStoreCopyKeyTest(hKeystoreFile1, hKeystoreFile2, hCrypto);
    keyStoreCopyKeyTest(hKeystoreRamFV1, hKeystoreRamFV2, hCrypto);
    keyStoreMoveKeyTest(hKeystoreFile1, hKeystoreFile2, hCrypto);
    keyStoreMoveKeyTest(hKeystoreRamFV1, hKeystoreRamFV2, hCrypto);

    // Cleanup
    OS_Keystore_free(hKeystoreFile1);
    OS_Keystore_free(hKeystoreFile2);
    OS_Keystore_free(hKeystoreRamFV1);
    OS_Keystore_free(hKeystoreRamFV2);
    OS_Crypto_free(hCrypto);
    OS_FileSystem_unmount(hFs);
    OS_FileSystem_free(hFs);

    TEST_FINISH();

    return 0;
}
