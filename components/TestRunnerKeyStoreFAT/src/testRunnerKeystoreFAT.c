/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"

#include "OS_Keystore.h"
#include "OS_Crypto.h"

#include "EncryptedPartitionFileStream.h"
#include "ChanMuxNvmDriver.h"

#include "keyStoreUnitTests.h"
#include "keyStoreIntegrationTests.h"
#include "keyStoreMultiInstanceTests.h"

#include <camkes.h>
#include <string.h>

static int entropyFunc(
    void* ctx, unsigned char* buf, size_t len);

void testRunnerInf_runTests()
{
    OS_Crypto_Config_t cfgLocal =
    {
        .mode = OS_Crypto_MODE_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.lib.rng = {
            .entropy = entropyFunc,
            .context = NULL
        }
    };
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystore1, hKeystore2;
    ChanMuxNvmDriver chanMuxNvm;
    EncryptedPartitionFileStream encryptedPartitionFileStream1;
    EncryptedPartitionFileStream encryptedPartitionFileStream2;
    seos_err_t err = SEOS_ERROR_GENERIC;
    bool ret = false;

    /************************** Init NVM driver *******************************/
    if (!ChanMuxNvmDriver_ctor(
            &chanMuxNvm,
            NVM_CHANNEL_NUMBER,
            chanMuxDataPort))
    {
        Debug_ASSERT_PRINTFLN(
            false,
            "ChanMuxNvmDriver_ctor() on Proxy channel %d failed",
            NVM_CHANNEL_NUMBER);
    }

    /************************** Init Crypto local version ****************************/
    err = OS_Crypto_init(&hCrypto, &cfgLocal);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_Crypto_init() failed with error code %d!", err);

    /************************** Init 1. local version of the KeyStore ****************************/

    Debug_LOG_INFO("create EncryptedPartitionFileStream for channel %d, partition ID %d",
                   NVM_CHANNEL_NUMBER, KEY_STORE_FAT_INSTANCE_1_PARTITION);

    ret = EncryptedPartitionFileStream_ctor(
        &encryptedPartitionFileStream1,
        ChanMuxNvmDriver_get_nvm(&chanMuxNvm),
        KEY_STORE_FAT_INSTANCE_1_PARTITION,
        FS_TYPE_FAT32);
    Debug_ASSERT_PRINTFLN(ret == true, "EncryptedPartitionFileStream_ctor() failed!");

    err = OS_Keystore_init(&hKeystore1,
                           EncryptedPartitionFileStream_get_FileStreamFactory(
                               &encryptedPartitionFileStream1 ),
                           hCrypto,
                           KEY_STORE_FAT_INSTANCE_1_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "OS_Keystore_init() failed with error code %d!", err);

    /************************** Init 2. local version of the KeyStore ****************************/
    Debug_LOG_INFO("create EncryptedPartitionFileStream for channel %d, partition ID %d",
                   NVM_CHANNEL_NUMBER, KEY_STORE_FAT_INSTANCE_2_PARTITION);

    ret = EncryptedPartitionFileStream_ctor(
        &encryptedPartitionFileStream2,
        ChanMuxNvmDriver_get_nvm(&chanMuxNvm),
        KEY_STORE_FAT_INSTANCE_2_PARTITION,
        FS_TYPE_FAT32);
    Debug_ASSERT_PRINTFLN(ret == true, "EncryptedPartitionFileStream_ctor() failed!");

    err = OS_Keystore_init(
        &hKeystore2,
        EncryptedPartitionFileStream_get_FileStreamFactory(
            &encryptedPartitionFileStream2 ),
        hCrypto,
        KEY_STORE_FAT_INSTANCE_2_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_Keystore_init() failed with error code %d!", err);

    /******************** Test local and remote versions **********************/
    Debug_LOG_INFO("\n\n\n\n**************************** Starting 'TestKeyStoreFAT_scenario_1' ****************************\n");
    if (!keyStoreUnitTests(hKeystore1))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_1 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_1 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_3' ****************************\n");
    if (!testKeyStoreAES(hKeystore1, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_3 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_3 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_5' ****************************\n");
    if (!testKeyStoreKeyPair(hKeystore1, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_5 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_5 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_7' ****************************\n");
    if (!keyStoreCopyKeyTest(hKeystore1, hKeystore2, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_7 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_7 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_9' ****************************\n");
    if (!keyStoreMoveKeyTest(hKeystore1, hKeystore2, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_9 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_9 succeeded!\n\n\n\n");
    }

    /***************************** Destruction *******************************/
    OS_Crypto_free(hCrypto);
    OS_Keystore_free(hKeystore1);
    EncryptedPartitionFileStream_dtor(&encryptedPartitionFileStream1);
    OS_Keystore_free(hKeystore2);
    EncryptedPartitionFileStream_dtor(&encryptedPartitionFileStream2);
}

/* Private functios -----------------------------------------------------------*/
static int entropyFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}
