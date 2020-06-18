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

static const ChanMuxClientConfig_t chanMuxNvmDriverConfig = {
    .port  = CHANMUX_DATAPORT_DUPLEX_SHARED_ASSIGN(chanMux_port),
    .wait  = chanMux_event_hasData_wait,
    .write = chanMux_rpc_write,
    .read  = chanMux_rpc_read
};

/* Private function prototypes -----------------------------------------------------------*/
void testRunnerInf_runTests()
{
    OS_Crypto_Config_t cfgLocal =
    {
        .mode = OS_Crypto_MODE_LIBRARY_ONLY,
        .library.entropy = OS_CRYPTO_ASSIGN_EntropySource(entropySource_rpc_read,
                                                          entropySource_dp),
    };
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystore1, hKeystore2;
    ChanMuxNvmDriver chanMuxNvm;
    EncryptedPartitionFileStream encryptedPartitionFileStream1;
    EncryptedPartitionFileStream encryptedPartitionFileStream2;
    OS_Error_t err = OS_ERROR_GENERIC;
    bool ret = false;

    /************************** Init NVM driver *******************************/
    if (!ChanMuxNvmDriver_ctor(&chanMuxNvm, &chanMuxNvmDriverConfig))
    {
        Debug_ASSERT_PRINTFLN(
            false,
            "ChanMuxNvmDriver_ctor() on Proxy channel %d failed",
            NVM_CHANNEL_NUMBER);
    }

    /************************** Init Crypto local version ****************************/
    err = OS_Crypto_init(&hCrypto, &cfgLocal);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Crypto_init failed with error code %d!", err);

    /************************** Init 1. local version of the KeyStore ****************************/
    Debug_LOG_INFO("create EncryptedPartitionFileStream for channel %d, partition ID %d",
                   NVM_CHANNEL_NUMBER, KEY_STORE_SPIFFS_INSTANCE_1_PARTITION);

    ret = EncryptedPartitionFileStream_ctor(
        &encryptedPartitionFileStream1,
        ChanMuxNvmDriver_get_nvm(&chanMuxNvm),
        KEY_STORE_SPIFFS_INSTANCE_1_PARTITION,
        FS_TYPE_SPIFFS);
    Debug_ASSERT_PRINTFLN(ret == true, "keyStoreContext_ctor failed!");

    err = OS_Keystore_init(
        &hKeystore1,
        EncryptedPartitionFileStream_get_FileStreamFactory(
            &encryptedPartitionFileStream1 ),
        hCrypto,
        KEY_STORE_SPIFFS_INSTANCE_1_NAME);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "SeosKeyStore_init failed with error code %d!", err);

    /************************** Init 2. local version of the KeyStore ****************************/
    Debug_LOG_INFO("create EncryptedPartitionFileStream for channel %d, partition ID %d",
                   NVM_CHANNEL_NUMBER, KEY_STORE_SPIFFS_INSTANCE_2_PARTITION);

    ret = EncryptedPartitionFileStream_ctor(
        &encryptedPartitionFileStream2,
        ChanMuxNvmDriver_get_nvm(&chanMuxNvm),
        KEY_STORE_SPIFFS_INSTANCE_2_PARTITION,
        FS_TYPE_SPIFFS);
    Debug_ASSERT_PRINTFLN(ret == true, "keyStoreContext_ctor failed!");

    err = OS_Keystore_init(
        &hKeystore2,
        EncryptedPartitionFileStream_get_FileStreamFactory(
            &encryptedPartitionFileStream2 ),
        hCrypto,
        KEY_STORE_SPIFFS_INSTANCE_2_NAME);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "SeosKeyStore_init failed with error code %d!", err);

    /******************** Test local and remote versions **********************/
    Debug_LOG_INFO("\n\n\n\n**************************** Starting 'TestKeyStoreSPIFFS_scenario_1' ****************************\n");
    if (!keyStoreUnitTests(hKeystore1))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreSPIFFS_scenario_1 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreSPIFFS_scenario_1 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreSPIFFS_scenario_3' ****************************\n");
    if (!testKeyStoreAES(hKeystore1, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreSPIFFS_scenario_3 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreSPIFFS_scenario_3 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreSPIFFS_scenario_5' ****************************\n");
    if (!testKeyStoreKeyPair(hKeystore1, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreSPIFFS_scenario_5 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreSPIFFS_scenario_5 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreSPIFFS_scenario_7' ****************************\n");
    if (!keyStoreCopyKeyTest(hKeystore1, hKeystore2, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreSPIFFS_scenario_7 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreSPIFFS_scenario_7 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreSPIFFS_scenario_9' ****************************\n");
    if (!keyStoreMoveKeyTest(hKeystore1, hKeystore2, hCrypto))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreSPIFFS_scenario_9 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreSPIFFS_scenario_9 succeeded!\n\n\n\n");
    }

    /***************************** Destruction *******************************/
    OS_Crypto_free(hCrypto);
    OS_Keystore_free(hKeystore1);
    EncryptedPartitionFileStream_dtor(&encryptedPartitionFileStream1);
    OS_Keystore_free(hKeystore2);
    EncryptedPartitionFileStream_dtor(&encryptedPartitionFileStream2);
}