/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file testRunnerKeystoreFAT.c
 *
 * @brief Tests for the keystore based on FAT
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"

#include "SeosKeyStore.h"
#include "SeosKeyStoreClient.h"
#include "SeosCrypto.h"
#include "SeosCryptoClient.h"

#include "KeyStoreInit.h"
#include "keyStoreUnitTests.h"
#include "keyStoreIntegrationTests.h"
#include "keyStoreMultiInstanceTests.h"

#include <camkes.h>
#include <string.h>

/* Defines -------------------------------------------------------------------*/
#define NVM_CHANNEL_NUMBER                  6

#define KEY_STORE_INSTANCE_1_NAME           "KeyStore1"
#define KEY_STORE_INSTANCE_1_PARTITION      0

#define KEY_STORE_INSTANCE_2_NAME           "KeyStore2"
#define KEY_STORE_INSTANCE_2_PARTITION      1



/* Private function prototypes -----------------------------------------------------------*/
static int entropyFunc(void* ctx, unsigned char* buf, size_t len);

/**
 * @weakgroup KeyStore_FAT_test_scenarios
 * @{
 *
 * @brief Test run for the keystore based on top of the FAT filesystem
 *
 * @test \b TestKeyStoreFAT_scenario_1  Perform TestKeyStore_testCase_01 - 03 for a local version of the KeyStore
 *
 * @test \b TestKeyStoreFAT_scenario_2  Perform TestKeyStore_testCase_01 - 03 for a remote version of the KeyStore
 *
 * @test \b TestKeyStoreFAT_scenario_3  Perform TestKeyStore_testCase_04 - 08 for a local version of the KeyStore
 *
 * @test \b TestKeyStoreFAT_scenario_4  Perform TestKeyStore_testCase_04 - 08 for a remote version of the KeyStore
 *
 * @test \b TestKeyStoreFAT_scenario_5  Perform TestKeyStore_testCase_09 - 11 for a local version of the KeyStore,
 *                                      for RSA and DH keypairs
 *
 * @test \b TestKeyStoreFAT_scenario_6  Perform TestKeyStore_testCase_09 - 11 for a remote version of the KeyStore,
 *                                      for RSA and DH keypairs
 * 
 * @test \b TestKeyStoreFAT_scenario_7  Perform TestKeyStore_testCase_12 - 14 for a local source KeyStore and a 
 *                                      local destination KeyStore
 * 
 * @test \b TestKeyStoreFAT_scenario_8  Perform TestKeyStore_testCase_12 - 14 for a local source KeyStore and a 
 *                                      remote destination KeyStore
 * 
 * @test \b TestKeyStoreFAT_scenario_9  Perform TestKeyStore_testCase_15 - 17 for a local source KeyStore and a 
 *                                      local destination KeyStore
 * 
 * @test \b TestKeyStoreFAT_scenario_10 Perform TestKeyStore_testCase_15 - 17 for a local source KeyStore and a 
 *                                      remote destination KeyStore
 *
 * @}
 */
void testRunnerInf_runTests()
{
    const SeosCrypto_Callbacks cb =
    {
        .malloc     = malloc,
        .free       = free,
        .entropy    = entropyFunc
    };
    SeosCrypto localCrypto;
    SeosCryptoClient cryptoClient;
    SeosCryptoCtx* cryptoApiLocal;
    SeosCryptoCtx* cryptoApiRpc;
    SeosCryptoRpc_Handle rpcHandle = NULL;

    SeosKeyStore localKeyStore1;
    SeosKeyStoreCtx* keyStoreApiLocal1;
    KeyStoreContext keyStoreCtx1;

    SeosKeyStore localKeyStore2;
    SeosKeyStoreCtx* keyStoreApiLocal2;
    KeyStoreContext keyStoreCtx2;

    SeosKeyStoreClient keyStoreClient; 
    SeosKeyStoreCtx* keyStoreApiRpc;
    SeosKeyStoreRpc_Handle keyStoreRpcHandle = NULL;

    seos_err_t err = SEOS_ERROR_GENERIC;
    bool ret = false;

    /************************** Init Crypto local version ****************************/
    err = SeosCrypto_init(&localCrypto, &cb, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCrypto_init failed with error code %d!", err);

    /************************** Init Crypto remote version ****************************/
    err = Crypto_getRpcHandle(&rpcHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "Crypto_getRpcHandle failed with error code %d!", err);

    err = SeosCryptoClient_init(&cryptoClient, rpcHandle, cryptoClientDataport);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoClient_init failed with error code %d!", err);

    /************************** Init 1. local version of the KeyStore ****************************/
    ret = keyStoreContext_ctor(&keyStoreCtx1,
                                NVM_CHANNEL_NUMBER,
                                KEY_STORE_INSTANCE_1_PARTITION,
                                SEOS_FS_TYPE_FAT,
                                chanMuxDataPort);
    Debug_ASSERT_PRINTFLN(ret == true, "keyStoreContext_ctor failed!");

    err = SeosKeyStore_init(&localKeyStore1,
                            SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(&(keyStoreCtx1.fileStreamFactory)),
                            &localCrypto,
                            KEY_STORE_INSTANCE_1_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStore_init failed with error code %d!", err);

    /************************** Init 2. local version of the KeyStore ****************************/
    ret = keyStoreContext_ctor(&keyStoreCtx2,
                                NVM_CHANNEL_NUMBER,
                                KEY_STORE_INSTANCE_2_PARTITION,
                                SEOS_FS_TYPE_FAT,
                                chanMuxDataPort);
    Debug_ASSERT_PRINTFLN(ret == true, "keyStoreContext_ctor failed!");

    err = SeosKeyStore_init(&localKeyStore2,
                            SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(&(keyStoreCtx2.fileStreamFactory)),
                            &localCrypto,
                            KEY_STORE_INSTANCE_2_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStore_init failed with error code %d!", err);

    /************************* Init KeyStore remote version ***************************/
    err = KeyStore_getRpcHandle(&keyStoreRpcHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "KeyStore_getRpcHandle failed with error code %d!", err);

    err = SeosKeyStoreClient_init(&keyStoreClient,
                                  keyStoreRpcHandle,
                                  keyStoreClientDataport);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreClient_init failed with error code %d!", err);

    /************************* API assignements ***************************/
    cryptoApiLocal      = SeosCrypto_TO_SEOS_CRYPTO_CTX(&localCrypto);
    cryptoApiRpc        = SeosCryptoClient_TO_SEOS_CRYPTO_CTX(&cryptoClient);
    keyStoreApiLocal1   = SeosKeyStore_TO_SEOS_KEY_STORE_CTX(&localKeyStore1);
    keyStoreApiLocal2   = SeosKeyStore_TO_SEOS_KEY_STORE_CTX(&localKeyStore2);
    keyStoreApiRpc      = SeosKeyStoreClient_TO_SEOS_KEY_STORE_CTX(&keyStoreClient);

    /******************** Test local and remote versions **********************/
    Debug_LOG_INFO("\n\n\n\n**************************** Starting 'TestKeyStoreFAT_scenario_1' ****************************\n");
    if (!keyStoreUnitTests(keyStoreApiLocal1))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_1 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_1 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_2' ****************************\n");
    if (!keyStoreUnitTests(keyStoreApiRpc))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_2 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_2 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_3' ****************************\n");
    if (!testKeyStoreAES(keyStoreApiLocal1, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_3 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_3 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_4' ****************************\n");
    if (!testKeyStoreAES(keyStoreApiRpc, cryptoApiRpc))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_4 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_4 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_5' ****************************\n");
    if (!testKeyStoreKeyPair(keyStoreApiLocal1, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_5 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_5 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_6' ****************************\n");
    if (!testKeyStoreKeyPair(keyStoreApiRpc, cryptoApiRpc))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_6 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_6 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_7' ****************************\n");
    if (!keyStoreCopyKeyTest(keyStoreApiLocal1, keyStoreApiLocal2, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_7 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_7 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_8' ****************************\n");
    if (!keyStoreCopyKeyTest(keyStoreApiLocal2, keyStoreApiRpc, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_8 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_8 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_9' ****************************\n");
    if (!keyStoreMoveKeyTest(keyStoreApiLocal1, keyStoreApiLocal2, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_9 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_9 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStoreFAT_scenario_10' ****************************\n");
    if (!keyStoreMoveKeyTest(keyStoreApiLocal2, keyStoreApiRpc, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStoreFAT_scenario_10 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStoreFAT_scenario_10 succeeded!\n\n\n\n");
    }

    /***************************** Destruction *******************************/
    SeosCrypto_free(cryptoApiLocal);
    SeosCryptoClient_free(cryptoApiRpc);
    
    SeosKeyStore_deInit(keyStoreApiLocal1);
    keyStoreContext_dtor(&keyStoreCtx1);

    SeosKeyStore_deInit(keyStoreApiLocal2);
    keyStoreContext_dtor(&keyStoreCtx2);    
    
    SeosKeyStoreClient_deInit(keyStoreApiRpc);
}

/* Private functios -----------------------------------------------------------*/
static int entropyFunc(void*           ctx,
                unsigned char*  buf,
                size_t          len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

///@}
