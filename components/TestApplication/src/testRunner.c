/**
 * @addtogroup KeyStoreApi_Tests
 * @{
 *
 * @file testRunner.c
 *
 * @brief top level test for the KeyStoreAPI
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

#include <camkes.h>
#include <string.h>

/* Defines -------------------------------------------------------------------*/
#define NVM_CHANNEL_NUMBER      (6)
#define KEY_STORE_INSTANCE_NAME "KeyStore1"

int entropyFunc(void*           ctx,
                unsigned char*  buf,
                size_t          len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

/**
 * @weakgroup KeyStoreApi_test_scenarios
 * @{
 *
 * @brief Top level test runner
 *
 * @test \b TestKeyStore_scenario_1     Perform TestKeyStore_testCase_01 - 03 for a local version of the KeyStore
 *
 * @test \b TestKeyStore_scenario_2     Perform TestKeyStore_testCase_01 - 03 for a remote version of the KeyStore
 *
 * @test \b TestKeyStore_scenario_3     Perform TestKeyStore_testCase_04 - 08 for a local version of the KeyStore
 *
 * @test \b TestKeyStore_scenario_4     Perform TestKeyStore_testCase_04 - 08 for a remote version of the KeyStore
 *
 * @test \b TestKeyStore_scenario_5     Perform TestKeyStore_testCase_09 - 11 for a local version of the KeyStore,
 *                                      for RSA and DH keypairs
 *
 * @test \b TestKeyStore_scenario_6     Perform TestKeyStore_testCase_09 - 11 for a remote version of the KeyStore,
 *                                      for RSA and DH keypairs
 *
 * @}
 */
int run()
{
    SeosCrypto localCrypto;
    SeosCryptoClient cryptoClient;
    SeosCryptoCtx* cryptoApiLocal;
    SeosCryptoCtx* cryptoApiRpc;
    SeosCryptoRpc_Handle rpcHandle = NULL;

    SeosKeyStore localKeyStore;
    SeosKeyStoreClient keyStoreClient;
    SeosKeyStoreCtx* keyStoreApiLocal;
    SeosKeyStoreCtx* keyStoreApiRpc;
    SeosKeyStoreRpc_Handle keyStoreRpcHandle = NULL;

    KeyStoreContext keyStoreCtx;

    seos_err_t err = SEOS_ERROR_GENERIC;

    /************************** Init Crypto local version ****************************/
    err = SeosCrypto_init(&localCrypto, malloc, free, entropyFunc, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCrypto_init failed with error code %d!", err);

    /************************** Init Crypto remote version ****************************/
    err = Crypto_getRpcHandle(&rpcHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "Crypto_getRpcHandle failed with error code %d!", err);

    err = SeosCryptoClient_init(&cryptoClient, rpcHandle, cryptoClientDataport);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoClient_init failed with error code %d!", err);

    /************************** Init KeyStore local version ****************************/
    Debug_ASSERT_PRINTFLN(keyStoreContext_ctor(&keyStoreCtx, NVM_CHANNEL_NUMBER,
                                               (void*)chanMuxDataPort) == true,
                          "keyStoreContext_ctor failed!");

    err = SeosKeyStore_init(&localKeyStore,
                            keyStoreCtx.fileStreamFactory,
                            &localCrypto,
                            KEY_STORE_INSTANCE_NAME);
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
    keyStoreApiLocal    = SeosKeyStore_TO_SEOS_KEY_STORE_CTX(&localKeyStore);
    keyStoreApiRpc      = SeosKeyStoreClient_TO_SEOS_KEY_STORE_CTX(&keyStoreClient);

    /******************** Test local and remote versions **********************/
    Debug_LOG_INFO("\n\n\n\n**************************** Starting 'TestKeyStore_scenario_1' ****************************\n");
    if (!keyStoreUnitTests(keyStoreApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_1 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_1 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_2' ****************************\n");
    if (!keyStoreUnitTests(keyStoreApiRpc))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_2 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_2 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n\n\n\n**************************** Starting 'TestKeyStore_scenario_3' ****************************\n");
    if (!testKeyStoreAES(keyStoreApiLocal, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_3 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_3 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_4' ****************************\n");
    if (!testKeyStoreAES(keyStoreApiRpc, cryptoApiRpc))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_4 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_4 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_5' ****************************\n");
    if (!testKeyStoreKeyPair(keyStoreApiLocal, cryptoApiLocal))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_5 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_5 succeeded!\n\n\n\n");
    }

    Debug_LOG_INFO("\n**************************** Starting 'TestKeyStore_scenario_6' ****************************\n");
    if (!testKeyStoreKeyPair(keyStoreApiRpc, cryptoApiRpc))
    {
        Debug_LOG_ERROR("\n\nTestKeyStore_scenario_6 FAILED!\n\n\n\n");
    }
    else
    {
        Debug_LOG_INFO("\n\nTestKeyStore_scenario_6 succeeded!\n\n\n\n");
    }

    /***************************** Destruction *******************************/
    keyStoreContext_dtor(&keyStoreCtx);

    SeosCrypto_free(cryptoApiLocal);
    SeosCryptoClient_free(cryptoApiRpc);

    SeosKeyStore_deInit(keyStoreApiLocal);
    SeosKeyStoreClient_deInit(keyStoreApiRpc);

    return 0;
}
///@}
