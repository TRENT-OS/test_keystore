/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreMultiInstanceTests.h"
#include "SeosCryptoApi.h"
#include "SeosKeyStoreApi.h"

/* Defines -------------------------------------------------------------------*/
#define COPY_KEY_NAME       "KeyCpy"
#define MOVE_KEY_NAME       "KeyMov"

/* Private variables ---------------------------------------------------------*/
static SeosCryptoKey_Data keyData;

static const SeosCryptoKey_Spec aes128Spec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .type = SeosCryptoKey_Type_AES,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .params.bits = 128
    }
};

/* Public functions -----------------------------------------------------------*/
bool keyStoreCopyKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, SeosCryptoCtx* cryptoCtx)
{
    SeosCrypto_KeyHandle key;
    size_t len;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_12 ************************************/
    err = SeosCryptoApi_keyGenerate(cryptoCtx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);

    err = SeosCryptoApi_keyExport(cryptoCtx, key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(srcKeyStore, COPY_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_keyFree(cryptoCtx, key);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyFree failed with err %d", err);

    /********************************** TestKeyStore_testCase_13 ************************************/
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, COPY_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d", err);

    /********************************** TestKeyStore_testCase_14 ************************************/
    err = SeosKeyStoreApi_copyKey(srcKeyStore, COPY_KEY_NAME, dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_copyKey failed with err %d", err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, COPY_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = SeosCryptoApi_keyImport(cryptoCtx, &key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyImport failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(srcKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    err = SeosKeyStoreApi_wipeKeyStore(dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    return true;
}

bool keyStoreMoveKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, SeosCryptoCtx* cryptoCtx)
{
    SeosCrypto_KeyHandle key;
    size_t len;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_15 ************************************/
    err = SeosCryptoApi_keyGenerate(cryptoCtx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);

    err = SeosCryptoApi_keyExport(cryptoCtx, key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(srcKeyStore, MOVE_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_keyFree(cryptoCtx, key);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyFree failed with err %d", err);

    /********************************** TestKeyStore_testCase_16 ************************************/
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d", err);

    /********************************** TestKeyStore_testCase_17 ************************************/
    err = SeosKeyStoreApi_moveKey(srcKeyStore, MOVE_KEY_NAME, dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_moveKey failed with err %d", err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(srcKeyStore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d", err);   
    
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = SeosCryptoApi_keyImport(cryptoCtx, &key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyImport failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(srcKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    err = SeosKeyStoreApi_wipeKeyStore(dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    return true;
}
