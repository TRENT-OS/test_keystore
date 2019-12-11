/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreMultiInstanceTests.h"
#include "SeosCryptoApi.h"
#include "SeosKeyStoreApi.h"
#include "LibDebug/Debug.h"

/* Defines -------------------------------------------------------------------*/
#define COPY_KEY_NAME       "KeyCpy"
#define MOVE_KEY_NAME       "KeyMov"

/* Private variables ---------------------------------------------------------*/
static SeosCryptoApi_Key_Data keyData;

static const SeosCryptoApi_Key_Spec aes128Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .params.bits = 128
    }
};

/* Public functions -----------------------------------------------------------*/
bool keyStoreCopyKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, SeosCryptoApi_Context* cryptoCtx)
{
    SeosCryptoApi_Key key;
    size_t len;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_12 ************************************/
    err = SeosCryptoApi_Key_generate(cryptoCtx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_generate failed with err %d", err);

    err = SeosCryptoApi_Key_export(cryptoCtx, key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(srcKeyStore, COPY_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_Key_free(cryptoCtx, key);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_free failed with err %d", err);

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

    err = SeosCryptoApi_Key_import(cryptoCtx, &key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_import failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(srcKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    err = SeosKeyStoreApi_wipeKeyStore(dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    return true;
}

bool keyStoreMoveKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, SeosCryptoApi_Context* cryptoCtx)
{
    SeosCryptoApi_Key key;
    size_t len;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_15 ************************************/
    err = SeosCryptoApi_Key_generate(cryptoCtx, &key, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_generate failed with err %d", err);

    err = SeosCryptoApi_Key_export(cryptoCtx, key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(srcKeyStore, MOVE_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_Key_free(cryptoCtx, key);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_free failed with err %d", err);

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

    err = SeosCryptoApi_Key_import(cryptoCtx, &key, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_import failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(srcKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    err = SeosKeyStoreApi_wipeKeyStore(dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    return true;
}
