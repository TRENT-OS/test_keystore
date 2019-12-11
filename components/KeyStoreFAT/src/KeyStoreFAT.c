/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "LibDebug/Debug.h"

#include "KeyStoreFAT.h"
#include "KeyStoreInit.h"
#include "SeosCryptoLib.h"
#include <camkes.h>

/* Defines -----------------------------------------------------------*/
#define NVM_CHANNEL_NUMBER              6
#define KEY_STORE_INSTANCE_NAME         "KeyStore1"
#define KEY_STORE_INSTANCE_PARTITION    0

/* Private function prototypes -----------------------------------------------------------*/
static int entropyFunc(void* ctx, unsigned char* buf, size_t len);

/* Private variables -----------------------------------------------------------*/
static SeosCryptoLib    cryptoCore;

/* Public functions -----------------------------------------------------------*/
seos_err_t
Crypto_getRpcHandle(SeosCryptoApi_RpcServer* instance)
{
    static SeosCryptoRpcServer the_one;
    const SeosCryptoApi_Callbacks cb = {
        .malloc     = malloc,
        .free       = free,
        .entropy    = entropyFunc
    };

    seos_err_t retval = SeosCryptoLib_init(&cryptoCore, &cb, NULL);
    if (SEOS_SUCCESS == retval)
    {
        retval = SeosCryptoRpcServer_init(&the_one, &cryptoCore, cryptoServerDataport);
        *instance = &the_one;

        if (SEOS_SUCCESS == retval)
        {
            Debug_LOG_TRACE("%s: created rpc object %p", __func__, *instance);
        }
    }
    return retval;
}

void
Crypto_closeRpcHandle(SeosCryptoApi_RpcServer instance)
{
    /// TODO
}

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance)
{
    static SeosKeyStore keyStore;
    static SeosKeyStoreRpc the_one;
    static KeyStoreContext keyStoreCtx;

    if (!keyStoreContext_ctor(&keyStoreCtx,
                                NVM_CHANNEL_NUMBER,
                                KEY_STORE_INSTANCE_PARTITION,
                                SEOS_FS_TYPE_FAT,
                                chanMuxDataPort))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the test!", __func__);
        return 0;
    }

    seos_err_t retval = SeosKeyStore_init(&keyStore,
                                          SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(&(keyStoreCtx.fileStreamFactory)),
                                          SeosCryptoLib_TO_SEOS_CRYPTO_CTX(&cryptoCore),
                                          KEY_STORE_INSTANCE_NAME);

    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!", __func__,
                        retval);
        return retval;
    }


    retval = SeosKeyStoreRpc_init(&the_one, &(keyStore.parent),
                                  keyStoreServerDataport);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_init failed with error code %d!", __func__,
                        retval);
        return retval;
    }

    *instance = &the_one;

    if (SEOS_SUCCESS == retval)
    {
        Debug_LOG_TRACE("%s: created rpc object %p", __func__, *instance);
    }

    return retval;
}

void
KeyStore_closeRpcHandle(SeosKeyStoreRpc_Handle instance)
{
    /// TODO
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
