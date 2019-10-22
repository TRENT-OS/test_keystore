/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "LibDebug/Debug.h"

#include "CryptoServer.h"
#include "KeyStoreInit.h"
#include <camkes.h>

/* Private function prototypes -----------------------------------------------------------*/
static int entropyFunc(void* ctx, unsigned char* buf, size_t len);

/* Private variables -----------------------------------------------------------*/
static SeosCrypto    cryptoCore;

/* Public functions -----------------------------------------------------------*/
seos_err_t
Crypto_getRpcHandle(SeosCryptoRpc_Handle* instance)
{
    static SeosCryptoRpc the_one;
    const SeosCrypto_Callbacks cb = {
        .malloc     = malloc,
        .free       = free,
        .entropy    = entropyFunc
    };   

    seos_err_t retval = SeosCrypto_init(&cryptoCore, &cb, NULL);
    if (SEOS_SUCCESS == retval)
    {
        retval = SeosCryptoRpc_init(&the_one, &cryptoCore, cryptoServerDataport);
        *instance = &the_one;

        if (SEOS_SUCCESS == retval)
        {
            Debug_LOG_TRACE("%s: created rpc object %p", __func__, *instance);
        }
    }
    return retval;
}

void
Crypto_closeRpcHandle(SeosCryptoRpc_Handle instance)
{
    /// TODO
}

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance)
{
    static SeosKeyStore keyStore;
    static SeosKeyStoreRpc the_one;
    static KeyStoreContext keyStoreCtx;

    if (!keyStoreContext_ctor(&keyStoreCtx, 6, (void*)chanMuxDataPort))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the test!", __func__);
        return 0;
    }

#ifdef FAT_FS
    int8_t ret = InitFatFS(&keyStoreCtx);
    if(ret < 0)
    {
        Debug_LOG_ERROR("%s: InitFatFS failed!", __func__);
        return 0;
    }
#endif
#ifdef SPIF_FS
    int8_t ret = InitSpifFS(&keyStoreCtx);
    if(ret < 0)
    {
        Debug_LOG_ERROR("%s: InitSpifFS failed!", __func__);
        return 0;
    }
#endif

    seos_err_t retval = SeosKeyStore_init(&keyStore,
                                          keyStoreCtx.fileStreamFactory,
                                          &cryptoCore,
                                          "KEY_STORE");

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
