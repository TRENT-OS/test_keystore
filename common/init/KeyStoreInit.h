/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "ProxyNVM.h"
#include "AesNvm.h"
#include "SeosKeyStore.h"

#include "seos_fs.h"
#include "seos_pm.h"
#include "SeosFileStream.h"
#include "SeosFileStreamFactory.h"


typedef struct KeyStoreContext
{
    ProxyNVM proxyNVM;
    ChanMuxClient chanMuxClient;
    AesNvm aesNvm;
    hPartition_t partition;
    SeosFileStreamFactory fileStreamFactory;
} KeyStoreContext;


bool keyStoreContext_ctor(KeyStoreContext*  keyStoreCtx,
                          uint8_t           channelNum,
                          uint8_t           partitionID,
                          uint8_t           fsType,
                          void*             dataport);


bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx);
