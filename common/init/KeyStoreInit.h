/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "ProxyNVM.h"
#include "AesNvm.h"
#include "SeosKeyStore.h"

#include "seos_fs.h"    // include path to fs-core must be set in cmakelists.txt
#include "seos_pm.h"    // include path to partition manager must be set in cmakelists.txt
#include "SeosFileStream.h"
#include "SeosFileStreamFactory.h"
#include "handle_resolver.h"
#include "partition_io_layer.h"
#include "api_pm.h"

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
                          register_fs_t     fsType,
                          void*             dataport);
bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx);