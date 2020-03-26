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


typedef struct
{
    // we expose a file stream interface
    SeosFileStreamFactory  fileStreamFactory;
    struct {
        hPartition_t           hPartition;
    } internal;

} EncryptedPartitionFileStream;


bool
EncryptedPartitionFileStream_ctor(
    EncryptedPartitionFileStream*  self,
    uint8_t                        channelNum,
    uint8_t                        partitionID,
    uint8_t                        fsType,
    void*                          dataport);


bool
EncryptedPartitionFileStream_dtor(
    EncryptedPartitionFileStream*  self);
