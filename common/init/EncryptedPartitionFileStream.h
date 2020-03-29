/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#pragma once

#include "SeosFileStream.h"
#include "SeosFileStreamFactory.h"


typedef struct
{
    struct {
        SeosFileStreamFactory  seosFileStreamFactory;
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


FileStreamFactory*
EncryptedPartitionFileStream_get_FileStreamFactory(
    EncryptedPartitionFileStream*  self);
