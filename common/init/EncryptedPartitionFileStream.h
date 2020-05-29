/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#pragma once

#include "LibMem/Nvm.h"
#include "OS_FilesystemFileStream.h"
#include "OS_FilesystemFileStreamFactory.h"


typedef struct
{
    struct {
        OS_FilesystemFileStreamFactory_t seosFileStreamFactory;
        hPartition_t hPartition;
    } internal;
} EncryptedPartitionFileStream;


bool
EncryptedPartitionFileStream_ctor(
    EncryptedPartitionFileStream* self,
    Nvm*                          nvm,
    uint8_t                       partitionID,
    uint8_t                       fsType);


bool
EncryptedPartitionFileStream_dtor(
    EncryptedPartitionFileStream* self);


FileStreamFactory*
EncryptedPartitionFileStream_get_FileStreamFactory(
    EncryptedPartitionFileStream* self);
