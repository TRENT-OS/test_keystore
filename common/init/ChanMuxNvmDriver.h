/**
 *
 * ChanMX NVM driver
 *
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 *
 */

#pragma once

#include "LibMem/Nvm.h"
#include "ProxyNVM.h"


typedef struct {
    ProxyNVM        proxyNVM;
    char            proxyBuffer[PAGE_SIZE];

    ChanMuxClient   chanMuxClient;
} ChanMuxNvmDriver;


bool
ChanMuxNvmDriver_ctor(
    ChanMuxNvmDriver*  self,
    uint8_t            channelNum,
    void*              dataport);


void
ChanMuxNvmDriver_dtor(
    ChanMuxNvmDriver*  self);


Nvm*
ChanMuxNvmDriver_get_nvm(
    ChanMuxNvmDriver*  self);
