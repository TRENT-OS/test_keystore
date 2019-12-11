/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#pragma once

#include "SeosCryptoRpcServer.h"
#include "SeosKeyStoreRpc.h"
#include "LibDebug/Debug.h"

#include <camkes.h>

seos_err_t
Crypto_getRpcHandle(SeosCryptoApi_RpcServer* instance);

void
Crypto_closeRpcHandle(SeosCryptoApi_RpcServer instance);

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance);

void
KeyStore_closeRpcHandle(SeosKeyStoreRpc_Handle instance);
