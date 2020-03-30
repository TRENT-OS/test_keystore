/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#pragma once

#include "OS_Crypto.h"
#include "SeosKeyStoreRpc.h"

seos_err_t
CryptoRpcServer_openSession(void);

seos_err_t
CryptoRpcServer_closeSession(void);

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance);

void
KeyStore_closeRpcHandle(SeosKeyStoreRpc_Handle instance);
