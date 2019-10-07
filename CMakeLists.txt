cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SPIFFS
    SEOS_KEYSTORE
)

set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "string")

project(test_keystore C)

DeclareCAmkESComponent(TestApplication
    INCLUDES
        common
    SOURCES
        components/TestApplication/src/keyStoreIntegrationTests.c
        components/TestApplication/src/keyStoreUnitTests.c
        components/TestApplication/src/testRunner.c
        common/KeyStoreInit.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
        seos_crypto
        seos_keystore
)

DeclareCAmkESComponent(CryptoServer
    INCLUDES
        common
    SOURCES
        components/CryptoServer/instance/CryptoServer.c
        common/KeyStoreInit.c
        ${SEOS_LIBS_DIR}/seos_crypto/src/SeosCryptoRpc.c
        ${SEOS_LIBS_DIR}/seos_keystore/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
        seos_crypto
        seos_keystore
)

DeclareCAmkESComponent(UartDrv
    SOURCES
        components/Uart/src/UartDrv.c
        components/Uart/src/qemu_uart.c
    C_FLAGS
        -Wall -Werror
)

DeclareCAmkESComponent(ChanMux
    SOURCES
        components/ChanMux/src/instance/ChanMux_Instance.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_libs
)

DeclareCAmkESRootserver(KeyStoreTestTopLevel.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()

