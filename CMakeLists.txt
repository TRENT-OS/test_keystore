cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config/config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_PARTITION_MANAGER
    SEOS_FILESYSTEM_CORE
    SEOS_FILESYSTEM_FAT
    SEOS_FILESYSTEM_SPIFFS
    SEOS_KEYSTORE
)

set(SEOS_FS_CONFIG_H_FILE ${CMAKE_CURRENT_LIST_DIR}/config/seos_fs_config.h)
set(SEOS_PM_CONFIG_H_FILE ${CMAKE_CURRENT_LIST_DIR}/config/seos_pm_config.h)

set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "string")

project(test_keystore C)

DeclareCAmkESComponent(TestApplication
    INCLUDES
        common
        config
    SOURCES
        components/TestApplication/src/keyStoreIntegrationTests.c
        components/TestApplication/src/keyStoreUnitTests.c
        components/TestApplication/src/keyStoreMultiInstanceTests.c
        components/TestApplication/src/testRunner.c
        common/KeyStoreInit.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
        # fs used by the keystore (FAT_FS / SPIF_FS)
        -DFAT_FS
        #-DSPIF_FS
    LIBS
        seos_libs
        seos_crypto
        seos_partition_manager
        seos_filesystem_core
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_keystore
)

DeclareCAmkESComponent(CryptoServer
    INCLUDES
        common
        config
    SOURCES
        components/CryptoServer/instance/CryptoServer.c
        common/KeyStoreInit.c
        ${SEOS_LIBS_DIR}/seos_crypto/src/SeosCryptoRpc.c
        ${SEOS_LIBS_DIR}/seos_keystore/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
        # fs used by the keystore (FAT_FS / SPIF_FS)
        -DFAT_FS
        #-DSPIF_FS
    LIBS
        seos_libs
        seos_crypto
        seos_partition_manager
        seos_filesystem_core
        seos_filesystem_fat
        seos_filesystem_spiffs
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

