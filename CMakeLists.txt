cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

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

set(SEOS_FS_CONFIG_H_FILE_FAT ${CMAKE_CURRENT_LIST_DIR}/components/KeyStoreFAT/config/seos_fs_config.h)
set(SEOS_PM_CONFIG_H_FILE_FAT ${CMAKE_CURRENT_LIST_DIR}/components/KeyStoreFAT/config/seos_pm_config.h)

set(SEOS_FS_CONFIG_H_FILE_SPIFFS ${CMAKE_CURRENT_LIST_DIR}/components/KeyStoreSPIFFS/config/seos_fs_config.h)
set(SEOS_PM_CONFIG_H_FILE_SPIFFS ${CMAKE_CURRENT_LIST_DIR}/components/KeyStoreSPIFFS/config/seos_pm_config.h)

set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "string")

project(test_keystore C)

DeclareCAmkESComponent(TopLevelTestRunner
    SOURCES
        components/TopLevelTestRunner/src/topLevelTestRunner.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
)

DeclareCAmkESComponent(TestRunnerKeyStoreFAT
    INCLUDES
        common/init
        common/test
    SOURCES
        common/init/KeyStoreInit.c
        common/test/keyStoreUnitTests.c
        common/test/keyStoreIntegrationTests.c
        common/test/keyStoreMultiInstanceTests.c
        components/TestRunnerKeyStoreFAT/src/testRunnerKeystoreFAT.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE_FAT}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE_FAT}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
)

DeclareCAmkESComponent(KeyStoreFAT
    INCLUDES
        common/init
        common/test
    SOURCES
        common/init/KeyStoreInit.c
        components/KeyStoreFAT/src/KeyStoreFAT.c

        ${SEOS_LIBS_DIR}/seos_crypto/src/SeosCryptoRpc.c
        ${SEOS_LIBS_DIR}/seos_keystore/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE_FAT}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE_FAT}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
)

DeclareCAmkESComponent(TestRunnerKeyStoreSPIFFS
    INCLUDES
        common/init
        common/test
    SOURCES
        common/init/KeyStoreInit.c
        common/test/keyStoreUnitTests.c
        common/test/keyStoreIntegrationTests.c
        common/test/keyStoreMultiInstanceTests.c
        components/TestRunnerKeyStoreSPIFFS/src/TestRunnerKeyStoreSPIFFS.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE_SPIFFS}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE_SPIFFS}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
)

DeclareCAmkESComponent(KeyStoreSPIFFS
    INCLUDES
        common/init
        common/test
    SOURCES
        common/init/KeyStoreInit.c
        components/KeyStoreSPIFFS/src/KeyStoreSPIFFS.c

        ${SEOS_LIBS_DIR}/seos_crypto/src/SeosCryptoRpc.c
        ${SEOS_LIBS_DIR}/seos_keystore/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE_SPIFFS}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE_SPIFFS}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_partition_manager
        seos_filesystem_core
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
        seos_core_api
        seos_libs
)

DeclareCAmkESRootserver(KeyStoreTestTopLevel.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()

