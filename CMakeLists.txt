cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CHANMUX
    SEOS_CRYPTO_WITH_RPC_SERVER
    SEOS_CRYPTO_WITH_RPC_CLIENT
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_PARTITION_MANAGER
    SEOS_FILESYSTEM_CORE
    SEOS_FILESYSTEM_FAT
    SEOS_FILESYSTEM_SPIFFS
    SEOS_KEYSTORE
)

set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "string")

set(SEOS_LIBS_KEYSTORE "${SEOS_LIBS_DIR}/seos_keystore")

project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


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
        common/init/EncryptedPartitionFileStream.c
        common/test/keyStoreUnitTests.c
        common/test/keyStoreIntegrationTests.c
        common/test/keyStoreMultiInstanceTests.c
        components/TestRunnerKeyStoreFAT/src/testRunnerKeystoreFAT.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        system_config
        seos_core_api
        seos_libs
        chanmux_client
        proxy_nvm
        seos_crypto_with_rpc_client
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
        common/init/EncryptedPartitionFileStream.c
        components/KeyStoreFAT/src/KeyStoreFAT.c
        ${SEOS_LIBS_KEYSTORE}/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        system_config
        seos_core_api
        seos_libs
        chanmux_client
        proxy_nvm
        seos_crypto_with_rpc_server
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
        common/init/EncryptedPartitionFileStream.c
        common/test/keyStoreUnitTests.c
        common/test/keyStoreIntegrationTests.c
        common/test/keyStoreMultiInstanceTests.c
        components/TestRunnerKeyStoreSPIFFS/src/TestRunnerKeyStoreSPIFFS.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        system_config
        seos_core_api
        seos_libs
        chanmux_client
        proxy_nvm
        seos_crypto_with_rpc_client
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
        common/init/EncryptedPartitionFileStream.c
        components/KeyStoreSPIFFS/src/KeyStoreSPIFFS.c
        ${SEOS_LIBS_KEYSTORE}/src/SeosKeyStoreRpc.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        system_config
        seos_core_api
        seos_libs
        chanmux_client
        proxy_nvm
        seos_crypto_with_rpc_server
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
        components/ChanMux/src/ChanMux.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_libs
        chanmux_server
)

DeclareCAmkESRootserver(KeyStoreTestTopLevel.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()

