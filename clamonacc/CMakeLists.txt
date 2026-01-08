# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

# The clamonacc executable.
add_executable( clamonacc )
target_sources( clamonacc
    PRIVATE
        clamonacc.c
        clamonacc.h
        c-thread-pool/thpool.c
        c-thread-pool/thpool.h
        client/client.c
        client/client.h
        client/communication.c
        client/communication.h
        client/protocol.c
        client/protocol.h
        client/socket.c
        client/socket.h
        fanotif/fanotif.c
        fanotif/fanotif.h
        inotif/inotif.c
        inotif/inotif.h
        inotif/hash.c
        inotif/hash.h
        misc/priv_fts.h
        misc/utils.c
        misc/utils.h
        scan/onas_queue.c
        scan/onas_queue.h
        scan/thread.c
        scan/thread.c
        scan/thread.h )

if(APPLE)
    target_sources( clamonacc
        PRIVATE
            esf/esf_interface.c
            esf/esf_interface.h )
    
    find_library(ENDPOINT_SECURITY_LIB EndpointSecurity)
    find_library(COREFOUNDATION_LIB CoreFoundation REQUIRED)
    target_link_libraries( clamonacc PRIVATE ${ENDPOINT_SECURITY_LIB} ${COREFOUNDATION_LIB} )
    target_compile_definitions( clamonacc PRIVATE HAVE_MACOS_ESF )

    # IMPORTANT (macOS):
    # If clamonacc is copied by hand out of the build tree (instead of installed via CMake),
    # it must not retain build-directory RPATHs like .../build/libclamav, or dyld will load
    # unsigned build artifacts and AMFI will reject them ("different Team IDs").
    #
    # Use an install-style rpath that resolves to /usr/local/clamav/lib when clamonacc lives in sbin/.
    set_target_properties(clamonacc PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path/../lib"
    )
endif()

if(NOT HAVE_SYSTEM_LFS_FTS)
    target_sources( clamonacc
        PRIVATE
            misc/fts.c )
endif()

target_include_directories( clamonacc
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR} # So subdir source can #include "clamonacc.h"
        ${CMAKE_BINARY_DIR} # For clamav-config.h
        ${CMAKE_SOURCE_DIR}/clamd # Yes, this is a hack! We want to use clamd headers even though clamd isn't a library.
)

set_target_properties( clamonacc PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

target_link_libraries( clamonacc
    PRIVATE
        ClamAV::libclamav
        ClamAV::common
        CURL::libcurl )
install(TARGETS clamonacc DESTINATION ${CMAKE_INSTALL_SBINDIR} COMPONENT programs)

if(SYSTEMD_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-clamonacc.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-clamonacc.service @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-clamonacc.service
        DESTINATION ${SYSTEMD_UNIT_DIR} COMPONENT programs)
endif()
