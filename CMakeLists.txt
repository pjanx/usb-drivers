cmake_minimum_required (VERSION 3.10)
project (usb-drivers VERSION 0.1.0 DESCRIPTION "USB drivers" LANGUAGES C)

# Moar warnings
set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS OFF)

if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUCC)
	# -Wunused-function is pretty annoying here, as everything is static
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-function")
endif ()

# Dependencies
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/liberty/cmake)
include (AddThreads)

find_package (PkgConfig REQUIRED)
pkg_check_modules (libusb libusb-1.0)

option (WITH_LIBUSB "Compile with libusb utilities" ${libusb_FOUND})

# Generate a configuration file
configure_file (${PROJECT_SOURCE_DIR}/config.h.in
	${PROJECT_BINARY_DIR}/config.h)
include_directories (${PROJECT_BINARY_DIR})

# Build
if ("${CMAKE_SYSTEM_NAME}" MATCHES BSD)
	# Need this for SIGWINCH in FreeBSD and OpenBSD respectively;
	# our POSIX version macros make it undefined
	add_definitions (-D__BSD_VISIBLE=1 -D_BSD_SOURCE=1)
elseif (APPLE)
	add_definitions (-D_DARWIN_C_SOURCE)
endif ()

if (WITH_LIBUSB)
	list (APPEND targets elksmart-comm)
	add_executable (elksmart-comm elksmart-comm.c)
	target_include_directories (elksmart-comm PUBLIC ${libusb_INCLUDE_DIRS})
	target_link_directories (elksmart-comm PUBLIC ${libusb_LIBRARY_DIRS})
	target_link_libraries (elksmart-comm ${libusb_LIBRARIES})
endif ()

# The files to be installed
include (GNUInstallDirs)

# These should be accessible by users, but need to touch system devices.
# Use the setuid bit, for simplicity.
install (TARGETS ${targets} DESTINATION ${CMAKE_INSTALL_BINDIR}
	PERMISSIONS
		OWNER_WRITE OWNER_READ OWNER_EXECUTE
		GROUP_READ GROUP_EXECUTE
		WORLD_READ WORLD_EXECUTE
		SETUID)
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# CPack
set (CPACK_PACKAGE_VENDOR "Premysl Eric Janouch")
set (CPACK_PACKAGE_CONTACT "Přemysl Eric Janouch <p@janouch.name>")
set (CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set (CPACK_GENERATOR "TGZ;ZIP")
set (CPACK_PACKAGE_FILE_NAME
	"${PROJECT_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "${PROJECT_NAME}-${PROJECT_VERSION}")
set (CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set (CPACK_SOURCE_IGNORE_FILES "/\\\\.git;/build;/CMakeLists.txt.user")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${PROJECT_VERSION}")

set (CPACK_SET_DESTDIR TRUE)
include (CPack)
