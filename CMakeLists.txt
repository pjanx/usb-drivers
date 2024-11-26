cmake_minimum_required (VERSION 3.10)
project (usb-drivers VERSION 1.0.0
	DESCRIPTION "User space USB drivers" LANGUAGES C)

# Moar warnings
set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS OFF)

if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUCC)
	# -Wunused-function is pretty annoying here, as everything is static
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-function")
endif ()

if (WIN32 AND CMAKE_CROSSCOMPILING)
	set (win32_deps_root "${PROJECT_SOURCE_DIR}")
	set (win32_deps_prefix "${win32_deps_root}/mingw64")
	list (APPEND CMAKE_PREFIX_PATH "${win32_deps_prefix}")
	list (APPEND CMAKE_INCLUDE_PATH "${win32_deps_prefix}/lib")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mms-bitfields")

	list (APPEND CMAKE_FIND_ROOT_PATH ${win32_deps_prefix})

	# Relativize prefixes, and bar pkg-config from looking up host libraries
	set (ENV{PKG_CONFIG_SYSROOT_DIR} "${win32_deps_root}")
	set (win32_deps_pcpath
		"${win32_deps_prefix}/share/pkgconfig:${win32_deps_prefix}/lib/pkgconfig")
	set (ENV{PKG_CONFIG_PATH} "${win32_deps_pcpath}")
	set (ENV{PKG_CONFIG_LIBDIR} "${win32_deps_pcpath}")
endif ()
if (WIN32)
	add_link_options (-static)
endif ()

# Dependencies
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/liberty/cmake)

find_package (PkgConfig REQUIRED)
pkg_check_modules (libusb libusb-1.0)
pkg_search_module (hidapi hidapi hidapi-hidraw hidapi-libusb)

option (WITH_LIBUSB "Compile with libusb-based utilities" ${libusb_FOUND})
option (WITH_HIDAPI "Compile with hidapi-based utilities" ${hidapi_FOUND})

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

if (WITH_LIBUSB AND NOT WIN32)
	# -liconv may or may not be a part of libc
	find_path (iconv_INCLUDE_DIRS iconv.h)

	list (APPEND targets elksmart-comm)
	add_executable (elksmart-comm elksmart-comm.c)
	target_include_directories (elksmart-comm
		PUBLIC ${libusb_INCLUDE_DIRS} ${iconv_INCLUDE_DIRS})
	target_link_directories (elksmart-comm PUBLIC ${libusb_LIBRARY_DIRS})
	target_link_libraries (elksmart-comm ${libusb_LIBRARIES})
endif ()
if (WITH_LIBUSB)
	list (APPEND targets razer-bw-te-ctl)
	add_executable (razer-bw-te-ctl razer-bw-te-ctl.c)
	target_include_directories (razer-bw-te-ctl PUBLIC ${libusb_INCLUDE_DIRS})
	target_link_directories (razer-bw-te-ctl PUBLIC ${libusb_LIBRARY_DIRS})
	target_link_libraries (razer-bw-te-ctl ${libusb_LIBRARIES})
endif ()

if (WITH_HIDAPI)
	list (APPEND targets eizoctl)
	add_executable (eizoctl eizoctl.c)
	target_include_directories (eizoctl PUBLIC ${hidapi_INCLUDE_DIRS})
	target_link_directories (eizoctl PUBLIC ${hidapi_LIBRARY_DIRS})
	target_link_libraries (eizoctl ${hidapi_LIBRARIES})
endif ()
if (WITH_HIDAPI AND WIN32)
	list (APPEND targets_gui eizoctltray)

	include (IconUtils)
	set (icon_png_list)
	foreach (icon_size 16 32 48)
		icon_to_png (eizoctltray ${PROJECT_SOURCE_DIR}/eizoctltray.svg
			${icon_size} ${PROJECT_BINARY_DIR}/icons icon_png)
		list (APPEND icon_png_list ${icon_png})
	endforeach ()
	icon_to_png (eizoctltray ${PROJECT_SOURCE_DIR}/eizoctltray.svg
		256 ${PROJECT_BINARY_DIR}/icons icon_png)

	set (icon_ico ${PROJECT_BINARY_DIR}/eizoctltray.ico)
	icon_for_win32 (${icon_ico} "${icon_png_list}" "${icon_png}")
	list (APPEND icon_ico_list )
	set_property (SOURCE eizoctltray.rc
		APPEND PROPERTY OBJECT_DEPENDS ${icon_ico})

	add_executable (eizoctltray WIN32 eizoctl.c eizoctltray.rc)
	target_compile_definitions (eizoctltray PUBLIC -DUNICODE -D_UNICODE -DTRAY)
	target_link_options (eizoctltray PUBLIC -municode)
	target_include_directories (eizoctltray PUBLIC ${hidapi_INCLUDE_DIRS})
	target_link_directories (eizoctltray PUBLIC ${hidapi_LIBRARY_DIRS})
	target_link_libraries (eizoctltray ${hidapi_LIBRARIES} powrprof)
endif ()

# Generate documentation from help output
if (NOT CMAKE_CROSSCOMPILING)
	find_program (HELP2MAN_EXECUTABLE help2man)
	if (NOT HELP2MAN_EXECUTABLE)
		message (FATAL_ERROR "help2man not found")
	endif ()

	foreach (target ${targets})
		set (page_output "${PROJECT_BINARY_DIR}/${target}.1")
		list (APPEND project_MAN_PAGES "${page_output}")
		add_custom_command (OUTPUT ${page_output}
			COMMAND ${HELP2MAN_EXECUTABLE} -N
				"${PROJECT_BINARY_DIR}/${target}" -o ${page_output}
			DEPENDS ${target}
			COMMENT "Generating man page for ${target}" VERBATIM)
	endforeach ()

	add_custom_target (docs ALL DEPENDS ${project_MAN_PAGES})
endif ()

# The files to be installed
include (GNUInstallDirs)

# These should be accessible by users, but need to touch system devices.
# Use the setuid bit, for simplicity.
set (SETUID "SETUID" CACHE STRING "Set this empty on permission issues")
install (TARGETS ${targets} DESTINATION ${CMAKE_INSTALL_BINDIR}
	PERMISSIONS
		OWNER_WRITE OWNER_READ OWNER_EXECUTE
		GROUP_READ GROUP_EXECUTE
		WORLD_READ WORLD_EXECUTE
		${SETUID})
install (TARGETS ${targets_gui} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

foreach (page ${project_MAN_PAGES})
	string (REGEX MATCH "\\.([0-9])$" manpage_suffix "${page}")
	install (FILES "${page}"
		DESTINATION "${CMAKE_INSTALL_MANDIR}/man${CMAKE_MATCH_1}")
endforeach ()

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
