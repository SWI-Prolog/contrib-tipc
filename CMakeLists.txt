cmake_minimum_required(VERSION 3.5)
project(swipl-tipc)

include("../cmake/PrologPackage.cmake")

AC_CHECK_HEADERS(linux/tipc.h)
if(HAVE_LINUX_TIPC_H)

include(Sockets)

AC_CHECK_HEADERS(unistd.h fcntl.h poll.h sys/time.h netinet/tcp.h)
AC_CHECK_FUNCS(poll)

configure_file(config.h.cmake config.h)

swipl_plugin(
    tipc
    C_SOURCES ../clib/error.c tipc.c ../clib/nonblockio.c
    C_LIBS ${LIBEDIT_LIBRARIES}
    PL_LIB_SUBDIR tipc
    PL_LIBS tipc.pl tipc_broadcast.pl tipc_paxos.pl tipc_linda.pl)
target_include_directories(
    plugin_tipc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../clib)

pkg_doc(tipc
	LIBSUBDIR
	    tipc
	SECTION
	    tipc_overview.md
	SUBSECTION
	    tipc_broadcast.pl tipc_paxos.pl tipc_linda.pl
	    SOURCE tipc.pl tipcpl.tex)

endif(HAVE_LINUX_TIPC_H)
