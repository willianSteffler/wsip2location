AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I. -pipe -D _GNU_SOURCE
AM_CXXFLAGS = -Wall -Werror

lib_LTLIBRARIES = libIP2Location.la
include_HEADERS = IP2Location.h IP2Loc_DBInterface.h 

libIP2Location_la_SOURCES = IP2Location.c \
							IP2Loc_DBInterface.c 
														
libIP2Location_la_LDFLAGS = -no-undefined -version-info 1:0:0
