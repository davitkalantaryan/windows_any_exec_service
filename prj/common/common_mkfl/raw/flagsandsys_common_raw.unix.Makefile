#
# repo:		    cpputils
# file:		    flagsandsys_common_pure.unix.Makefile
# created on:	    2020 Dec 14
# created by:	    Davit Kalantaryan (davit.kalantaryan@desy.de)
# purpose:	    This file can be only as include
#

ifndef cpputilsRepoRoot
        mkfile_path		=  $(abspath $(lastword $(MAKEFILE_LIST)))
        mkfile_dir		=  $(shell dirname $(mkfile_path))
        cpputilsRepoRoot	:= $(shell curDir=`pwd` && cd $(mkfile_dir)/../../../.. && pwd && cd ${curDir})
endif

ifndef artifactRoot
        artifactRoot	= $(cpputilsRepoRoot)
endif

include $(cpputilsRepoRoot)/contrib/cinternal/prj/common/common_mkfl/flagsandsys_common.unix.Makefile

COMMON_FLAGS	+= -I$(cpputilsRepoRoot)/include

LIBS	+= -L$(cpputilsRepoRoot)/sys/$(lsbCode)/$(Configuration)/lib
LIBS	+= -L$(cpputilsRepoRoot)/sys/$(lsbCode)/$(Configuration)/tlib
