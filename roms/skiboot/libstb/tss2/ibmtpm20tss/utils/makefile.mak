#################################################################################
#										#
#			Windows MinGW TPM2 Makefile OpenSSL 1.1.1 32-bit	#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2019					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

# Windows OpenSSL 1.1.1 32-bit with mingw

# Please contribute a solution for OpenSSL 64-bit (Shining Light),
# which does not include the mingw .a files.

# For this to work, copy the file .../openssl/bin/libcrypto-1.1.dll to
# libcrypto.dll.  Please contribute a solution that does not require
# this step.

# C compiler

CC = "c:/program files/mingw/bin/gcc.exe"

# compile - common flags for TSS library and applications

CCFLAGS += 					\
	-DTPM_WINDOWS				\
	-I. 					\
	-I"c:/program files/MinGW/include"	\
	-I"c:/program files/openssl/include"	\

# compile - for TSS library

CCLFLAGS +=					\
		-DTPM_TPM20

# compile - for applications

CCAFLAGS += 			\
		-DTPM_TPM20

# link - common flags flags TSS library and applications

LNFLAGS +=					\
	-D_MT					\
	-DTPM_WINDOWS				\
	-I.

# link - for TSS library

LNLFLAGS += 

# link - for applications, TSS path, TSS and OpenSSl libraries

LNAFLAGS += 

LNLIBS = 	"c:/program files/openssl/lib/mingw/libcrypto.a" \
		"c:/program files/MinGW/lib/libws2_32.a"

# shared library

LIBTSS=libibmtss.dll

# executable extension

EXE=.exe

# 

ALL =

# default TSS library

TSS_OBJS = 	tssfile.o 		\
		tsscryptoh.o 		\
		tsscrypto.o 		\
		tssprintcmd.o

# common to all builds

include makefile-common
include makefile-common20

#
# Start Windows TBSI
#

# mingw libraries are apparently no longer compatible with Windows
# Kits for TBS.  Contributions are welcome.  Until then, use the
# Visual Studio solution for the hardware TPM.

#TSS_OBJS += tsstbsi.o

#CCFLAGS +=	-DTPM_WINDOWS_TBSI
#CCFLAGS +=	-D_WIN32_WINNT=0x0600

# Windows 10

#CCFLAGS +=	-DTPM_WINDOWS_TBSI_WIN8
#CCFLAGS +=	-I"c:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\shared"

#LNLIBS += "c:/Program Files (x86)/Windows Kits/10/Lib/10.0.17763.0/um/x64/tbs.lib"

# Windows 7

#CCFLAGS +=	-DTPM_WINDOWS_TBSI_WIN7

#LNLIBS += c:/progra~1/Micros~2/Windows/v7.1/lib/Tbs.lib

#
# End Windows TBSI
#

# default build target

all:	$(ALL)

# TSS shared library source

tss.o: 		$(TSS_HEADERS) tss.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss.c
tssproperties.o: $(TSS_HEADERS) tssproperties.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssproperties.c
tssauth.o: 	$(TSS_HEADERS) tssauth.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth.c
tssmarshal.o: 	$(TSS_HEADERS) tssmarshal.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssmarshal.c
tsscryptoh.o: 	$(TSS_HEADERS) tsscryptoh.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsscryptoh.c
tsscrypto.o: 	$(TSS_HEADERS) tsscrypto.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsscrypto.c
tssutils.o: 	$(TSS_HEADERS) tssutils.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssutils.c
tssfile.o: 	$(TSS_HEADERS) tssfile.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssfile.c
tsssocket.o: 	$(TSS_HEADERS) tsssocket.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsssocket.c
tssdev.o: 	$(TSS_HEADERS) tssdev.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssdev.c
tsstransmit.o: 	$(TSS_HEADERS) tsstransmit.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tsstransmit.c
tssresponsecode.o: $(TSS_HEADERS) tssresponsecode.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssresponsecode.c
tssccattributes.o: $(TSS_HEADERS) tssccattributes.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssccattributes.c
tssprint.o: 	$(TSS_HEADERS) tssprint.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssprint.c
Unmarshal.o: 	$(TSS_HEADERS) Unmarshal.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Unmarshal.c
Commands.o: 	$(TSS_HEADERS) Commands.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) Commands.c
CommandAttributeData.o: 	$(TSS_HEADERS) CommandAttributeData.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) CommandAttributeData.c
ntc2lib.o:	$(TSS_HEADERS) ntc2lib.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) ntc2lib.c
tssntc.o:	$(TSS_HEADERS) tssntc.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssntc.c

# TPM 2.0

tss20.o: 	$(TSS_HEADERS) tss20.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tss20.c
tssauth20.o: 	$(TSS_HEADERS) tssauth20.c
		$(CC) $(CCFLAGS) $(CCLFLAGS) tssauth20.c

# TSS shared library build

$(LIBTSS): 	$(TSS_OBJS)
		$(CC) $(LNFLAGS) $(LNLFLAGS) -shared -o $(LIBTSS) $(TSS_OBJS) \
		-Wl,--out-implib,libibmtss.a $(LNLIBS)

.PHONY:		clean
.PRECIOUS:	%.o

clean:		
		rm -f *.o 	\
		$(LIBTSS)	\
		$(ALL)

create.exe:	create.o objecttemplates.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o objecttemplates.o cryptoutils.o $(LNLIBS) $(LIBTSS) 

createloaded.exe:	createloaded.o objecttemplates.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o objecttemplates.o cryptoutils.o $(LNLIBS) $(LIBTSS) 

createprimary.exe:	createprimary.o objecttemplates.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o objecttemplates.o cryptoutils.o $(LNLIBS) $(LIBTSS) 

eventextend.exe:	eventextend.o eventlib.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o eventlib.o cryptoutils.o $(LNLIBS) $(LIBTSS) 

imaextend.exe:	imaextend.o imalib.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o imalib.o cryptoutils.o $(LNLIBS) $(LIBTSS) 

createek.exe:	createek.o ekutils.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

certifyx509.exe:	certifyx509.o ekutils.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

createekcert.exe:	createekcert.o ekutils.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

importpem.exe:	importpem.o objecttemplates.o ekutils.o cryptoutils.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o objecttemplates.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

loadexternal.exe:	loadexternal.o cryptoutils.o ekutils.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o cryptoutils.o ekutils.o $(LNLIBS) $(LIBTSS)

nvread.exe:	nvread.o ekutils.o cryptoutils.o $(LIBTSS) 
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

nvwrite.exe:	nvwrite.o ekutils.o cryptoutils.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

signapp.exe:	signapp.o ekutils.o cryptoutils.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

writeapp.exe:	writeapp.o ekutils.o cryptoutils.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o ekutils.o cryptoutils.o $(LNLIBS) $(LIBTSS)

%.exe:		%.o applink.o cryptoutils.o $(LIBTSS)
		$(CC) $(LNFLAGS) -L. -libmtss $< -o $@ applink.o cryptoutils.o $(LNLIBS) $(LIBTSS)

%.o:		%.c
		$(CC) $(CCFLAGS) $(CCAFLAGS) $< -o $@
