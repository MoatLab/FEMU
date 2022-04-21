transform=s&^&tss&

lib_LTLIBRARIES = libibmtss.la
#if CONFIG_TPM20
lib_LTLIBRARIES += libibmtssutils.la
#endif

# default TSS Library
libibmtss_la_SOURCES = tssfile.c tsscryptoh.c tsscrypto.c
libibmtss_la_LIBADD = $(LIBCRYPTO_LIBS)

# TSS shared library object files (utils/makefile-common)
libibmtss_la_SOURCES += tss.c tssproperties.c tssmarshal.c tssauth.c tssutils.c tsssocket.c tssdev.c tsstransmit.c tssresponsecode.c tssccattributes.c tssprint.c Unmarshal.c CommandAttributeData.c

# TPM 2.0
# TSS share libarary object files
if CONFIG_TPM20
libibmtss_la_SOURCES += tss20.c tssauth20.c Commands.c tssprintcmd.c
libibmtss_la_SOURCES += ntc2lib.c tssntc.c
endif

# (from utils/makefile-common12)
if CONFIG_TPM12
libibmtss_la_SOURCES += tss12.c tssauth12.c tssmarshal12.c Unmarshal12.c Commands12.c tssccattributes12.c CommandAttributeData12.c
endif

libibmtss_la_CFLAGS = -fPIC
if CONFIG_HWTPM
libibmtss_la_CFLAGS += -DTPM_INTERFACE_TYPE_DEFAULT="\"dev\""
endif

if CONFIG_RMTPM
libibmtss_la_CFLAGS += -DTPM_DEVICE_DEFAULT="\"/dev/tpmrm0\""
endif

if CONFIG_TPM20
libibmtss_la_CFLAGS += -DTPM_TPM20
endif

if CONFIG_TPM12
libibmtss_la_CFLAGS += -DTPM_TPM12
endif

if CONFIG_TSS_NOPRINT
libibmtss_la_CFLAGS += -DTPM_TSS_NO_PRINT
endif

if CONFIG_TSS_NOFILE
libibmtss_la_CFLAGS += -DTPM_TSS_NOFILE
if CONFIG_TSS_NOCRYPTO
libibmtss_la_CFLAGS += -DTPM_TSS_NOCRYPTO
endif
endif

if CONFIG_TSS_NOECC
libibmtss_la_CFLAGS += -DTPM_TSS_NOECC
endif

libibmtss_la_CCFLAGS = -Wall -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wformat=2 -Wold-style-definition -Wno-self-assign -ggdb
libibmtss_la_LDFLAGS = -version-info @TSSLIB_VERSION_INFO@

libibmtssutils_la_SOURCES = cryptoutils.c ekutils.c imalib.c eventlib.c
libibmtssutils_la_CFLAGS = -fPIC

if CONFIG_TPM20
libibmtssutils_la_CFLAGS += -DTPM_TPM20
endif

if CONFIG_TPM12
libibmtssutils_la_CFLAGS += -DTPM_TPM12
endif

if CONFIG_TSS_NOECC
libibmtssutils_la_CFLAGS += -DTPM_TSS_NOECC
endif

#current[:revision[:age]]
#result: [current-age].age.revision
libibmtssutils_la_LDFLAGS = -version-info @TSSLIB_VERSION_INFO@
libibmtssutils_la_LIBADD = libibmtss.la $(LIBCRYPTO_LIBS)

noinst_HEADERS = CommandAttributes.h imalib.h tssdev.h ntc2lib.h tssntc.h Commands_fp.h objecttemplates.h tssproperties.h cryptoutils.h Platform.h tssauth.h tsssocket.h ekutils.h eventlib.h tssccattributes.h
# install every header in ibmtss
nobase_include_HEADERS = ibmtss/*.h

notrans_man_MANS = man/man1/*.1

if CONFIG_TPM20
noinst_HEADERS += tss20.h tssauth20.h ibmtss/tssprintcmd.h
endif

if CONFIG_TPM12
noinst_HEADERS += tss12.h Commands12_fp.h tssauth12.h tssccattributes12.h ibmtss/Unmarshal12_fp.h ibmtss/Parameters12.h ibmtss/tpmstructures12.h ibmtss/tpmconstants12.h ibmtss/tpmtypes12.h
endif

if CONFIG_TPM20
bin_PROGRAMS = activatecredential eventextend imaextend certify certifycreation certifyx509 changeeps changepps clear \
	clearcontrol clockrateadjust clockset commit contextload contextsave create createloaded createprimary \
	dictionaryattacklockreset dictionaryattackparameters duplicate eccparameters ecephemeral encryptdecrypt \
	eventsequencecomplete evictcontrol flushcontext getcommandauditdigest getcapability getcryptolibrary \
	getrandom gettestresult getsessionauditdigest gettime hashsequencestart hash hierarchycontrol \
	hierarchychangeauth hmac hmacstart import importpem load loadexternal makecredential nvcertify nvchangeauth \
	nvdefinespace nvextend nvglobalwritelock nvincrement nvread nvreadlock nvreadpublic nvsetbits \
	nvundefinespace nvundefinespacespecial nvwrite nvwritelock objectchangeauth pcrallocate pcrevent pcrextend \
	pcrread pcrreset policyauthorize policyauthvalue policycommandcode policycphash policynamehash \
	policycountertimer policyduplicationselect policygetdigest policymaker policymakerpcr policyauthorizenv \
	policynv policynvwritten policyor policypassword policypcr policyrestart policysigned policysecret \
	policytemplate policyticket quote powerup readclock readpublic returncode rewrap rsadecrypt rsaencrypt \
	sequenceupdate sequencecomplete setcommandcodeauditstatus setprimarypolicy shutdown sign startauthsession \
	startup stirrandom unseal \
	verifysignature zgen2phase signapp writeapp timepacket createek createekcert tpm2pem tpmpublic2eccpoint \
	ntc2getconfig ntc2preconfig ntc2lockconfig publicname tpmcmd printattr

if CONFIG_TSS_NOECC
UTILS_CFLAGS = -DTPM_TSS_NOECC
endif

activatecredential_SOURCES = activatecredential.c
activatecredential_CFLAGS = $(UTILS_CFLAGS)
activatecredential_LDADD = libibmtssutils.la libibmtss.la

eventextend_SOURCES = eventextend.c
eventextend_CFLAGS = $(UTILS_CFLAGS)
eventextend_LDADD = libibmtssutils.la libibmtss.la

imaextend_SOURCES = imaextend.c
imaextend_CFLAGS = $(UTILS_CFLAGS)
imaextend_LDADD = libibmtssutils.la libibmtss.la

certify_SOURCES = certify.c
certify_CFLAGS = $(UTILS_CFLAGS)
certify_LDADD = libibmtssutils.la libibmtss.la

certifycreation_SOURCES = certifycreation.c
certifycreation_CFLAGS = $(UTILS_CFLAGS)
certifycreation_LDADD = libibmtssutils.la libibmtss.la

certifyx509_SOURCES = certifyx509.c
certifyx509_CFLAGS = $(UTILS_CFLAGS)
certifyx509_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

changeeps_SOURCES = changeeps.c
changeeps_CFLAGS = $(UTILS_CFLAGS)
changeeps_LDADD = libibmtssutils.la libibmtss.la

changepps_SOURCES = changepps.c
changepps_CFLAGS = $(UTILS_CFLAGS) -DTPM_POSIX
changepps_LDADD = libibmtssutils.la libibmtss.la

clear_SOURCES = clear.c
clear_CFLAGS = $(UTILS_CFLAGS)
clear_LDADD = libibmtssutils.la libibmtss.la

clearcontrol_SOURCES = clearcontrol.c
clearcontrol_CFLAGS = $(UTILS_CFLAGS)
clearcontrol_LDADD = libibmtssutils.la libibmtss.la

clockrateadjust_SOURCES = clockrateadjust.c
clockrateadjust_CFLAGS = $(UTILS_CFLAGS)
clockrateadjust_LDADD = libibmtssutils.la libibmtss.la

clockset_SOURCES = clockset.c
clockset_CFLAGS = $(UTILS_CFLAGS)
clockset_LDADD = libibmtssutils.la libibmtss.la

commit_SOURCES = commit.c
commit_CFLAGS = $(UTILS_CFLAGS)
commit_LDADD = libibmtssutils.la libibmtss.la

contextload_SOURCES = contextload.c
contextload_CFLAGS = $(UTILS_CFLAGS)
contextload_LDADD = libibmtssutils.la libibmtss.la

contextsave_SOURCES = contextsave.c
contextsave_CFLAGS = $(UTILS_CFLAGS)
contextsave_LDADD = libibmtssutils.la libibmtss.la

create_SOURCES = create.c objecttemplates.c
create_CFLAGS = $(UTILS_CFLAGS)
create_LDADD = libibmtssutils.la libibmtss.la

createloaded_SOURCES = createloaded.c objecttemplates.c
createloaded_CFLAGS = $(UTILS_CFLAGS)
createloaded_LDADD = libibmtssutils.la libibmtss.la

createprimary_SOURCES = createprimary.c objecttemplates.c
createprimary_CFLAGS = $(UTILS_CFLAGS)
createprimary_LDADD = libibmtssutils.la libibmtss.la

dictionaryattacklockreset_SOURCES = dictionaryattacklockreset.c
dictionaryattacklockreset_CFLAGS = $(UTILS_CFLAGS)
dictionaryattacklockreset_LDADD = libibmtssutils.la libibmtss.la

dictionaryattackparameters_SOURCES = dictionaryattackparameters.c
dictionaryattackparameters_CFLAGS = $(UTILS_CFLAGS)
dictionaryattackparameters_LDADD = libibmtssutils.la libibmtss.la

duplicate_SOURCES = duplicate.c
duplicate_CFLAGS = $(UTILS_CFLAGS)
duplicate_LDADD = libibmtssutils.la libibmtss.la

eccparameters_SOURCES = eccparameters.c
eccparameters_CFLAGS = $(UTILS_CFLAGS)
eccparameters_LDADD = libibmtssutils.la libibmtss.la

ecephemeral_SOURCES = ecephemeral.c
ecephemeral_CFLAGS = $(UTILS_CFLAGS)
ecephemeral_LDADD = libibmtssutils.la libibmtss.la

encryptdecrypt_SOURCES = encryptdecrypt.c
encryptdecrypt_CFLAGS = $(UTILS_CFLAGS)
encryptdecrypt_LDADD = libibmtssutils.la libibmtss.la

eventsequencecomplete_SOURCES = eventsequencecomplete.c
eventsequencecomplete_CFLAGS = $(UTILS_CFLAGS)
eventsequencecomplete_LDADD = libibmtssutils.la libibmtss.la

evictcontrol_SOURCES = evictcontrol.c
evictcontrol_CFLAGS = $(UTILS_CFLAGS)
evictcontrol_LDADD = libibmtssutils.la libibmtss.la

flushcontext_SOURCES = flushcontext.c
flushcontext_CFLAGS = $(UTILS_CFLAGS)
flushcontext_LDADD = libibmtssutils.la libibmtss.la

getcommandauditdigest_SOURCES = getcommandauditdigest.c
getcommandauditdigest_CFLAGS = $(UTILS_CFLAGS)
getcommandauditdigest_LDADD = libibmtssutils.la libibmtss.la

getcapability_SOURCES = getcapability.c
getcapability_CFLAGS = $(UTILS_CFLAGS)
getcapability_LDADD = libibmtssutils.la libibmtss.la

getcryptolibrary_SOURCES = getcryptolibrary.c
getcryptolibrary_CFLAGS = $(UTILS_CFLAGS)
getcryptolibrary_LDADD = libibmtssutils.la libibmtss.la

getrandom_SOURCES = getrandom.c
getrandom_CFLAGS = $(UTILS_CFLAGS)
getrandom_LDADD = libibmtssutils.la libibmtss.la

gettestresult_SOURCES = gettestresult.c
gettestresult_CFLAGS = $(UTILS_CFLAGS)
gettestresult_LDADD = libibmtssutils.la libibmtss.la

getsessionauditdigest_SOURCES = getsessionauditdigest.c
getsessionauditdigest_CFLAGS = $(UTILS_CFLAGS)
getsessionauditdigest_LDADD = libibmtssutils.la libibmtss.la

gettime_SOURCES = gettime.c
gettime_CFLAGS = $(UTILS_CFLAGS)
gettime_LDADD = libibmtssutils.la libibmtss.la

hashsequencestart_SOURCES = hashsequencestart.c
hashsequencestart_CFLAGS = $(UTILS_CFLAGS)
hashsequencestart_LDADD = libibmtssutils.la libibmtss.la

hash_SOURCES = hash.c
hash_CFLAGS = $(UTILS_CFLAGS)
hash_LDADD = libibmtssutils.la libibmtss.la

hierarchycontrol_SOURCES = hierarchycontrol.c
hierarchycontrol_CFLAGS = $(UTILS_CFLAGS)
hierarchycontrol_LDADD = libibmtssutils.la libibmtss.la

hierarchychangeauth_SOURCES = hierarchychangeauth.c
hierarchychangeauth_CFLAGS = $(UTILS_CFLAGS)
hierarchychangeauth_LDADD = libibmtssutils.la libibmtss.la

hmac_SOURCES = hmac.c
hmac_CFLAGS = $(UTILS_CFLAGS)
hmac_LDADD = libibmtssutils.la libibmtss.la

hmacstart_SOURCES = hmacstart.c
hmacstart_CFLAGS = $(UTILS_CFLAGS)
hmacstart_LDADD = libibmtssutils.la libibmtss.la

import_SOURCES = import.c
import_CFLAGS = $(UTILS_CFLAGS)
import_LDADD = libibmtssutils.la libibmtss.la

importpem_SOURCES = importpem.c objecttemplates.c
importpem_CFLAGS = $(UTILS_CFLAGS)
importpem_LDADD = libibmtssutils.la libibmtss.la

load_SOURCES = load.c
load_CFLAGS = $(UTILS_CFLAGS)
load_LDADD = libibmtssutils.la libibmtss.la

loadexternal_SOURCES = loadexternal.c
loadexternal_CFLAGS = $(UTILS_CFLAGS)
loadexternal_LDADD = libibmtssutils.la libibmtss.la

makecredential_SOURCES = makecredential.c
makecredential_CFLAGS = $(UTILS_CFLAGS)
makecredential_LDADD = libibmtssutils.la libibmtss.la

nvcertify_SOURCES = nvcertify.c
nvcertify_CFLAGS = $(UTILS_CFLAGS)
nvcertify_LDADD = libibmtssutils.la libibmtss.la

nvchangeauth_SOURCES = nvchangeauth.c
nvchangeauth_CFLAGS = $(UTILS_CFLAGS)
nvchangeauth_LDADD = libibmtssutils.la libibmtss.la

nvdefinespace_SOURCES = nvdefinespace.c
nvdefinespace_CFLAGS = $(UTILS_CFLAGS)
nvdefinespace_LDADD = libibmtssutils.la libibmtss.la

nvextend_SOURCES = nvextend.c
nvextend_CFLAGS = $(UTILS_CFLAGS)
nvextend_LDADD = libibmtssutils.la libibmtss.la

nvglobalwritelock_SOURCES = nvglobalwritelock.c
nvglobalwritelock_CFLAGS = $(UTILS_CFLAGS)
nvglobalwritelock_LDADD = libibmtssutils.la libibmtss.la

nvincrement_SOURCES = nvincrement.c
nvincrement_CFLAGS = $(UTILS_CFLAGS)
nvincrement_LDADD = libibmtssutils.la libibmtss.la

nvread_SOURCES = nvread.c
nvread_CFLAGS = $(UTILS_CFLAGS)
nvread_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

nvreadlock_SOURCES = nvreadlock.c
nvreadlock_CFLAGS = $(UTILS_CFLAGS)
nvreadlock_LDADD = libibmtssutils.la libibmtss.la

nvreadpublic_SOURCES = nvreadpublic.c
nvreadpublic_CFLAGS = $(UTILS_CFLAGS)
nvreadpublic_LDADD = libibmtssutils.la libibmtss.la

nvsetbits_SOURCES = nvsetbits.c
nvsetbits_CFLAGS = $(UTILS_CFLAGS)
nvsetbits_LDADD = libibmtssutils.la libibmtss.la

nvundefinespace_SOURCES = nvundefinespace.c
nvundefinespace_CFLAGS = $(UTILS_CFLAGS)
nvundefinespace_LDADD = libibmtssutils.la libibmtss.la

nvundefinespacespecial_SOURCES = nvundefinespacespecial.c
nvundefinespacespecial_CFLAGS = $(UTILS_CFLAGS)
nvundefinespacespecial_LDADD = libibmtssutils.la libibmtss.la

nvwrite_SOURCES = nvwrite.c
nvwrite_CFLAGS = $(UTILS_CFLAGS)
nvwrite_LDADD = libibmtssutils.la libibmtss.la

nvwritelock_SOURCES = nvwritelock.c
nvwritelock_CFLAGS = $(UTILS_CFLAGS)
nvwritelock_LDADD = libibmtssutils.la libibmtss.la

objectchangeauth_SOURCES = objectchangeauth.c
objectchangeauth_CFLAGS = $(UTILS_CFLAGS)
objectchangeauth_LDADD = libibmtssutils.la libibmtss.la

pcrallocate_SOURCES = pcrallocate.c
pcrallocate_CFLAGS = $(UTILS_CFLAGS)
pcrallocate_LDADD = libibmtssutils.la libibmtss.la

pcrevent_SOURCES = pcrevent.c
pcrevent_CFLAGS = $(UTILS_CFLAGS)
pcrevent_LDADD = libibmtssutils.la libibmtss.la

pcrextend_SOURCES = pcrextend.c
pcrextend_CFLAGS = $(UTILS_CFLAGS)
pcrextend_LDADD = libibmtssutils.la libibmtss.la

pcrread_SOURCES = pcrread.c
pcrread_CFLAGS = $(UTILS_CFLAGS)
pcrread_LDADD = libibmtssutils.la libibmtss.la

pcrreset_SOURCES = pcrreset.c
pcrreset_CFLAGS = $(UTILS_CFLAGS)
pcrreset_LDADD = libibmtssutils.la libibmtss.la

policyauthorize_SOURCES = policyauthorize.c
policyauthorize_CFLAGS = $(UTILS_CFLAGS)
policyauthorize_LDADD = libibmtssutils.la libibmtss.la

policyauthvalue_SOURCES = policyauthvalue.c
policyauthvalue_CFLAGS = $(UTILS_CFLAGS)
policyauthvalue_LDADD = libibmtssutils.la libibmtss.la

policycommandcode_SOURCES = policycommandcode.c
policycommandcode_CFLAGS = $(UTILS_CFLAGS)
policycommandcode_LDADD = libibmtssutils.la libibmtss.la

policycphash_SOURCES = policycphash.c
policycphash_CFLAGS = $(UTILS_CFLAGS)
policycphash_LDADD = libibmtssutils.la libibmtss.la

policynamehash_SOURCES = policynamehash.c
policynamehash_CFLAGS = $(UTILS_CFLAGS)
policynamehash_LDADD = libibmtssutils.la libibmtss.la

policycountertimer_SOURCES = policycountertimer.c
policycountertimer_CFLAGS = $(UTILS_CFLAGS)
policycountertimer_LDADD = libibmtssutils.la libibmtss.la

policyduplicationselect_SOURCES = policyduplicationselect.c
policyduplicationselect_CFLAGS = $(UTILS_CFLAGS)
policyduplicationselect_LDADD = libibmtssutils.la libibmtss.la

policygetdigest_SOURCES = policygetdigest.c
policygetdigest_CFLAGS = $(UTILS_CFLAGS)
policygetdigest_LDADD = libibmtssutils.la libibmtss.la

policymaker_SOURCES = policymaker.c
policymaker_CFLAGS = $(UTILS_CFLAGS)
policymaker_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

policymakerpcr_SOURCES = policymakerpcr.c
policymakerpcr_CFLAGS = $(UTILS_CFLAGS)
policymakerpcr_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

policyauthorizenv_SOURCES = policyauthorizenv.c
policyauthorizenv_CFLAGS = $(UTILS_CFLAGS)
policyauthorizenv_LDADD = libibmtssutils.la libibmtss.la

policynv_SOURCES = policynv.c
policynv_CFLAGS = $(UTILS_CFLAGS)
policynv_LDADD = libibmtssutils.la libibmtss.la

policynvwritten_SOURCES = policynvwritten.c
policynvwritten_CFLAGS = $(UTILS_CFLAGS)
policynvwritten_LDADD = libibmtssutils.la libibmtss.la

policyor_SOURCES = policyor.c
policyor_CFLAGS = $(UTILS_CFLAGS)
policyor_LDADD = libibmtssutils.la libibmtss.la

policypassword_SOURCES = policypassword.c
policypassword_CFLAGS = $(UTILS_CFLAGS)
policypassword_LDADD = libibmtssutils.la libibmtss.la

policypcr_SOURCES = policypcr.c
policypcr_CFLAGS = $(UTILS_CFLAGS)
policypcr_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

policyrestart_SOURCES = policyrestart.c
policyrestart_CFLAGS = $(UTILS_CFLAGS)
policyrestart_LDADD = libibmtssutils.la libibmtss.la

policysigned_SOURCES = policysigned.c
policysigned_CFLAGS = $(UTILS_CFLAGS)
policysigned_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

policysecret_SOURCES = policysecret.c
policysecret_CFLAGS = $(UTILS_CFLAGS)
policysecret_LDADD = libibmtssutils.la libibmtss.la

policytemplate_SOURCES = policytemplate.c
policytemplate_CFLAGS = $(UTILS_CFLAGS)
policytemplate_LDADD = libibmtssutils.la libibmtss.la

policyticket_SOURCES = policyticket.c
policyticket_CFLAGS = $(UTILS_CFLAGS)
policyticket_LDADD = libibmtssutils.la libibmtss.la

quote_SOURCES = quote.c
quote_CFLAGS = $(UTILS_CFLAGS)
quote_LDADD = libibmtssutils.la libibmtss.la

powerup_SOURCES = powerup.c
powerup_CFLAGS = $(UTILS_CFLAGS)
powerup_LDADD = libibmtssutils.la libibmtss.la

readclock_SOURCES = readclock.c
readclock_CFLAGS = $(UTILS_CFLAGS)
readclock_LDADD = libibmtssutils.la libibmtss.la

readpublic_SOURCES = readpublic.c
readpublic_CFLAGS = $(UTILS_CFLAGS)
readpublic_LDADD = libibmtssutils.la libibmtss.la

returncode_SOURCES = returncode.c
returncode_CFLAGS = $(UTILS_CFLAGS)
returncode_LDADD = libibmtssutils.la libibmtss.la

rewrap_SOURCES = rewrap.c
rewrap_CFLAGS = $(UTILS_CFLAGS)
rewrap_LDADD = libibmtssutils.la libibmtss.la

rsadecrypt_SOURCES = rsadecrypt.c
rsadecrypt_CFLAGS = $(UTILS_CFLAGS)
rsadecrypt_LDADD = libibmtssutils.la libibmtss.la

rsaencrypt_SOURCES = rsaencrypt.c
rsaencrypt_CFLAGS = $(UTILS_CFLAGS)
rsaencrypt_LDADD = libibmtssutils.la libibmtss.la

sequenceupdate_SOURCES = sequenceupdate.c
sequenceupdate_CFLAGS = $(UTILS_CFLAGS)
sequenceupdate_LDADD = libibmtssutils.la libibmtss.la

sequencecomplete_SOURCES = sequencecomplete.c
sequencecomplete_CFLAGS = $(UTILS_CFLAGS)
sequencecomplete_LDADD = libibmtssutils.la libibmtss.la

setcommandcodeauditstatus_SOURCES = setcommandcodeauditstatus.c
setcommandcodeauditstatus_CFLAGS = $(UTILS_CFLAGS)
setcommandcodeauditstatus_LDADD = libibmtssutils.la libibmtss.la

setprimarypolicy_SOURCES = setprimarypolicy.c
setprimarypolicy_CFLAGS = $(UTILS_CFLAGS)
setprimarypolicy_LDADD = libibmtssutils.la libibmtss.la

shutdown_SOURCES = shutdown.c
shutdown_CFLAGS = $(UTILS_CFLAGS)
shutdown_LDADD = libibmtssutils.la libibmtss.la

sign_SOURCES = sign.c
sign_CFLAGS = $(UTILS_CFLAGS)
sign_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

startauthsession_SOURCES = startauthsession.c
startauthsession_CFLAGS = $(UTILS_CFLAGS)
startauthsession_LDADD = libibmtssutils.la libibmtss.la

startup_SOURCES = startup.c
startup_CFLAGS = $(UTILS_CFLAGS)
startup_LDADD = libibmtssutils.la libibmtss.la

stirrandom_SOURCES = stirrandom.c
stirrandom_CFLAGS = $(UTILS_CFLAGS)
stirrandom_LDADD = libibmtssutils.la libibmtss.la

unseal_SOURCES = unseal.c
unseal_CFLAGS = $(UTILS_CFLAGS)
unseal_LDADD = libibmtssutils.la libibmtss.la

verifysignature_SOURCES = verifysignature.c
verifysignature_CFLAGS = $(UTILS_CFLAGS)
verifysignature_LDADD = libibmtssutils.la libibmtss.la

zgen2phase_SOURCES = zgen2phase.c
zgen2phase_CFLAGS = $(UTILS_CFLAGS)
zgen2phase_LDADD = libibmtssutils.la libibmtss.la

signapp_SOURCES = signapp.c
signapp_CFLAGS = $(UTILS_CFLAGS)
signapp_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

writeapp_SOURCES = writeapp.c
writeapp_CFLAGS = $(UTILS_CFLAGS)
writeapp_LDADD = libibmtssutils.la libibmtss.la

timepacket_SOURCES = timepacket.c
timepacket_CFLAGS = $(UTILS_CFLAGS)
timepacket_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

createek_SOURCES = createek.c
createek_CFLAGS = $(UTILS_CFLAGS)
createek_LDADD = libibmtssutils.la libibmtss.la $(LIBCRYPTO_LIBS)

createekcert_SOURCES = createekcert.c
createekcert_CFLAGS = $(UTILS_CFLAGS)
createekcert_LDADD = libibmtssutils.la libibmtss.la

tpm2pem_SOURCES = tpm2pem.c
tpm2pem_CFLAGS = $(UTILS_CFLAGS)
tpm2pem_LDADD = libibmtssutils.la libibmtss.la

tpmpublic2eccpoint_SOURCES = tpmpublic2eccpoint.c
tpmpublic2eccpoint_CFLAGS = $(UTILS_CFLAGS)
tpmpublic2eccpoint_LDADD = libibmtssutils.la libibmtss.la

ntc2getconfig_SOURCES = ntc2getconfig.c
ntc2getconfig_CFLAGS = $(UTILS_CFLAGS)
ntc2getconfig_LDADD = libibmtssutils.la libibmtss.la

ntc2preconfig_SOURCES = ntc2preconfig.c
ntc2preconfig_CFLAGS = $(UTILS_CFLAGS)
ntc2preconfig_LDADD = libibmtssutils.la libibmtss.la

ntc2lockconfig_SOURCES = ntc2lockconfig.c
ntc2lockconfig_CFLAGS = $(UTILS_CFLAGS)
ntc2lockconfig_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

publicname_SOURCES = publicname.c
publicname_CFLAGS = $(OPENSSL_CFLAGS)
publicname_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

tpmcmd_SOURCES = tpmcmd.c
tpmcmd_CFLAGS = $(OPENSSL_CFLAGS)
tpmcmd_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

printattr_SOURCES = printattr.c
printattr_CFLAGS = $(OPENSSL_CFLAGS)
printattr_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

endif
