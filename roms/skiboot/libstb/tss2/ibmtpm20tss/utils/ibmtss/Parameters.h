/********************************************************************************/
/*										*/
/*			  Command and Response Parameter Structures		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2019				*/
/*										*/
/********************************************************************************/

/* TPM and TSS share thses structures */

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include "TPM_Types.h"

#include "ActivateCredential_fp.h"
#include "CertifyCreation_fp.h"
#include "Certify_fp.h"
#include "CertifyX509_fp.h"
#include "ChangeEPS_fp.h"
#include "ChangePPS_fp.h"
#include "ClearControl_fp.h"
#include "Clear_fp.h"
#include "ClockRateAdjust_fp.h"
#include "ClockSet_fp.h"
#include "Commit_fp.h"
#include "ContextLoad_fp.h"
#include "ContextSave_fp.h"
#include "CreatePrimary_fp.h"
#include "Create_fp.h"
#include "CreateLoaded_fp.h"
#include "DictionaryAttackLockReset_fp.h"
#include "DictionaryAttackParameters_fp.h"
#include "Duplicate_fp.h"
#include "ECC_Parameters_fp.h"
#include "ECDH_KeyGen_fp.h"
#include "ECDH_ZGen_fp.h"
#include "EC_Ephemeral_fp.h"
#include "EncryptDecrypt_fp.h"
#include "EncryptDecrypt2_fp.h"
#include "EventSequenceComplete_fp.h"
#include "EvictControl_fp.h"
#include "FlushContext_fp.h"
#include "GetCapability_fp.h"
#include "GetCommandAuditDigest_fp.h"
#include "GetRandom_fp.h"
#include "GetSessionAuditDigest_fp.h"
#include "GetTestResult_fp.h"
#include "GetTime_fp.h"
#include "HMAC_Start_fp.h"
#include "HMAC_fp.h"
#include "HashSequenceStart_fp.h"
#include "Hash_fp.h"
#include "HierarchyChangeAuth_fp.h"
#include "HierarchyControl_fp.h"
#include "Import_fp.h"
#include "IncrementalSelfTest_fp.h"
#include "LoadExternal_fp.h"
#include "Load_fp.h"
#include "MakeCredential_fp.h"
#include "NV_Certify_fp.h"
#include "NV_ChangeAuth_fp.h"
#include "NV_DefineSpace_fp.h"
#include "NV_Extend_fp.h"
#include "NV_GlobalWriteLock_fp.h"
#include "NV_Increment_fp.h"
#include "NV_ReadLock_fp.h"
#include "NV_ReadPublic_fp.h"
#include "NV_Read_fp.h"
#include "NV_SetBits_fp.h"
#include "NV_UndefineSpaceSpecial_fp.h"
#include "NV_UndefineSpace_fp.h"
#include "NV_WriteLock_fp.h"
#include "NV_Write_fp.h"
#include "ObjectChangeAuth_fp.h"
#include "PCR_Allocate_fp.h"
#include "PCR_Event_fp.h"
#include "PCR_Extend_fp.h"
#include "PCR_Read_fp.h"
#include "PCR_Reset_fp.h"
#include "PCR_SetAuthPolicy_fp.h"
#include "PCR_SetAuthValue_fp.h"
#include "PP_Commands_fp.h"
#include "PolicyAuthValue_fp.h"
#include "PolicyAuthorize_fp.h"
#include "PolicyCommandCode_fp.h"
#include "PolicyCounterTimer_fp.h"
#include "PolicyCpHash_fp.h"
#include "PolicyDuplicationSelect_fp.h"
#include "PolicyGetDigest_fp.h"
#include "PolicyLocality_fp.h"
#include "PolicyNV_fp.h"
#include "PolicyAuthorizeNV_fp.h"
#include "PolicyNvWritten_fp.h"
#include "PolicyNameHash_fp.h"
#include "PolicyOR_fp.h"
#include "PolicyPCR_fp.h"
#include "PolicyPassword_fp.h"
#include "PolicyPhysicalPresence_fp.h"
#include "PolicyRestart_fp.h"
#include "PolicySecret_fp.h"
#include "PolicySigned_fp.h"
#include "PolicyTemplate_fp.h"
#include "PolicyTicket_fp.h"
#include "Quote_fp.h"
#include "RSA_Decrypt_fp.h"
#include "RSA_Encrypt_fp.h"
#include "ReadClock_fp.h"
#include "ReadPublic_fp.h"
#include "Rewrap_fp.h"
#include "SelfTest_fp.h"
#include "SequenceComplete_fp.h"
#include "SequenceUpdate_fp.h"
#include "SetAlgorithmSet_fp.h"
#include "SetCommandCodeAuditStatus_fp.h"
#include "SetPrimaryPolicy_fp.h"
#include "Shutdown_fp.h"
#include "Sign_fp.h"
#include "StartAuthSession_fp.h"
#include "Startup_fp.h"
#include "StirRandom_fp.h"
#include "TestParms_fp.h"
#include "Unseal_fp.h"
#include "VerifySignature_fp.h"
#include "ZGen_2Phase_fp.h"
#include "NTC_fp.h"

#include <ibmtss/Parameters12.h>

typedef union {
    ActivateCredential_In         ActivateCredential;
    CertifyCreation_In            CertifyCreation;
    Certify_In                    Certify;
    ChangeEPS_In                  ChangeEPS;
    ChangePPS_In                  ChangePPS;
    ClearControl_In               ClearControl;
    Clear_In                      Clear;
    ClockRateAdjust_In            ClockRateAdjust;
    ClockSet_In                   ClockSet;
    Commit_In                     Commit;
    ContextLoad_In                ContextLoad;
    ContextSave_In                ContextSave;
    CreatePrimary_In              CreatePrimary;
    Create_In                     Create;
    DictionaryAttackLockReset_In  DictionaryAttackLockReset;
    DictionaryAttackParameters_In DictionaryAttackParameters;
    Duplicate_In                  Duplicate;
    ECC_Parameters_In             ECC_Parameters;
    ECDH_KeyGen_In                ECDH_KeyGen;
    ECDH_ZGen_In                  ECDH_ZGen;
    EC_Ephemeral_In               EC_Ephemeral;
    EncryptDecrypt_In             EncryptDecrypt;
    EventSequenceComplete_In      EventSequenceComplete;
    EvictControl_In               EvictControl;
    FlushContext_In               FlushContext;
    GetCapability_In              GetCapability;
    GetCommandAuditDigest_In      GetCommandAuditDigest;
    GetRandom_In                  GetRandom;
    GetSessionAuditDigest_In      GetSessionAuditDigest;
    GetTime_In                    GetTime;
    HMAC_In                       HMAC;
    HMAC_Start_In                 HMAC_Start;
    HashSequenceStart_In          HashSequenceStart;
    Hash_In                       Hash;
    HierarchyChangeAuth_In        HierarchyChangeAuth;
    HierarchyControl_In           HierarchyControl;
    Import_In                     Import;
    IncrementalSelfTest_In        IncrementalSelfTest;
    LoadExternal_In               LoadExternal;
    Load_In                       Load;
    MakeCredential_In             MakeCredential;
    NV_Certify_In                 NV_Certify;
    NV_ChangeAuth_In              NV_ChangeAuth;
    NV_DefineSpace_In             NV_DefineSpace;
    NV_Extend_In                  NV_Extend;
    NV_GlobalWriteLock_In         NV_GlobalWriteLock;
    NV_Increment_In               NV_Increment;
    NV_ReadLock_In                NV_ReadLock;
    NV_ReadPublic_In              NV_ReadPublic;
    NV_Read_In                    NV_Read;
    NV_SetBits_In                 NV_SetBits;
    NV_UndefineSpaceSpecial_In    NV_UndefineSpaceSpecial;
    NV_UndefineSpace_In           NV_UndefineSpace;
    NV_WriteLock_In               NV_WriteLock;
    NV_Write_In                   NV_Write;
    ObjectChangeAuth_In           ObjectChangeAuth;
    PCR_Allocate_In               PCR_Allocate;
    PCR_Event_In                  PCR_Event;
    PCR_Extend_In                 PCR_Extend;
    PCR_Read_In                   PCR_Read;
    PCR_Reset_In                  PCR_Reset;
    PCR_SetAuthPolicy_In          PCR_SetAuthPolicy;
    PCR_SetAuthValue_In           PCR_SetAuthValue;
    PP_Commands_In                PP_Commands;
    PolicyAuthValue_In            PolicyAuthValue;
    PolicyAuthorize_In            PolicyAuthorize;
    PolicyCommandCode_In          PolicyCommandCode;
    PolicyCounterTimer_In         PolicyCounterTimer;
    PolicyCpHash_In               PolicyCpHash;
    PolicyDuplicationSelect_In    PolicyDuplicationSelect;
    PolicyGetDigest_In            PolicyGetDigest;
    PolicyLocality_In             PolicyLocality;
    PolicyNV_In                   PolicyNV;
    PolicyAuthorizeNV_In          PolicyAuthorizeNV;
    PolicyNameHash_In             PolicyNameHash;
    PolicyOR_In                   PolicyOR;
    PolicyPCR_In                  PolicyPCR;
    PolicyPassword_In             PolicyPassword;
    PolicyPhysicalPresence_In     PolicyPhysicalPresence;
    PolicyRestart_In              PolicyRestart;
    PolicySecret_In               PolicySecret;
    PolicySigned_In               PolicySigned;
    PolicyTicket_In               PolicyTicket;
    Quote_In                      Quote;
    RSA_Decrypt_In                RSA_Decrypt;
    RSA_Encrypt_In                RSA_Encrypt;
    ReadPublic_In                 ReadPublic;
    Rewrap_In                     Rewrap;
    SelfTest_In                   SelfTest;
    SequenceComplete_In           SequenceComplete;
    SequenceUpdate_In             SequenceUpdate;
    SetAlgorithmSet_In            SetAlgorithmSet;
    SetCommandCodeAuditStatus_In  SetCommandCodeAuditStatus;
    SetPrimaryPolicy_In           SetPrimaryPolicy;
    Shutdown_In                   Shutdown;
    Sign_In                       Sign;
    StartAuthSession_In           StartAuthSession;
    Startup_In                    Startup;
    StirRandom_In                 StirRandom;
    TestParms_In                  TestParms;
    Unseal_In                     Unseal;
    VerifySignature_In            VerifySignature;
    ZGen_2Phase_In                ZGen_2Phase;

    ActivateIdentity_In		ActivateIdentity;
    CreateWrapKey_In		CreateWrapKey;
    CreateEndorsementKeyPair_In	CreateEndorsementKeyPair;
    Extend_In			Extend;
    FlushSpecific_In		FlushSpecific;
    GetCapability12_In		GetCapability12;
    MakeIdentity_In		MakeIdentity;
    NV_DefineSpace12_In		NV_DefineSpace12;
    NV_ReadValue_In		NV_ReadValue;
    NV_ReadValueAuth_In		NV_ReadValueAuth;
    NV_WriteValue_In		NV_WriteValue;
    NV_WriteValueAuth_In	NV_WriteValueAuth;
    OSAP_In			OSAP;
    OwnerReadInternalPub_In	OwnerReadInternalPub;
    OwnerSetDisable_In		OwnerSetDisable;
    LoadKey2_In			LoadKey2;
    PcrRead12_In		PcrRead12;
    PCR_Reset12_In		PCR_Reset12;
    Quote2_In			Quote2;
    ReadPubek_In		ReadPubek;
    Sign12_In			Sign12;
    Startup12_In		Startup12;
    TakeOwnership_In		TakeOwnership;
} COMMAND_PARAMETERS;

typedef union
{
    ActivateCredential_Out         ActivateCredential;
    CertifyCreation_Out            CertifyCreation;
    Certify_Out                    Certify;
    Commit_Out                     Commit;
    ContextLoad_Out                ContextLoad;
    ContextSave_Out                ContextSave;
    CreatePrimary_Out              CreatePrimary;
    Create_Out                     Create;
    Duplicate_Out                  Duplicate;
    ECC_Parameters_Out             ECC_Parameters;
    ECDH_KeyGen_Out                ECDH_KeyGen;
    ECDH_ZGen_Out                  ECDH_ZGen;
    EC_Ephemeral_Out               EC_Ephemeral;
    EncryptDecrypt_Out             EncryptDecrypt;
    EventSequenceComplete_Out      EventSequenceComplete;
    GetCapability_Out              GetCapability;
    GetCommandAuditDigest_Out      GetCommandAuditDigest;
    GetRandom_Out                  GetRandom;
    GetSessionAuditDigest_Out      GetSessionAuditDigest;
    GetTestResult_Out              GetTestResult;
    GetTime_Out                    GetTime;
    HMAC_Out                       HMAC;
    HMAC_Start_Out                 HMAC_Start;
    HashSequenceStart_Out          HashSequenceStart;
    Hash_Out                       Hash;
    Import_Out                     Import;
    IncrementalSelfTest_Out        IncrementalSelfTest;
    LoadExternal_Out               LoadExternal;
    Load_Out                       Load;
    MakeCredential_Out             MakeCredential;
    NV_Certify_Out                 NV_Certify;
    NV_ReadPublic_Out              NV_ReadPublic;
    NV_Read_Out                    NV_Read;
    ObjectChangeAuth_Out           ObjectChangeAuth;
    PCR_Allocate_Out               PCR_Allocate;
    PCR_Event_Out                  PCR_Event;
    PCR_Read_Out                   PCR_Read;
    PolicyGetDigest_Out            PolicyGetDigest;
    PolicySecret_Out               PolicySecret;
    PolicySigned_Out               PolicySigned;
    Quote_Out                      Quote;
    RSA_Decrypt_Out                RSA_Decrypt;
    RSA_Encrypt_Out                RSA_Encrypt;
    ReadClock_Out                  ReadClock;
    ReadPublic_Out                 ReadPublic;
    Rewrap_Out                     Rewrap;
    SequenceComplete_Out           SequenceComplete;
    Sign_Out                       Sign;
    StartAuthSession_Out           StartAuthSession;
    Unseal_Out                     Unseal;
    VerifySignature_Out            VerifySignature;
    ZGen_2Phase_Out                ZGen_2Phase;

    ActivateIdentity_Out		ActivateIdentity;
    CreateWrapKey_Out			CreateWrapKey;
    CreateEndorsementKeyPair_Out	CreateEndorsementKeyPair;
    Extend_Out				Extend;
    GetCapability12_Out			GetCapability12;
    MakeIdentity_Out			MakeIdentity;
    NV_ReadValue_Out			NV_ReadValue;
    NV_ReadValueAuth_Out		NV_ReadValueAuth;
    OIAP_Out				OIAP;
    OSAP_Out				OSAP;
    OwnerReadInternalPub_Out		OwnerReadInternalPub;
    LoadKey2_Out			LoadKey2;
    PcrRead12_Out			PcrRead12;
    Quote2_Out				Quote2;
    ReadPubek_Out			ReadPubek;
    Sign12_Out				Sign12;
    TakeOwnership_Out			TakeOwnership;
} RESPONSE_PARAMETERS;

#endif
