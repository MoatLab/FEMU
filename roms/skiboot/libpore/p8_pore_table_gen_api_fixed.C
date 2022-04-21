/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/p8_pore_table_gen_api_fixed.C $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2013,2014                        */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */
// $Id: p8_pore_table_gen_api_fixed.C,v 1.15 2014/05/30 20:31:24 cmolsen Exp $
//
/*------------------------------------------------------------------------------*/
/* *! (C) Copyright International Business Machines Corp. 2012                  */
/* *! All Rights Reserved -- Property of IBM                                    */
/* *! ***  ***                                                  */
/*------------------------------------------------------------------------------*/
/* *! TITLE :       p8_pore_table_gen_api_fixed.C                               */
/* *! DESCRIPTION : PORE SLW table generaion APIs                               */
/* *! OWNER NAME :  Michael Olsen            Email: cmolsen@us.ibm.com          */
//
/* *! USAGE :       To build for PHYP command-line -                            */
/*                  buildecmdprcd   -C "p8_pore_table_gen_api_fixed.C"   -c "p8_pore_table_static_data.c,sbe_xip_image.c,pore_inline_assembler.c"  -u "SLW_COMMAND_LINE_RAM"  p8_pore_table_gen_api_fixed_main.C                                                    */
//
/* *! COMMENTS :    - The DYNAMIC_RAM_TABLE_PPD was dropped in v1.12 of this    */ 
/*                    code. See v1.12 for explanation and code implementation.  */
//
/*------------------------------------------------------------------------------*/

#define __P8_PORE_TABLE_GEN_API_C
#include <p8_delta_scan_rw.h>
#include <p8_pore_api_custom.h>
#include <p8_pore_table_gen_api.H>

/*
// io_image -      pointer to SLW image
// i_modeBuild -   0: HB/IPL mode, 1: PHYP/Rebuild mode, 2: SRAM mode.
// i_regName -     unswizzled enum SPR value (NOT a name)
// i_regData -     data to write
// i_coreIndex -   core ID = [0:15]
// i_threadIndex - thread to operate on = [0:7]. 
*/
uint32_t p8_pore_gen_cpureg_fixed(  void      *io_image,
                              uint8_t   i_modeBuild,
                              uint32_t  i_regName, 
                              uint64_t  i_regData, 
                              uint32_t  i_coreId,
                              uint32_t  i_threadId)
{
  uint32_t  rc=0, rcLoc=0, iCount=0;
  int       i=0, iReg=-1;
  uint64_t  xipSlwRamSection;
  void      *hostSlwRamSection;
  void      *hostSlwSectionFixed;
  uint64_t  xipRamTableThis;
  void      *hostRamVector;
  void      *hostRamTableThis=NULL;
  void      *hostRamEntryThis=NULL, *hostRamEntryNext=NULL;
  uint8_t   bNewTable=0, bFound=0;
  uint8_t   bEntryEnd=1, headerType=0;
  SbeXipSection  xipSection;
  SbeXipItem    xipTocItem;
  RamTableEntry ramEntryThis, *ramEntryNext;
  uint32_t  sprSwiz=0;
  uint8_t 	bReplaceEntry=0;
  uint32_t	headerNext=0;
  uint32_t	instrNext=0;
	

  // -------------------------------------------------------------------------
  // Validate Ramming parameters.
  //
  // ...check mode build
  if (i_modeBuild>P8_SLW_MODEBUILD_MAX_VALUE)  {
    MY_ERR("modeBuild=%i invalid. Valid range is [0;%i].",
      i_modeBuild,P8_SLW_MODEBUILD_MAX_VALUE);
    rcLoc = 1;
  }
  // ...check register value
  bFound = 0;
  for (i=0;i<SLW_SPR_REGS_SIZE;i++)  {
    if (i_regName==SLW_SPR_REGS[i].value)  {
      bFound = 1;
      iReg = i;
      break;
    }
  }
  if (!bFound)  {
    MY_ERR("Register value = %i is not supported.\n",i_regName);
    MY_ERR("The following registers are supported:\n");
    for (i=0;i<SLW_SPR_REGS_SIZE;i++)
      MY_ERR("\t(%s,%i)\n",SLW_SPR_REGS[i].name,SLW_SPR_REGS[i].value);
    rcLoc = 1;
  }
  // ...check core ID
  if (i_coreId>=SLW_MAX_CORES)  {
    MY_ERR("Core ID = %i is not within valid range of [0;%i]\n",i_coreId,SLW_MAX_CORES-1);
    rcLoc = 1;
  }
  // ...check thread ID
  // - ensure it's zero if SPR is not thread scoped, i.e. if SPR is core scoped.
  // - error out if threadId exceed max num of threads.
  if (i_regName!=P8_SPR_HSPRG0 && i_regName!=P8_SPR_LPCR && i_regName!=P8_MSR_MSR)  {
    i_threadId = 0;
  }
  if (i_threadId>=SLW_CORE_THREADS)  {
    MY_ERR("Thread ID = %i is not within valid range of [0;%i]\n",i_threadId,SLW_CORE_THREADS-1);
    rcLoc = 1;
  }
  if (rcLoc)
    return IMGBUILD_ERR_RAM_INVALID_PARM;
  rcLoc = 0;
  
  // -------------------------------------------------------------------------
  // Check slw section location and size. (Mainly needed for fixed image.)
  //
  if (i_modeBuild==P8_SLW_MODEBUILD_IPL ||
      i_modeBuild==P8_SLW_MODEBUILD_REBUILD)  {  // Fixed image.
    hostSlwSectionFixed = (void*)( (uintptr_t)io_image + 
                                   FIXED_SLW_IMAGE_SIZE -
                                   FIXED_FFDC_SECTION_SIZE -
                                   FIXED_SLW_SECTION_SIZE );
    // Even though we shouldn't call this api during a rebuild, it should be 
    // safe to do so in this particular case since none of the info requested
    // is supposed to be moved during a rebuild.
    rc = sbe_xip_get_section( io_image, SBE_XIP_SECTION_SLW, &xipSection);
    if (rc)  {
      MY_ERR("Probably invalid section name for SBE_XIP_SECTION_SLW.\n");
      return IMGBUILD_ERR_GET_SECTION;
    }
    hostSlwRamSection = (void*)((uintptr_t)io_image + xipSection.iv_offset);
    if (hostSlwSectionFixed!=hostSlwRamSection)  {
      MY_ERR("hostSlwSectionFixed != hostSlwRamSection(from image api).\n");
      return IMGBUILD_ERR_RAM_HDRS_NOT_SYNCED;
    }
    else  {
      MY_INF("hostSlwSectionFixed == hostSlwRamSection(from image api).\n");
    }
  }
  else  {  // SRAM non-fixed image.
    rc = sbe_xip_get_section( io_image, SBE_XIP_SECTION_SLW, &xipSection);
    if (rc)  {
      MY_ERR("Probably invalid section name for SBE_XIP_SECTION_SLW.\n");
      return IMGBUILD_ERR_GET_SECTION;
    }
    hostSlwRamSection = (void*)((uintptr_t)io_image + xipSection.iv_offset);
    sbe_xip_host2pore( io_image, hostSlwRamSection, &xipSlwRamSection);
  }

  // -------------------------------------------------------------------------
  // Cross check SPR register and table defines
  //
  if (SLW_SPR_REGS_SIZE!=(SLW_MAX_CPUREGS_CORE+SLW_MAX_CPUREGS_THREADS))  {
    MY_ERR("Defines in *.H header file not in sync.\n");
    return IMGBUILD_ERR_RAM_HDRS_NOT_SYNCED;
  }
  if (xipSection.iv_size!=FIXED_SLW_SECTION_SIZE)  {
    MY_ERR("Fixed SLW table size in *.H header file differs from SLW section size in image.\n"); 
    MY_ERR("Check code or image version.\n");
    return IMGBUILD_ERR_RAM_HDRS_NOT_SYNCED;
  }

  // -------------------------------------------------------------------------
  // Summarize parameters and checking results.
  //
  MY_INF("Input parameter checks - OK\n");
  MY_INF("\tMode build= %i\n",i_modeBuild);
  MY_INF("\tRegister  = (%s,%i)\n",SLW_SPR_REGS[iReg].name,SLW_SPR_REGS[iReg].value);
  MY_INF("\tCore ID   = %i\n",i_coreId);
  MY_INF("\tThread ID = %i\n",i_threadId);
  MY_INF("Image validation and size checks - OK\n");
  MY_INF("\tSLW section size=  %i\n",xipSection.iv_size);
  
  // -------------------------------------------------------------------------
  // Locate RAM vector and locate RAM table associated with "This" core ID.
  //
  if (i_modeBuild==P8_SLW_MODEBUILD_IPL ||
      i_modeBuild==P8_SLW_MODEBUILD_REBUILD)  {  // Fixed image.
    hostRamTableThis = (void*)( (uintptr_t)io_image +
                                FIXED_SLW_IMAGE_SIZE -
                                FIXED_FFDC_SECTION_SIZE -
                                FIXED_SLW_SECTION_SIZE +
                                SLW_RAM_TABLE_SPACE_PER_CORE*i_coreId );
    if (*(uintptr_t*)hostRamTableThis)  {  // Table content NOT empty.
      bNewTable = 0;                       // So, NOT new table.
    }
    else  {                                // Table content empty.
      bNewTable = 1;                       // So, new table.
    }
  }
  else  {                 // SRAM non-fixed image.
    rc = sbe_xip_find( io_image, SLW_HOST_REG_VECTOR_TOC_NAME, &xipTocItem);
    if (rc)  {
      MY_ERR("Probably invalid key word for SLW_HOST_REG_VECTOR_TOC_NAME.\n");
      return IMGBUILD_ERR_KEYWORD_NOT_FOUND;
    }
    sbe_xip_pore2host( io_image, xipTocItem.iv_address, &hostRamVector);
    xipRamTableThis = myRev64(*((uint64_t*)hostRamVector + i_coreId));
    if (xipRamTableThis)  {
      sbe_xip_pore2host( io_image, xipRamTableThis, &hostRamTableThis);
      bNewTable = 0;
    }
    else  {
      hostRamTableThis = (void*)( (uintptr_t)hostSlwRamSection + 
                                  SLW_RAM_TABLE_SPACE_PER_CORE*i_coreId );
      bNewTable = 1;
    }
  }


	// -------------------------------------------------------------------------
  // Create most of the RAM entry, so it can be used to find a potential existing entry to 
	// replace. Postpone decision about bEntryEnd and assume its zero for now (not end). 
  //
  if (i_regName==P8_MSR_MSR)  {
    // ...make the MSR header
    headerType = 0x1; // MTMSRD header.
    ramEntryThis.header = ( ((uint32_t)headerType) << RAM_HEADER_TYPE_START_C   & RAM_HEADER_TYPE_MASK_C )   |
                          (            i_threadId  << RAM_HEADER_THREAD_START_C & RAM_HEADER_THREAD_MASK_C );
    // ...make the MSR instr
    ramEntryThis.instr =  RAM_MTMSRD_INSTR_TEMPL_C;
  }
  else  {
    // ...make the SPR header
    headerType = 0x0; // MTSPR header.
    ramEntryThis.header = ( ((uint32_t)headerType) << RAM_HEADER_TYPE_START_C   & RAM_HEADER_TYPE_MASK_C )   |
                          (            i_regName   << RAM_HEADER_SPRN_START_C   & RAM_HEADER_SPRN_MASK_C )   |
                          (            i_threadId  << RAM_HEADER_THREAD_START_C & RAM_HEADER_THREAD_MASK_C );
    // ...make the SPR instr 
    sprSwiz = i_regName>>5 | (i_regName & 0x0000001f)<<5;
    if (sprSwiz!=SLW_SPR_REGS[iReg].swizzled)  {
      MY_ERR("Inconsistent swizzle rules implemented. Check code. Dumping data.\n");
      MY_ERR("\tsprSwiz (on-the-fly-calc)=%i\n",sprSwiz);
      MY_ERR("\tSLW_SPR_REGS[%i].swizzled=%i\n",iReg,SLW_SPR_REGS[iReg].swizzled);
      return IMGBUILD_ERR_RAM_CODE;
    }
    ramEntryThis.instr =  RAM_MTSPR_INSTR_TEMPL_C | ( ( sprSwiz<<RAM_MTSPR_SPR_START_C ) & RAM_MTSPR_SPR_MASK_C );
  }
  // ...make the data
  ramEntryThis.data  = i_regData;



  // -------------------------------------------------------------------------
  // Determine insertion point of new RAM entry, hostRamEntryThis.  The possibilities are:
	// - New table => First entry
	// - Existing Ram entry => Replace said entry
	// - Existing table, new Ram entry => Last entry
  //
	bReplaceEntry = 0;
  if (bNewTable)  {
    // Append to beginning of agreed upon static Ram table position for this coreId.
    bEntryEnd = 1;
	  ramEntryThis.header = ( ((uint32_t)bEntryEnd)  << RAM_HEADER_END_START_C    & RAM_HEADER_END_MASK_C )    |
														ramEntryThis.header;
    hostRamEntryThis = hostRamTableThis;
    if (i_modeBuild==P8_SLW_MODEBUILD_SRAM)  {
      // Update RAM vector (since it is currently NULL)
      *((uint64_t*)hostRamVector + i_coreId) = 
                           myRev64( xipSlwRamSection + SLW_RAM_TABLE_SPACE_PER_CORE*i_coreId );
    }
  }
  else  {
		// Append at end of existing Ram table for this coreId
		//   or
    // Replace an existing Ram entry
    hostRamEntryNext = hostRamTableThis;
    ramEntryNext = (RamTableEntry*)hostRamEntryNext;
		headerNext = myRev32(ramEntryNext->header);
		instrNext = myRev32(ramEntryNext->instr);
    iCount = 1;
		// Examine all entries, except last entry.
    while ((headerNext & RAM_HEADER_END_MASK_C)==0 && bReplaceEntry==0)  {
      if (iCount>=SLW_MAX_CPUREGS_OPS)  {
        MY_ERR("Bad table! Header end bit not found and RAM table full (=%i entries).\n",SLW_MAX_CPUREGS_OPS);
        return IMGBUILD_ERR_RAM_TABLE_END_NOT_FOUND;
      }
			if (ramEntryThis.header==headerNext && ramEntryThis.instr==instrNext)  {
				// Its a replacement. Stop searching. Go do the replacement.
				bReplaceEntry = 1;
		    hostRamEntryThis = hostRamEntryNext;
			}
			else  {
      	hostRamEntryNext = (void*)((uint8_t*)hostRamEntryNext + XIPSIZE_RAM_ENTRY);
      	ramEntryNext = (RamTableEntry*)hostRamEntryNext;
				headerNext = myRev32(ramEntryNext->header);
				instrNext = myRev32(ramEntryNext->instr);
      	iCount++;
			}
    }
		if (bReplaceEntry==0)  {
			// Examine the last entry.
   	 	if (headerNext & RAM_HEADER_END_MASK_C)  {
	  		// Now we know for sure that our new Ram entry will also be the last, either as a 
				// replace or append. So put the end bit into the new entry.
				bEntryEnd = 1;
			  ramEntryThis.header = ( ((uint32_t)bEntryEnd)  << RAM_HEADER_END_START_C    & RAM_HEADER_END_MASK_C )    |
																ramEntryThis.header;
				// Determine if to replace or append.
				if (ramEntryThis.header==headerNext && ramEntryThis.instr==instrNext)  {
					// Its a replacement. And it would be legal to replace the very last Ram in a completely full table.
  	 	  	if (iCount<=SLW_MAX_CPUREGS_OPS)  {
						bReplaceEntry = 1;
				    hostRamEntryThis = hostRamEntryNext;
   		  	}
   	  		else  {
   	    		MY_ERR("RAM table is full. Max %i entries allowed.\n",SLW_MAX_CPUREGS_OPS);
   	    		return IMGBUILD_ERR_RAM_TABLE_FULL;
	  	  	}
				}
				else  {
					// Its an append. Make sure there's room for one more Ram entry.
  	 	  	if (iCount<SLW_MAX_CPUREGS_OPS)  {
						// Zero out the end bit in last entrys header (which will now be 2nd last).
		     	  ramEntryNext->header = ramEntryNext->header & myRev32(~RAM_HEADER_END_MASK_C);
				    hostRamEntryThis = (void*)((uint8_t*)hostRamEntryNext + XIPSIZE_RAM_ENTRY);
   		  	}
   	  		else  {
   	    		MY_ERR("RAM table is full. Max %i entries allowed.\n",SLW_MAX_CPUREGS_OPS);
   	    		return IMGBUILD_ERR_RAM_TABLE_FULL;
	  	  	}
 	    	}
			}
 	   	else  {
 	   	  MY_ERR("We should never get here. Check code. Dumping data:\n");
 	   	  MY_ERR("myRev32(ramEntryNext->header) = 0x%08x\n",myRev32(ramEntryNext->header));
 	   	  MY_ERR("RAM_HEADER_END_MASK_C         = 0x%08x\n",RAM_HEADER_END_MASK_C);
 	   	  return IMGBUILD_ERR_RAM_CODE;
 	   	}
		}
  }


  // Summarize new table entry data
  MY_INF("New table entry data (host format):\n");
  MY_INF("\theader = 0x%08x\n",ramEntryThis.header);
  MY_INF("\tinstr  = 0x%08x\n",ramEntryThis.instr);
  MY_INF("\tdata   = 0x%016llx\n",ramEntryThis.data);

  // -------------------------------------------------------------------------
  // Insert the new RAM entry into the table in BE format.
  //
  ramEntryNext = (RamTableEntry*)hostRamEntryThis;
  // ...some redundant checking
  if (bNewTable)  {
    // For any new table, the insertion location should be clean. We check for this here.
    if (myRev32(ramEntryNext->header)!=0)  {
      MY_ERR("WARNING : Table entry location should be empty for a new table. Check code and image. Dumping data:\n");
      MY_ERR("\theader = 0x%08x\n",myRev32(ramEntryNext->header));
      MY_ERR("\tinstr  = 0x%08x\n",myRev32(ramEntryNext->instr));
      MY_ERR("\tdata   = 0x%016llx\n",myRev64(ramEntryNext->data));
      rc = IMGBUILD_WARN_RAM_TABLE_CONTAMINATION;
    }
  }
	// ..insert the new Ram entry.
  ramEntryNext->header = myRev32(ramEntryThis.header);
  ramEntryNext->instr  = myRev32(ramEntryThis.instr);
  ramEntryNext->data   = myRev64(ramEntryThis.data);

  return rc;
}


/*
// io_image -    Pointer to SLW image.
// i_modeBuild - 0: HB/IPL mode, 1: PHYP/Rebuild mode, 2: SRAM mode. 
// i_scomAddr -  Scom address.
// i_coreId -    The core ID [0:15].
// i_scomData -  Data to write to scom register.
// i_operation - What to do with the scom addr and data.
// i_section -   0: General Scoms, 1: L2 cache, 2: L3 cache.
*/
uint32_t p8_pore_gen_scom_fixed(void       *io_image,
                                uint8_t    i_modeBuild,
                                uint32_t   i_scomAddr,
                                uint32_t   i_coreId,     // [0:15] 
                                uint64_t   i_scomData,
                                uint32_t   i_operation,  // [0:7]
                                uint32_t   i_section)    // [0,1,2]
{
  uint32_t  rc=0, rcLoc=0, iEntry=0;
  uint32_t  chipletId=0;
  uint32_t  operation=0;
  uint32_t  entriesCount=0, entriesMatch=0, entriesNOP=0;
  void      *hostSlwSection;
  void      *hostSlwSectionFixed;
  uint64_t  xipScomTableThis;
  void      *hostScomVector, *hostScomTableThis;
  void      *hostScomEntryNext;       // running entry pointer
  void      *hostScomEntryMatch=NULL; // pointer to entry that matches scomAddr
  void      *hostScomEntryRET=NULL;   // pointer to first return instr after table
  void      *hostScomEntryNOP=NULL;   // pointer to first nop IIS
  uint8_t   bufIIS[XIPSIZE_SCOM_ENTRY], bufNOP[4], bufRET[4];
  SbeXipSection xipSection;
  SbeXipItem    xipTocItem;
  PoreInlineContext ctx;
  
  // -------------------------------------------------------------------------
  // Validate Scom parameters.
  //
  // ...check if valid Scom register (is there anything we can do here to check?)
  // Skipping check. We blindly trust caller.
  //
  // ...check mode build
  if (i_modeBuild>P8_SLW_MODEBUILD_MAX_VALUE)  {
    MY_ERR("modeBuild=%i invalid. Valid range is [0;%i].",
      i_modeBuild,P8_SLW_MODEBUILD_MAX_VALUE);
    rcLoc = 1;
  }
  // ...check Scom operation
  if (i_operation>P8_PORE_SCOM_LAST_OP)  {
    MY_ERR("Scom operation = %i is not within valid range of [%d;%d]\n",
      i_operation, P8_PORE_SCOM_FIRST_OP, P8_PORE_SCOM_LAST_OP);
    rcLoc = 1;
  }
  // ...check that core ID corresponds to valid chiplet ID
  chipletId = i_coreId + P8_CID_EX_LOW;
  if (chipletId<P8_CID_EX_LOW || chipletId>P8_CID_EX_HIGH)  {
    MY_ERR("Chiplet ID = 0x%02x is not within valid range of [0x%02x;0x%02x]\n",
      chipletId, P8_CID_EX_LOW, P8_CID_EX_HIGH);
    rcLoc = 1;
  }
  if (rcLoc)
    return IMGBUILD_ERR_SCOM_INVALID_PARM;
  rcLoc = 0;
 
  // -------------------------------------------------------------------------
  // Check slw section location and size. (Mainly needed for fixed image.)
  //
  if (i_modeBuild==P8_SLW_MODEBUILD_IPL ||
      i_modeBuild==P8_SLW_MODEBUILD_REBUILD)  {  // Fixed image.
    hostSlwSectionFixed = (void*)( (uintptr_t)io_image + 
                                   FIXED_SLW_IMAGE_SIZE -
                                   FIXED_FFDC_SECTION_SIZE -
                                   FIXED_SLW_SECTION_SIZE );
    // Even though we shouldn't call this api during a rebuild, it should be 
    // safe to do so in this particular case since none of the info requested
    // is supposed to be moved during a rebuild.
    rc = sbe_xip_get_section( io_image, SBE_XIP_SECTION_SLW, &xipSection);
    if (rc)  {
      MY_ERR("Probably invalid section name for SBE_XIP_SECTION_SLW.\n");
      return IMGBUILD_ERR_GET_SECTION;
    }
    hostSlwSection = (void*)((uintptr_t)io_image + xipSection.iv_offset);
    if (hostSlwSectionFixed!=hostSlwSection)  {
      MY_ERR("hostSlwSectionFixed != hostSlwSection(from image api).\n");
      return IMGBUILD_ERR_SCOM_HDRS_NOT_SYNCD;
    }
    else  {
      MY_INF("hostSlwSectionFixed == hostSlwSection(from image api).\n");
    }
  }
  else  {                 // SRAM non-fixed image.
    rc = sbe_xip_get_section( io_image, SBE_XIP_SECTION_SLW, &xipSection);
    if (rc)  {
      MY_ERR("Probably invalid section name for SBE_XIP_SECTION_SLW.\n");
      return IMGBUILD_ERR_GET_SECTION;
    }
    hostSlwSection = (void*)((uintptr_t)io_image + xipSection.iv_offset);
  }

  // -------------------------------------------------------------------------
  // Check .slw section size and cross-check w/header define.
  //
  if (xipSection.iv_size!=FIXED_SLW_SECTION_SIZE)  {
    MY_ERR("SLW table size in *.H header file (=%ld) differs from SLW section size in image (=%i).\n",FIXED_SLW_SECTION_SIZE,xipSection.iv_size);
    MY_ERR("Check code or image version.\n");
    return IMGBUILD_ERR_SCOM_HDRS_NOT_SYNCD;
  }

  // -------------------------------------------------------------------------
  // Summarize parameters and checking results.
  //
  MY_INF("Input parameter checks - OK\n");
  MY_INF("\tRegister  = 0x%08x\n",i_scomAddr);
  MY_INF("\tOperation = %i\n",i_operation);
  MY_INF("\tSection   = %i\n",i_section);
  MY_INF("\tCore ID   = %i\n",i_coreId);
  MY_INF("Image validation and size checks - OK\n");
  MY_INF("\tSLW section size=  %i\n",xipSection.iv_size);
  
  // -------------------------------------------------------------------------
  // Locate Scom vector according to i_section and then locate Scom table 
  //   associated with "This" core ID.
  //
  if (i_modeBuild==P8_SLW_MODEBUILD_IPL ||
      i_modeBuild==P8_SLW_MODEBUILD_REBUILD)  {  // Fixed image.
    switch (i_section)  {
    case P8_SCOM_SECTION_NC:
      hostScomTableThis = (void*)( (uintptr_t)hostSlwSection +
                                   SLW_RAM_TABLE_SIZE +
                                   SLW_SCOM_TABLE_SPACE_PER_CORE_NC*i_coreId );
      break;
    case P8_SCOM_SECTION_L2:
      hostScomTableThis = (void*)( (uintptr_t)hostSlwSection +
                                   SLW_RAM_TABLE_SIZE +
                                   SLW_SCOM_TABLE_SIZE_NC +
                                   SLW_SCOM_TABLE_SPACE_PER_CORE_L2*i_coreId );
      break;
    case P8_SCOM_SECTION_L3:
      hostScomTableThis = (void*)( (uintptr_t)hostSlwSection +
                                   SLW_RAM_TABLE_SIZE +
                                   SLW_SCOM_TABLE_SIZE_NC +
                                   SLW_SCOM_TABLE_SIZE_L2 +
                                   SLW_SCOM_TABLE_SPACE_PER_CORE_L3*i_coreId );
      break;
    default:
      MY_ERR("Invalid value for i_section (=%i).\n",i_section);
      MY_ERR("Valid values for i_section = [%i,%i,%i].\n",
        P8_SCOM_SECTION_NC,P8_SCOM_SECTION_L2,P8_SCOM_SECTION_L3);
      return IMGBUILD_ERR_SCOM_INVALID_SUBSECTION;
      break;
    }
  }
  else  {                 // SRAM non-fixed image.
    switch (i_section)  {
    case P8_SCOM_SECTION_NC:
      rc = sbe_xip_find( io_image, SLW_HOST_SCOM_NC_VECTOR_TOC_NAME, &xipTocItem);
      if (rc)  {
        MY_ERR("Probably invalid key word for SLW_HOST_SCOM_NC_VECTOR_TOC_NAME.\n");
        return IMGBUILD_ERR_KEYWORD_NOT_FOUND;
      }
      break;
    case P8_SCOM_SECTION_L2:
      rc = sbe_xip_find( io_image, SLW_HOST_SCOM_L2_VECTOR_TOC_NAME, &xipTocItem);
      if (rc)  {
        MY_ERR("Probably invalid key word for SLW_HOST_SCOM_L2_VECTOR_TOC_NAME.\n");
        return IMGBUILD_ERR_KEYWORD_NOT_FOUND;
      }
      break;
    case P8_SCOM_SECTION_L3:
      rc = sbe_xip_find( io_image, SLW_HOST_SCOM_L3_VECTOR_TOC_NAME, &xipTocItem);
      if (rc)  {
        MY_ERR("Probably invalid key word for SLW_HOST_SCOM_L3_VECTOR_TOC_NAME.\n");
        return IMGBUILD_ERR_KEYWORD_NOT_FOUND;
      }
      break;
    default:
      MY_ERR("Invalid value for i_section (=%i).\n",i_section);
      MY_ERR("Valid values for i_section = [%i,%i,%i].\n",
        P8_SCOM_SECTION_NC,P8_SCOM_SECTION_L2,P8_SCOM_SECTION_L3);
      return IMGBUILD_ERR_SCOM_INVALID_SUBSECTION;
    }
    MY_INF("xipTocItem.iv_address = 0x%016llx\n",xipTocItem.iv_address);
    sbe_xip_pore2host( io_image, xipTocItem.iv_address, &hostScomVector);
    MY_INF("hostScomVector = 0x%016llx\n",(uint64_t)hostScomVector);
    xipScomTableThis = myRev64(*((uint64_t*)hostScomVector + i_coreId));
    MY_INF("xipScomTableThis = 0x%016llx\n",xipScomTableThis);
    if (xipScomTableThis)  {
      sbe_xip_pore2host( io_image, xipScomTableThis, &hostScomTableThis);
    }
    else  {  // Should never be here.
      MY_ERR("Code or image bug. Scom vector table entries should never be null.\n");
      return IMGBUILD_ERR_CHECK_CODE;
    }
  }

  //
  // Determine where to place/do Scom action and if entry already exists.
  // Insertion rules:
  // - If entry doesn't exist, insert at first NOP. (Note that if you don't do
  //   this, then the table might potentially overflow since the max table size
  //   doesn't include NOP entries.)
  // - If no NOP found, insert at first RET.
  //
  
  //----------------------------------------------------------------------------
  // 1. Create search strings for addr, nop and ret.
  //----------------------------------------------------------------------------
  // Note, the following IIS will also be used in case of
  // - i_operation==append
  // - i_operation==replace
  pore_inline_context_create( &ctx, (void*)bufIIS, XIPSIZE_SCOM_ENTRY, 0, 0);
  pore_LS( &ctx, P1, chipletId);
  pore_STI( &ctx, i_scomAddr, P1, i_scomData);
  if (ctx.error  > 0)  {
    MY_ERR("pore_LS or _STI generated rc = %d", ctx.error);
    return IMGBUILD_ERR_PORE_INLINE_ASM;
  }
  pore_inline_context_create( &ctx, (void*)bufRET, 4, 0, 0);
  pore_RET( &ctx);
  if (ctx.error > 0)  {
    MY_ERR("pore_RET generated rc = %d", ctx.error);
    return IMGBUILD_ERR_PORE_INLINE_ASM;
  }
  pore_inline_context_create( &ctx, (void*)bufNOP, 4, 0, 0);
  pore_NOP( &ctx);
  if (ctx.error > 0)  {
    MY_ERR("pore_NOP generated rc = %d", ctx.error);
    return IMGBUILD_ERR_PORE_INLINE_ASM;
  }
  
  //----------------------------------------------------------------------------
  // 2. Search for addr and nop in relevant coreId table until first RET.
  //----------------------------------------------------------------------------
  // Note:
  // - We go through ALL entries until first RET instr. We MUST find a RET instr,
  //   though we don't check for overrun until later. (Could be improved.)
  // - Count number of entries, incl the NOOPs, until we find an RET.
  // - The STI(+SCOM_addr) opcode is in the 2nd word of the Scom entry.
  // - For an append operation, if a NOP is found (before a RET obviously), the 
  //   SCOM is replacing that NNNN sequence.
  hostScomEntryNext = hostScomTableThis;
  MY_INF("hostScomEntryNext (addr): 0x%016llx\n ",(uint64_t)hostScomEntryNext);
  while (memcmp(hostScomEntryNext, bufRET, sizeof(uint32_t)))  {
    entriesCount++;
    MY_INF("Number of SCOM entries: %i\n ",entriesCount);
    if (*((uint32_t*)bufIIS+1)==*((uint32_t*)hostScomEntryNext+1) && entriesMatch==0)  {// +1 skips 1st word in Scom entry (which loads the PC in an LS operation.)
      hostScomEntryMatch = hostScomEntryNext;
      entriesMatch++;
    }
    if (memcmp(hostScomEntryNext, bufNOP, sizeof(uint32_t))==0 && entriesNOP==0)  {
      hostScomEntryNOP = hostScomEntryNext;
      entriesNOP++;
    }
    hostScomEntryNext = (void*)((uintptr_t)hostScomEntryNext + XIPSIZE_SCOM_ENTRY);
  }
  hostScomEntryRET = hostScomEntryNext; // The last EntryNext is always the first RET.
  
  //----------------------------------------------------------------------------
  // 3. Qualify (translate) operation and IIS.
  //----------------------------------------------------------------------------
  if (i_operation==P8_PORE_SCOM_APPEND)  
  {
    operation = i_operation;
  }
  else if (i_operation==P8_PORE_SCOM_REPLACE)  
  {
    if (hostScomEntryMatch)
      // ... do a replace
      operation = i_operation;
    else
      // ... do an append
      operation = P8_PORE_SCOM_APPEND;
  }
  else if (i_operation==P8_PORE_SCOM_NOOP)  
  {
    // ...overwrite earlier bufIIS from the search step
    pore_inline_context_create( &ctx, (void*)bufIIS, XIPSIZE_SCOM_ENTRY, 0, 0);
    pore_NOP( &ctx);
    pore_NOP( &ctx);
    pore_NOP( &ctx);
    pore_NOP( &ctx);
    if (ctx.error > 0)  {
      MY_ERR("*** _NOP generated rc = %d", ctx.error);
      return IMGBUILD_ERR_PORE_INLINE_ASM;
    }
    operation = i_operation;
  }
  else if ( i_operation==P8_PORE_SCOM_AND        ||
            i_operation==P8_PORE_SCOM_OR )  
  {
    operation = i_operation;
  }            
  else if ( i_operation==P8_PORE_SCOM_AND_APPEND )  
  {
    if (hostScomEntryMatch)
      // ... do the AND on existing Scom
      operation = P8_PORE_SCOM_AND;
    else
      // ... do an append (this better be to an _AND register type)
      operation = P8_PORE_SCOM_APPEND;  
  }
  else if ( i_operation==P8_PORE_SCOM_OR_APPEND )  
  {
    if (hostScomEntryMatch)
      // ... do the OR on existing Scom
      operation = P8_PORE_SCOM_OR;
    else
      // ... do an append (this better be to an _OR register type)
      operation = P8_PORE_SCOM_APPEND;  
  }
  else if (i_operation==P8_PORE_SCOM_RESET)  
  {
    // ... create RNNN instruction sequence.
    pore_inline_context_create( &ctx, (void*)bufIIS, XIPSIZE_SCOM_ENTRY, 0, 0);
    pore_RET( &ctx);
    pore_NOP( &ctx);
    pore_NOP( &ctx);
    pore_NOP( &ctx);
    if (ctx.error > 0)  {
      MY_ERR("***_RET or _NOP generated rc = %d", ctx.error);
      return IMGBUILD_ERR_PORE_INLINE_ASM;
    }
    operation = i_operation;
  }
  else  
  {
    MY_ERR("Scom operation = %i is not within valid range of [%d;%d]\n",
      i_operation, P8_PORE_SCOM_FIRST_OP, P8_PORE_SCOM_LAST_OP);
    return IMGBUILD_ERR_SCOM_INVALID_PARM;
  }
  
  //----------------------------------------------------------------------------
  // 4. Check for overrun.
  //----------------------------------------------------------------------------
  // Note:
  // - An entry count exceeding the max allocated entry count will result in a code error
  //   because the allocation is based on an agreed upon max number of entries and 
  //   therefore either the code header file needs to change or the caller is not abiding 
  //   by the rules.
  // - An entry count equalling the max allocated entry count is allowed for all commands
  //   except the APPEND command, incl the translated REPLACE->APPEND, which will result 
  //   in the previously mentioned code error being returned.
  // - The table can be full but still include NOOPs. If so, we can still APPEND since
  //   we append at first occurrence of a NOOP or at the end of the table (at the RET).
  switch (i_section)  {
  case P8_SCOM_SECTION_NC:
    if ( ( (operation==P8_PORE_SCOM_APPEND && entriesCount==SLW_MAX_SCOMS_NC) &&
           hostScomEntryNOP==NULL ) ||
           entriesCount>SLW_MAX_SCOMS_NC )
    {
      MY_ERR("SCOM table NC is full. Max %i entries allowed.\n",SLW_MAX_SCOMS_NC);
      return IMGBUILD_ERR_CHECK_CODE;
    }
    break;
  case P8_SCOM_SECTION_L2:
    if ( ( (operation==P8_PORE_SCOM_APPEND && entriesCount==SLW_MAX_SCOMS_L2) &&
           hostScomEntryNOP==NULL ) ||
           entriesCount>SLW_MAX_SCOMS_L2 )
    {
      MY_ERR("SCOM table L2 is full. Max %i entries allowed.\n",SLW_MAX_SCOMS_L2);
      return IMGBUILD_ERR_CHECK_CODE;
    }
    break;
  case P8_SCOM_SECTION_L3:
    if ( ( (operation==P8_PORE_SCOM_APPEND && entriesCount==SLW_MAX_SCOMS_L3) &&
           hostScomEntryNOP==NULL ) ||
           entriesCount>SLW_MAX_SCOMS_L3 )
    {
      MY_ERR("SCOM table L3 is full. Max %i entries allowed.\n",SLW_MAX_SCOMS_L3);
      return IMGBUILD_ERR_CHECK_CODE;
    }
    break;
  default:
    MY_ERR("Invalid value for i_section (=%i).\n",i_section);
    MY_ERR("Valid values for i_section = [%i,%i,%i].\n",
        P8_SCOM_SECTION_NC,P8_SCOM_SECTION_L2,P8_SCOM_SECTION_L3);
    return IMGBUILD_ERR_SCOM_INVALID_SUBSECTION;
  }


  // ---------------------------------------------------------------------------
  // 5.  Insert the SCOM.
  // ---------------------------------------------------------------------------
  // Assuming pre-allocated Scom table (after pre-allocated Ram table):
  // - Table is pre-filled with RNNN ISS.
  // - Each core Id has dedicated space, uniformly distributed by SLW_MAX_SCOMS_NC*
  //   XIPSIZE_SCOM_ENTRY.
  // - Remember to check for more than SLW_MAX_SCOMS_NC entries!
  switch (operation)  {

  case P8_PORE_SCOM_APPEND:  // Append a Scom at first occurring NNNN or RNNN,  
    if (hostScomEntryNOP)  {
      // ... replace the NNNN
      MY_INF("Append at NOP\n");
      memcpy(hostScomEntryNOP,(void*)bufIIS,XIPSIZE_SCOM_ENTRY);
    }
    else if (hostScomEntryRET)  {
      // ... replace the RNNN
      MY_INF("Append at RET\n");
      memcpy(hostScomEntryRET,(void*)bufIIS,XIPSIZE_SCOM_ENTRY);
    }
    else  {
      // We should never be here.
      MY_ERR("In case=_SCOM_APPEND: EntryRET=NULL is impossible. Check code.\n");
      return IMGBUILD_ERR_CHECK_CODE;
    }
    break;
  case P8_PORE_SCOM_REPLACE: // Replace existing Scom with new data
    if (hostScomEntryMatch)  {
      // ... do a vanilla replace
      MY_INF("Replace existing Scom\n");
      memcpy(hostScomEntryMatch,(void*)bufIIS,XIPSIZE_SCOM_ENTRY);
    }
    else  {
      // We should never be here.
      MY_ERR("In case=_SCOM_REPLACE: EntryMatch=NULL is impossible. Check code.\n");
      return IMGBUILD_ERR_CHECK_CODE;
    }
    break;
  case P8_PORE_SCOM_NOOP:
    if (hostScomEntryMatch)  {
      // ... do a vanilla replace
      MY_INF("Replace existing Scom w/NOPs\n");
      memcpy(hostScomEntryMatch,(void*)bufIIS,XIPSIZE_SCOM_ENTRY);
    }
    else  {
      MY_ERR("No Scom entry found to replace NOOPs with.\n");
      return IMGBUILD_ERR_SCOM_ENTRY_NOT_FOUND;
    }
    break;
  case P8_PORE_SCOM_OR:      // Overlay Scom data onto existing data by bitwise OR
    if (hostScomEntryMatch)  {
      // ... do an OR on the data (which is the 2nd DWord in the entry)
      MY_INF("Overlay existing Scom - OR case\n");
      *((uint64_t*)hostScomEntryMatch+1) = 
        *((uint64_t*)hostScomEntryMatch+1) | myRev64(i_scomData);
    }
    else  { 
      MY_ERR("No Scom entry found to do OR operation with.\n");
      return IMGBUILD_ERR_SCOM_ENTRY_NOT_FOUND;
    }
    break;
  case P8_PORE_SCOM_AND:     // Overlay Scom data onto existing data by bitwise AND
    if (hostScomEntryMatch)  {
      // ... do an AND on the data (which is the 2nd DWord in the entry)
      MY_INF("Overlay existing Scom - AND case\n");
      *((uint64_t*)hostScomEntryMatch+1) = 
        *((uint64_t*)hostScomEntryMatch+1) & myRev64(i_scomData);
    }
    else  { 
      MY_ERR("No Scom entry found to do AND operation with.\n");
      return IMGBUILD_ERR_SCOM_ENTRY_NOT_FOUND;
    }
    break;
  case P8_PORE_SCOM_RESET:   // Reset (delete) table. Refill w/RNNN ISS.
    MY_INF("Reset table\n");
    hostScomEntryNext = hostScomTableThis;
    for ( iEntry=0; iEntry<entriesCount; iEntry++)  {
      memcpy( hostScomEntryNext, (void*)bufIIS, XIPSIZE_SCOM_ENTRY);
      hostScomEntryNext = (void*)((uintptr_t)hostScomEntryNext + XIPSIZE_SCOM_ENTRY);
    }
    break;
  default:
    MY_ERR("Impossible value of operation (=%i). Check code.\n",operation);
    return IMGBUILD_ERR_CHECK_CODE;
  
  }  // End of switch(operation)

  return rc;
}
