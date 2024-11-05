#ifndef SBL_ERRCODES_H
#define SBL_ERRCODES_H

enum sbl_errors
  {
    SBL_COULDNT_INIT 		=    -1,
    SBL_PROTOCOL_TOO_OLD	=    -2,
    SBL_PROTOCOL_TOO_NEW	=    -3,
    SBL_NO_CONFIG_FILES_FOUND	=    -4,
    SBL_FAILED_LOADING_KERNEL_IMAGE=    -5,
    
    SBL_UNKNOWN_ERROR		=   -10
  };

#endif

