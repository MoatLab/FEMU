\ -------------------------------------------------------------------------
\ SCSI encode/decode unit
\ -------------------------------------------------------------------------

: decode-unit-scsi ( str len -- id lun )
  2 parse-nhex
;

: encode-unit-scsi ( id lun -- str len)
  swap
  pocket tohexstr
  " ," pocket tmpstrcat >r
  rot pocket tohexstr r> tmpstrcat drop
;
