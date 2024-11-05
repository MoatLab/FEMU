\ Power

defer power-off    ( -- )

: no-power-off
  s" power-off is not available on this platform." type cr
  ;

' no-power-off to power-off
