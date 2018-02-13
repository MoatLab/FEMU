#!/bin/bash

rm -rf cscope*
find $(pwd) -name *.\[ch\] > cscope.files
cscope -b -q -R 2>/dev/null
#rm -f cscope.files
echo "cscope.out generated..."
