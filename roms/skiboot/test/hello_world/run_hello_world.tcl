source ../../external/mambo/skiboot.tcl

mysim go
mysim memory fwrite 0x30000000 0x500000 skiboot-hello_world.dump
exit
