all: pointer_generator write_pointer_to_disk

pointer_generator: pointer_generator.c
	gcc pointer_generator.c -o pointer_generator	

write_pointer_to_disk: write_pointer_to_disk.c
	gcc write_pointer_to_disk.c -o write_pointer_to_disk

clean:
	rm pointer_generator write_pointer_to_disk
