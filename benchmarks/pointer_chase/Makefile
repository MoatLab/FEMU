all: pointer_generator write_pointer_to_disk host_pointer_reader

pointer_generator: pointer_generator.cpp
	g++ pointer_generator.cpp -o pointer_generator	

write_pointer_to_disk: write_pointer_to_disk.c
	gcc write_pointer_to_disk.c -o write_pointer_to_disk

host_pointer_reader: host_pointer_reader.c
	gcc host_pointer_reader.c -o host_pointer_reader

clean:
	rm pointer_generator write_pointer_to_disk
