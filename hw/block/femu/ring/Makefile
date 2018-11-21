CC = gcc
INC += 
LIB += 

CFLAGS += -g

TARGET = rt
ALL:$(TARGET)

OBJ = rte_ring.o

$(TARGET):$(OBJ)  ring-test.o 
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	rm -f *.o
	rm -f $(TARGET) 

install:
