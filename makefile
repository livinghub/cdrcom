all: main.o eap.o md5.o ping.o
	$(CC) -o dr main.o md5.o eap.o ping.o -lpcap -lpthread

main.o: main.c
	$(CC) -c main.c -o main.o

eap.o: eap.c
	$(CC) -c eap.c -o eap.o

md5.o: md5c.c
	$(CC) -c md5c.c -o md5.o

ping.o: ping.c
	$(CC) -c ping.c -o ping.o

clean: 
	rm *.o
