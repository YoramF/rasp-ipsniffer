
ipsniffer:	main.o network.o
	gcc -s -o ./bin/ipsniffer network.o main.o -l pthread

main.o:	main.c network.c network.h
	gcc -c -O3 main.c 

network.o:	network.c network.h
	gcc -c -O3 network.c
