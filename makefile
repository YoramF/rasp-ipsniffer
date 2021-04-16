CFILES = $(wildcard *.c)
OFILES = $(CFILES:%.c=%.o)
OFILES_D = $(CFILES:%.c=%_d.o)
LIB = -l pthread
GCCFLAGS = -O3 -s
GCCFLAGS_D = -g

ipsniffer:	$(OFILES)
	gcc $(GCCFLAGS) -o ./bin/ipsniffer $(OFILES) $(LIB)

ipsniffer_d: $(OFILES_D)
	gcc $(GCCFLAGS_D) -o ./bin/ipsniffer_d $(OFILES_D) $(LIB)

%.o: %.c
	gcc $(GCCFLAGS) -c $< -o $@

%_d.o: %.c
	gcc $(GCCFLAGS_D) -c $< -o $@

clean:
	rm *.o
