LDLIBS=-lpcap

all: send-arp

send-arp: main.o arp_spoofing.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
