LDLIBS=-lpcap -pthread
TARGET=tcp-block

all: $(TARGET)

arp-spoof: main.o $(TARGET) tcphdr.o ethhdr.o iphdr.o ip.o mac.o buf.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f  *.o $(TARGET)
