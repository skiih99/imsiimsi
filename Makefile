all: send-arp

send-arp: send-arp.o arphdr.o ethhdr.o ip.o mac.o main.o
	g++ -o send-arp send-arp.o arphdr.o ethhdr.o ip.o mac.o main.o -lpcap

send-arp.o: send-arp.h ethhdr.h arphdr.h send-arp.cpp
	g++ -c -o send-arp.o send-arp.cpp

arphdr.o: arphdr.h arphdr.cpp
	g++ -c -o arphdr.o arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp
	g++ -c -o ethhdr.o ethhdr.cpp

ip.o: ip.h ip.cpp
	g++ -c -o ip.o ip.cpp

mac.o: mac.h mac.cpp
	g++ -c -o mac.o mac.cpp

main.o: send-arp.h main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f send-arp
	rm -f *.o
