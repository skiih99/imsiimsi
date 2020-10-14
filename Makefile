all: send-arp

send-arp: send-arp.o ip.o mac.o main.o
	g++ -o send-arp send-arp.o ip.o mac.o main.o -lpcap

send-arp.o: send-arp.h send-arp.cpp
	g++ -c -o send-arp.o send-arp.cpp

ip.o: ip.h ip.cpp
	g++ -c -o ip.o ip.cpp

mac.o: mac.h mac.cpp
	g++ -c -o mac.o mac.cpp

main.o: send-arp.h main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f send-arp
	rm -f *.o
