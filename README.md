# ARP Spoofing using C #
## Overview ##
This project demonstrates ARP spoofing using a C program on a Linux environment. ARP spoofing is a technique where an attacker sends fake ("spoofed") Address Resolution Protocol (ARP) messages onto a local area network. This can be used for various purposes, such as intercepting or modifying traffic between two parties.

## Prerequisites ##
Before running the program, ensure the following:

### Network Configuration: ###
* Obtain the IP and MAC addresses of:
  - Victim (TARGET_IP and TARGET_MAC)
  - Router (ROUTER_IP and ROUTER_MAC)
  - Attacker (ATTACKER_IP and ATTACKER_MAC)
    
  ### Install libpcap: ###
  * Install development files for libpcap library : ``` sudo apt-get install libpcap-dev ```

## Compilation ##
Compile the C program using GCC:  ``` gcc mim.c -o mim -lpcap ```

## Running the Program ##
Execute the compiled program with root privileges (required for sending raw packets):  ``` sudo ./mim ```


## Explanation ##
### Code Structure ###
 * Main Functionality:
   - Opens a network interface for packet capture and spoofing.
   - Creates two threads:
       - One for spoofing ARP responses to the victim (target).
       - Another for spoofing ARP responses to the router.
  - Uses libpcap for sending and receiving packets.
    
* Functions:
  - setIPForwarding(int toggle): Enables or disables IP forwarding on the Linux kernel.
  - sendARP(...): Constructs and sends an ARP reply packet.
  - sendARPPackets(void *args): Thread function to continuously send ARP packets to the specified target (victim or router).
    
### Notes ###
* Ensure proper permissions and network configuration before running the program.
* Use responsibly and legally, as ARP spoofing can be used maliciously.
