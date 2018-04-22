/// \file filter.c
/// \brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Chris Dickens (RIT CS)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.
///

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "filter.h"
#include "pktUtility.h"

/// maximum line length of a configuration file
#define MAX_LINE_LEN  256

#define SUB_INIT 0x80000000
#define MIN_ALLOC 5
#define LOCAL "LOCAL_NET"
#define BTCP "BLOCK_INBOUND_TCP_PORT"
#define BPING "BLOCK_PING_REQ"
#define BIP "BLOCK_IP_ADDR"


/// The type used to hold the configuration settings for a filter
typedef struct FilterConfig_S
{
    unsigned int localIpAddr;    ///< the local IP address
    unsigned int localMask;      ///< the address mask
    bool blockInboundEchoReq;    ///< where to block inbound echo
    unsigned int numBlockedInboundTcpPorts;   ///< count of blocked ports
    unsigned int* blockedInboundTcpPorts;     ///< array of blocked ports
    unsigned int numBlockedIpAddresses;       ///< count of blocked addresses
	// all addresses will be in ip-tuple order!!!
	unsigned int* blockedIpAddresses;         ///< array of blocked addresses
} FilterConfig;


/// Parses the remainder of the string last operated on by strtok 
/// and converts each octet of the ASCII string IP address to an
/// unsigned integer value.
/// @param ipAddr The destination into which to store the octets
/// @pre caller must have first called strtok to set its pointer.
/// @post ipAddr contains the ip address found in the string
static void parse_remainder_of_string_for_ip(unsigned int* ipAddr)
{
   char* pToken;

   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[0]);
   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[1]);
   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[2]);
   pToken = strtok(NULL, "/");
   sscanf(pToken, "%u", &ipAddr[3]);
}


/// Checks if an IP address is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param addr The IP address that is to be checked
/// @return True if the IP address is to be blocked
static bool block_ip_address(FilterConfig* fltCfg, unsigned int addr){
	//parse the blocked array of addresses to and check if addr is in there
	bool result = false;
	for(int i = 0; i < fltCfg->numBlockedIpAddresses; i++){
		if(fltCfg->blockedIpAddresses[i] == addr )
			result = true;	
	}
	return result;
}


/// Checks if a TCP port is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param port The TCP port that is to be checked
/// @return True if the TCP port is to be blocked
static bool block_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port){
	bool result = false;
	for(int i = 0; i < fltCfg->numBlockedInboundTcpPorts;i++){
		if(fltCfg->blockedInboundTcpPorts[i] == port )
			result = true;	
	}
	return result;
}


/// Checks if a packet is coming into the network from the external world. Uses
/// the localMask in the supplied filter configuration to compare the srcIpAddr
/// and dstIpAddr to the localIpAddr supplied in the filter configuration. If the
/// dstIpAddr is on the same network as the localIpAddr, and the srcIpAddr is not
/// on the same network as the localIpAddr then the packet is inbound.
/// @param fltCfg The filter configuration to use
/// @param srcIpAddr The source IP address of a packet
/// @param dstIpAddr The destination IP address of a packet
static bool packet_is_inbound(FilterConfig* fltCfg, unsigned int srcIpAddr, unsigned int dstIpAddr){
	bool result = false;
	unsigned int local = fltCfg->localIpAddr;
	unsigned int netBits = fltCfg->localMask-1;
	unsigned int subnetMask = SUB_INIT;

	//local ip address is host ip and unique
	if( mask == 32 )
		return result;
	else{
		// calculate subnet mask based on cider ip format		
		for( int i = 0; i < netBits;i++)
			subnetMask = subnetMask | (subnetMask >> 1);
	}

	if( ((src & subnetMask) != (local & subnetMask)) && ((dest & subnetMask) == (local & subnetMask)) )
		result = true;	

	return result;
}


/// Adds the specified IP address to the array of blocked IP addresses in the
/// specified filter configuration. This requires allocating additional memory
/// to extend the length of the array that holds the blocked IP addresses.
/// @param fltCfg The filter configuration to which the IP address is added
/// @param ipAddr The IP address that is to be blocked
static void add_blocked_ip_address(FilterConfig* fltCfg, unsigned int ipAddr){
	if(fltCfg->numBlockedIpAddresses >= 5)
		fltCfg->blockedIpAddresses = (unsigned int*)realloc(fltCfg->blockedIpAddresses,(fltCfg->numBlockedIpAddresses)*sizeof(unsigned int));
	fltCfg->blockedIpAddresses[fltCfg->numBlockedIpAddresses] = ipAddr;
	fltCfg->numBlockedIpAddresses++;
}


/// Adds the specified TCP port to the array of blocked TCP ports in the
/// specified filter configuration. This requires allocating additional
/// memory to extend the length of the array that holds the blocked ports.
/// @param fltCfg The filter configuration to which the TCP port is added
/// @param port The TCP port that is to be blocked
static void add_blocked_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port){
	if(fltCfg->numBlockedInboundTcpPorts >= 5)
		fltCfg->blockedInboundTcpPorts = (unsigned int*)realloc(fltCfg->blockedInboundTcpPorts,(fltCfg->numBlockedInboundTcpPorts)*sizeof(unsigned int));
	fltCfg->blockedInboundTcpPorts[fltCfg->numBlockedInboundTcpPorts] = port;
	fltCfg->numBlockedInboundTcpPorts++;
}


/// Creates an instance of a filter by allocating memory for a FilterConfig
/// and initializing its member variables.
/// @return A pointer to the new filter
IpPktFilter create_filter(void){
	FilterConfig* filter = NULL;
	filter = (FilterConfig *)malloc(sizeof(FilterConfig));

	filter->localIpAddr = 0;
	filter->localMask = 0;
	filter->blockInboundEchoReq = false;
	filter->numBlockedInboundTcpPorts = 0;
	filter->blockedInboundTcpPorts = (unsigned int*)malloc(MIN_ALLOC*sizeof(int));
	filter->numBlockedIpAddresses = 0;
	filter->blockedIpAddresses = (unsigned int*)malloc(MIN_ALLOC*sizeof(int));	

	return (IpPktFilter)filter; 
}


/// Destroys an instance of a filter by freeing all of the dynamically
/// allocated memory associated with the filter.
/// @param filter The filter that is to be destroyed
void destroy_filter(IpPktFilter filter){
	FilterConfig* fltCfg = filter;
	
	free( fltCfg->blockedInboundTcpPorts );
	free( fltCfg->blockedIpAddresses );
	free( filter );
}


/// Configures a filter instance using the specified configuration file.
/// Reads the file line by line and uses strtok, strcmp, and sscanf to 
/// parse each line.  After each line is successfully parsed the result
/// is stored in the filter.  Blank lines are skipped.  When the end of
/// the file is encountered, the file is closed and the function returns.
/// @param filter The filter that is to be configured
/// @param filename The full path/filename of the configuration file that
/// is to be read.
/// @return True when successful
bool configure_filter(IpPktFilter filter, char* filename){
	char* buf;
  	FILE* pFile;
  	char* pToken;
  	char* success;
   	bool  validConfig = false;
	ssize_t read;
	size_t len;

//TODO: return true if valid config file

    pFile = fopen(filename, "r"); 
	if(pFile == NULL){
    	printf("ERROR: invalid config file\n");
    	return false;
    }
	//read until end of file character
	while( (read = getline(&buf,&len,pFile)) != -1 ){
		//loop attributes
		unsigned int ipaddr = 0;
		unsigned int mask = 0;
		unsigned int port = 0;
		char ipDelimit[] = ":/";
		//check for the commands
		if(strstr(buf,LOCAL) != NULL){ //local ip address and mask

			pToken = strtok(buf,ipDelimit);
			pToken = strtok(NULL,ipDelimit);
			parse_remainder_of_string_for_ip(&ipaddr);
			fltCfg->localIpAddr = ipaddr;
			pToken = strtok(NULL,ipDelimit);
			sscanf(pToken,"/%d",&mask);
			fltCfg->localMask = mask;	
			validConfig = true;			

		}else if(strstr(buf,BTCP) != NULL){ //TCP port to be blocked

			pToken = strtok(buf,BTCP);
			sscanf(pToken,": %d",&port);
			add_blocked_inbound_tcp_port(fltCfg,port);	
			validConfig = true;			
	
		}else if(strstr(buf,BPING) != NULL){ //block ping requests yes/no

			fltCfg->boolInboundEchoReq = true;		
			validConfig = true;			

		}else if(strstr(buf,BIP) != NULL){ //IP address to be blocked with mask

			ipaddr = 0;
			pToken = strtok(buf,ipDelimit);
			pToken = strtok(NULL,ipDelimit);
			parse_remainder_of_string_for_ip(&ipaddr);	
			add_blocked_ip_address(fltCfg,ipaddr);
			validConfig = true;			

		}else{//line contains just whitespace or unrecognized command
			
		}
			
	}


    if(validConfig == false){
        fprintf(stderr, "Error, configuration file must set LOCAL_NET\n");
   	}
 
   	return validConfig;
}

/**
 * Print hex ip in decimal format
 */
void printIP(unsigned int ipaddr){
	unsigned char* sr = (unsigned char*)&ipaddr;
	for(int i = 0; i < 4; i++){
		if(i < 3)
			printf("%d.",(int)sr[i]);
		else
			printf("%d\n",(int)sr[i]);
	}
}

/// Uses the settings specified by the filter instance to determine
/// if a packet should be allowed or blocked.  The source and
/// destination IP addresses are extracted from each packet and
/// checked using the block_ip_address helper function. The IP protocol
/// is extracted from the packet and if it is ICMP or TCP then 
/// additional processing occurs. This processing blocks inbound packets
/// set to blocked TCP destination ports and inbound ICMP echo requests.
/// @param filter The filter configuration to use
/// @param pkt The packet to exame
/// @return True if the packet is allowed by the filter. False if the packet
/// is to be blocked
bool filter_packet(IpPktFilter filter, unsigned char* pkt){
    unsigned int srcIpAddr;
    unsigned int dstIpAddr;
	unsigned int protocol = 0;
	bool result = true;
    FilterConfig* fltCfg = (FilterConfig*)filter;

	srcIPAddr = ExtractSrcAddrFromIpHeader( pkt );
	printIP( srcIPAddr );

	dstIPAddr = ExtractDstAddrFromIpHeader( pkt );
	printIP( dstIpAddr );

	if( !block_ip_address( fltCfg,srcIPAddr ) )
		result = false;		

	if( !block_ip_address( fltCfg,dstIPAddr ) )
		result = false;
	
	if( (protocol = ExtractIpProtocol( pkt )) != 0 ){
		
	}

//TODO: student implements filter_packet()

	return true;
}

