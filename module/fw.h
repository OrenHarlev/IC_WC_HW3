#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// the protocols we will work with
typedef enum {
    PROT_ICMP	= 1,
    PROT_TCP	= 6,
    PROT_UDP	= 17,
    PROT_OTHER 	= 255,
    PROT_ANY	= 143,
} prot_t;

// various reasons to be registered in each log entry
typedef enum {
    REASON_FW_INACTIVE            = -1,
    REASON_NO_MATCHING_RULE       = -2,
    REASON_XMAS_PACKET            = -4,
    REASON_ILLEGAL_VALUE          = -8,
    REASON_NO_MATCHING_CONNECTION = -16,
    REASON_STATE_DONT_MATCH       = -32,
    REASON_ACTIVE_CONNECTION      = -64
} reason_t;

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG_RESET		"log"
#define ATTR_NAME_LOG_RESET         "reset"
#define DEVICE_NAME_LOG_READ        "fw_log"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"enp0s8"
#define OUT_NET_DEVICE_NAME			"enp0s9"
#define LOCAL_IP                    "10.0.2.15"
#define IN_NET_DEVICE_IP            "10.1.1.3"
#define OUT_NET_DEVICE_IP           "10.1.2.3"

// auxiliary values, for your convenience
#define IP_VERSION       (4)
#define PORT_ANY         (0)
#define IP_ANY           (0)
#define PORT_ABOVE_1023  (1023)
#define MAX_RULES        (50)
#define MAX_RULE_NAME    (20)
#define RULE_ARGS        (11)
#define IP_BITS          (32)
#define LB_MSByte        (127)
#define LB_MASK          (8)
#define PORT_FTP_DATA    (20)
#define PORT_FTP_CONTROL (21)
#define PORT_HTTP        (80)
#define PORT_HTTP_PROXY  (800)
#define PORT_FTP_PROXY   (210)
#define PORT_SMTP        (25)
#define PORT_SMTP_PROXY  (250)
#define PORT_ZOOKEPPER   (2181)
#define PORT_ZOOKEPPER_PROXY (21810)


// device minor numbers, for your convenience
typedef enum {
    MINOR_RULES    = 0,
    MINOR_LOG      = 1,
    MINOR_LOG_READ = 2,
    MINOR_CONNS    = 3,
} minor_t;

typedef enum {
    ACK_NO 		= 0x01,
    ACK_YES 	= 0x02,
    ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
    DIRECTION_IN 	= 0x01,
    DIRECTION_OUT 	= 0x02,
    DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
    char rule_name[MAX_RULE_NAME];			// names will be no longer than 20 chars
    direction_t direction;
    __be32	src_ip;
    __be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
    __u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
    // (the field is redundant - easier to print)
    __be32	dst_ip;
    __be32	dst_prefix_mask; 	// as above
    __u8    dst_prefix_size; 	// as above
    __be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
    prot_t	protocol; 			// values from: prot_t
    ack_t	ack; 				// values from: ack_t
    __u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
    ktime_t       	timestamp;     	// time of creation/update
    unsigned char  	protocol;     	// values from: prot_t
    unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
    __be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
    __be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
    __be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
    __be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
    reason_t     	reason;       	// rule#index, or values from: reason_t
    unsigned int   	count;        	// counts this line's hits
} log_row_t;

// packet relevant data
typedef struct {
    direction_t direction;
    __be32	src_ip;
    __be32	dst_ip;
    __be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __u8	protocol; 			// values from: prot_t
    ack_t	ack; 				// values from: ack_t
    bool syn;
    bool fin;
} packet_t;

typedef enum
{
    LISTEN = 1,
    SYN_SENT = 2,
    SYN_RCVD = 3,
    ESTABLISHED = 4,
    FIN_WAIT = 5, // this state includes FIN_WAIT_1 and FIN_WAIT_2 since as a gate-way they are logically the same.
//  FIN_WAIT_2,
            CLOSE_WAIT = 6,
//  CLOSING,
//  TIME_WAIT,
//  LAST_ACK,
            CLOSED = 7, // CLOSING, TIME_WAIT, LAST_ACK will be considered as CLOSED since we are not expecting more packets from those states
} state_t;

typedef struct
{
    __be32	cIp;
    __be32	sIp;
    __be16	cPort; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __be16	sPort; 			// number of port or 0 for any or port 1023 for any port number > 1023
    state_t cState;
    state_t sState;
} connection_t;
#endif