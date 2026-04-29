// Bridging header for the samizdat-tunnel extension.
//
// Exposes Darwin kernel-control socket types to Swift so we can find the
// utun fd Apple opens for NEPacketTunnelProvider but doesn't pass us
// through the public API.
//
// iOS user-space SDK does not include <sys/kern_control.h> directly, so
// we replicate the stable bits here verbatim. Same trick Tun2SocksKit
// uses; types are part of the Darwin ABI and have not changed since
// macOS 10.4 / iOS 4. Used by
// PacketTunnelProvider.findTunnelFileDescriptor().

#ifndef SamizdatTunnelBridgingHeader_h
#define SamizdatTunnelBridgingHeader_h

#include <stdint.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#ifndef u_int8_t
typedef uint8_t  u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
typedef unsigned char u_char;
#endif

#ifndef CTLIOCGINFO
#define CTLIOCGINFO 0xc0644e03UL
#endif

struct ctl_info {
    u_int32_t ctl_id;
    char      ctl_name[96];
};

struct sockaddr_ctl {
    u_char    sc_len;
    u_char    sc_family;
    u_int16_t ss_sysaddr;
    u_int32_t sc_id;
    u_int32_t sc_unit;
    u_int32_t sc_reserved[5];
};

#endif /* SamizdatTunnelBridgingHeader_h */
