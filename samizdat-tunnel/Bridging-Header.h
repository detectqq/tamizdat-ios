// Objective-C / C bridging header for the samizdat-tunnel extension.
// Exposes Darwin kernel-control socket types to Swift so we can find the
// utun fd Apple opens for NEPacketTunnelProvider but doesn't pass us
// through the public API.
//
// Used by PacketTunnelProvider.findTunnelFileDescriptor().

#ifndef SamizdatTunnelBridgingHeader_h
#define SamizdatTunnelBridgingHeader_h

#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>

#endif /* SamizdatTunnelBridgingHeader_h */
