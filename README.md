# PackageEtherCapture

**Warning: PackageEtherCapture is a 0.x release.  The API and resulting data structure are very unstable.  If you use this package, we recommend using a specific minor release and not automatically upgrading without testing.**

PackageEtherCapture is a Swift Package with two sets of functionality:
1. Capturing frames from the network (wrapping the C-based libpcap library)
2. Decoding network frames into a Swift data structure.

## Packet capture restrictions

**Capturing packets requires read access to /dev/bpf* (the berkely packet filter device files).  Most MacOS users who "can administer their computers" are in the admin group, so we recommend the following commmand: **

    sudo chmod g+r /dev/bpf*

If you already installed Wireshark on your system, the installation process may have already created an "access_bpf" group, granted it rw access to /dev/bpf*, and added you to that group.  If that is already done, no further change is necessary.

**Access to /dev/bpf* is not available on iOS.  So capturing packets from the wire is only supported for MacOS**

**Access to /dev/bpf* is not possible for sandboxed apps.  So capturing packets in an app in the MacOS App store is not possible.**

## Dependencies

PackageEtherCapture uses Apple's swift-log API for logging. See https://github.com/apple/swift-log Bootstrapping the logging system is not required to use PackageEtherCapture.  The Logger label is "net.networkmom.PackageEtherCapture".

## Capture API

Here is the API for initiating a capture:

    public init(interface: String, count: Int32 = 0, command: String, snaplen: Int = 96, promiscuous: Bool = true, _ callback: @escaping (Frame) -> Void) throws {

Where "command" is a String with an embedded libpcap filter (the same as used by tcpdump and Wireshark).  See https://www.tcpdump.org/manpages/pcap-filter.7.html

Assuming the initializer does not throw an error, the closure passed into the call will be delivered a Frame data structure each time a Frame is captured.

PackageEtherCaptureDemo https://github.com/darrellroot/PackageEtherCaptureDemo demonstrates the simplest possible capture:

    import Foundation
    import PackageEtherCapture
    let etherCapture: EtherCapture?
    do {
        etherCapture = try EtherCapture(interface: "en0", command: "icmp or icmp6") { frame in
            //This closure is called every time a frame is captured.  The magic is in the frame data structure
            debugPrint(frame.description)
        }
    } catch {
        print("EtherCapture initialization failed with error \(error)")
    }
    RunLoop.current.run()

## Frame Creation API

Another way to use PackageEtherCapture is to pass in captured network traffic (one frame at a time) to create Frame data structures.  Here's an example from the CLI version of etherdump , passing in data obtained from a .pcapng file:

        for (count,packet) in packetBlocks.enumerated() {
            let frame = Frame(data: packet.packetData)
            displayFrame(frame: frame, packetCount: Int32(count), arguments: arguments)
        }

Here's the Frame initializer:
    public init(data: Data, timeval: timeval = timeval()) {

The Frame initializer does not currently fail, but if it is unable to decode a valid frame it will set the frameFormat to .invalid and layer3 contents to .unknown.  The raw data will still be available in the data structure.

## Regarding "Layer" Terminology in PackageEtherCapture

PackageEtherCapture uses "layers of encapsulation".  The initial layer is called layer-2 and is currently an Ethernet Frame.  Anything encapsulated in that Frame is called "layer 3".  That is usually IPv4 or IPv6, but it could be LLDP, STP, or CDP.  Those are (in an OSI model sense) layer-2 protocols, but they are also "application data" encoded inside a frame.  Because they are encapsulated inside the Layer-2 frame, PackageEtherCapture puts them at layer-3 of the returned data structure.

## Supported Decodes as of February 2020

The following Layer-2 decodes are currently supported:
1. Ethernet-II frame
2. 802.3 frame (with optional support for 802.2 SNAP header)
3. Invalid

The following Layer-3 decodes are currently supported:
1. IPv4 Header
2. IPv6 Header
3. Unknown

The following Layer-4 decodes are currently supported:
1. UDP Datagram Header
2. TCP Segment Header
3. Unknown

We hope and expect m
## Frame Hierarchial Data Structure Overview

Here is an overview of the data structure hierarchy:

    Frame.layer3
        IPv4
        IPv6
        Unknown
        
        IPv4.layer4 and IPv6.layer4:
            Tcp
            Udp
            Unknown
    
    Frame also has a .layer4 computed property which conveniently returns the layer4 contents

## EtherDisplay Protocol

This protocol includes conveniently available computed properties for displaying capture data.  Every structure in the Frame hierarchy should comply.

    public protocol EtherDisplay {
        var description: String { get }
        var verboseDescription: String { get }
        var hexdump: String { get }
    }

## Frame Data Structure (see source code for latest updates)

    public struct Frame: CustomStringConvertible, EtherDisplay, Identifiable, Codable {
        public init(data: Data, timeval: timeval = timeval()) {
    
    public let id = UUID()
    public let date: Date    // pcap timestamp of packet capture
    public let srcmac: String
    public let dstmac: String
    public var frameFormat: FrameFormat
    public var ieeeLength: UInt? = nil  //802.2 802.3 encapsulation
    public var ieeeDsap: UInt8? = nil
    public var ieeeSsap: UInt8? = nil
    public var ieeeControl: UInt8? = nil
    public var snapOrg: UInt? = nil  //802.2 SNAP header
    public var snapType: UInt? = nil   //802.2 SNAP header
    public var ethertype: UInt? = nil // ethernetII encapsulation
    /**
     - Parameter layer3: Nested data structure with higher layer information
     */
    public var layer3: Layer3 = .unknown(Unknown.completely)    
    public var layer4: Layer4? {
    public let data: Data  // total frame contents

## Layer3 enumeration: (we expect to add many cases as more decodes are added)

    public enum Layer3: CustomStringConvertible, EtherDisplay, Codable {
        case ipv4(IPv4)
        case ipv6(IPv6)
        case unknown(Unknown)

## IPv4 Data Structure

    public struct IPv4: CustomStringConvertible, EtherDisplay, Codable {
    
    public let sourceIP: IPv4Address
    public let destinationIP: IPv4Address
    public let data: Data
    public let version: UInt8
    public let ihl: UInt8  // 4 times IHL field
    public let dscp: UInt8
    public let ecn: UInt8
    public let totalLength: UInt
    public let identification: UInt
    public let evilBit: Bool
    public let dontFragmentFlag: Bool
    public let moreFragmentsFlag: Bool
    public let fragmentOffset: UInt
    public let ttl: UInt8
    public let ipProtocol: UInt8
    public let headerChecksum: UInt
    public let options: Data?
    //public let payload: Data?
    /**
     - Parameter layer4: Nested data structure with higher layer information
     */
    public var layer4: Layer4 = .unknown(Unknown.completely)

## IPv6 Data Structure

    public struct IPv6: EtherDisplay, Codable {
    
    public let data: Data
    public let version: UInt8
    public let trafficClass: UInt8
    public let flowLabel: UInt
    public let payloadLength: UInt
    public let nextHeader: UInt8
    public let hopLimit: UInt8
    public let sourceIP: IPv6Address
    public let destinationIP: IPv6Address
    public let layer4: Layer4

## Layer 4 enumeration: (We expect to add ICMP, plus possibly others)

    public enum Layer4: CustomStringConvertible, EtherDisplay, Codable {
        case tcp(Tcp)
        case udp(Udp)
        case unknown(Unknown)


## Tcp Data Structure

    public struct Tcp: EtherDisplay, Codable {

    public let data: Data
    public let sourcePort: UInt
    public let destinationPort: UInt
    public let sequenceNumber: UInt
    public let acknowledgementNumber: UInt
    public let dataOffset: UInt8
    public let urg: Bool
    public let ack: Bool
    public let psh: Bool
    public let rst: Bool
    public let syn: Bool
    public let fin: Bool
    public let window: UInt
    public let checksum: UInt
    public let urgentPointer: UInt
    public let options: Data?
    public let payload: Data

public struct Udp: EtherDisplay, Codable {
    public let data: Data
    public let payload: Data
    public let sourcePort: UInt
    public let destinationPort: UInt
    public let length: UInt
    public let checksum: UInt

## At this time we do not have a layer-5 structure for application-level data, but we anticipate that in the future.
