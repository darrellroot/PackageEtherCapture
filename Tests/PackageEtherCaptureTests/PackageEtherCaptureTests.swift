import XCTest
import Network
@testable import PackageEtherCapture

final class PackageEtherCaptureTests: XCTestCase {
    
    /*
     To get frames for testing use wireshark
     
     To get ASCII detailed decode click in middle decode section:
        right-click->copy->all visible items
     
     To get hex stream for Frame() construct input:
        right-click->copy->as hex stream
     */
    func testIpv4Frame30() {
        /*
         Frame 30: 66 bytes on wire (528 bits), 66 bytes captured (528 bits) on interface 0
         Ethernet II, Src: Apple_2c:0d:50 (c8:69:cd:2c:0d:50), Dst: Apple_89:0a:04 (68:5b:35:89:0a:04)
             Destination: Apple_89:0a:04 (68:5b:35:89:0a:04)
                 Address: Apple_89:0a:04 (68:5b:35:89:0a:04)
                 .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
                 .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
             Source: Apple_2c:0d:50 (c8:69:cd:2c:0d:50)
                 Address: Apple_2c:0d:50 (c8:69:cd:2c:0d:50)
                 .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
                 .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
             Type: IPv4 (0x0800)
         Internet Protocol Version 4, Src: 192.168.0.16, Dst: 192.168.0.10
             0100 .... = Version: 4
             .... 0101 = Header Length: 20 bytes (5)
             Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
                 0000 00.. = Differentiated Services Codepoint: Default (0)
         .00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
             Total Length: 52
             Identification: 0x0000 (0)
             Flags: 0x4000, Don't fragment
                 0... .... .... .... = Reserved bit: Not set
                 .1.. .... .... .... = Don't fragment: Set
                 ..0. .... .... .... = More fragments: Not set
                 ...0 0000 0000 0000 = Fragment offset: 0
             Time to live: 64
             Protocol: TCP (6)
             Header checksum: 0xb959 [validation disabled]
             [Header checksum status: Unverified]
             Source: 192.168.0.16
             Destination: 192.168.0.10
         Transmission Control Protocol, Src Port: 49153, Dst Port: 56958, Seq: 1, Ack: 2, Len: 0
             Source Port: 49153
             Destination Port: 56958
             [Stream index: 3]
             [TCP Segment Len: 0]
             Sequence number: 1    (relative sequence number)
             [Next sequence number: 1    (relative sequence number)]
             Acknowledgment number: 2    (relative ack number)
             1000 .... = Header Length: 32 bytes (8)
             Flags: 0x010 (ACK)
             Window size value: 2052
          lated window size: 2052]
             [Window size scaling factor: -1 (unknown)]
             Checksum: 0x2031 [unverified]
             [Checksum Status: Unverified]
             Urgent pointer: 0
             Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
                 TCP Option - No-Operation (NOP)
                 TCP Option - No-Operation (NOP)
                 TCP Option - Timestamps: TSval 2268058408, TSecr 468163254
                     Kind: Time Stamp Option (8)
                     Length: 10
                     Timestamp value: 2268058408
                     Timestamp echo reply: 468163254
             [SEQ/ACK analysis]
             [Timestamps]

         */
        let packetStream = "685b35890a04c869cd2c0d50080045000034000040004006b959c0a80010c0a8000ac001de7ebc1aa99e868a316380100804203100000101080a872fd3281be79ab6"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 66)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "c8:69:cd:2c:0d:50")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x0800)
        XCTAssert(frame.data.count == 66)
        guard case .ipv4(let ipv4) = frame.layer3 else {
            XCTFail()
            return
        }
        //IPv4 packet tests
        XCTAssert(ipv4.sourceIP == IPv4Address("192.168.0.16")!)
        XCTAssert(ipv4.destinationIP == IPv4Address("192.168.0.10")!)
        XCTAssert(ipv4.data.count == 52)
        XCTAssert(ipv4.version == 4)
        XCTAssert(ipv4.ihl == 5)
        XCTAssert(ipv4.dscp == 0)
        XCTAssert(ipv4.ecn == 0)
        XCTAssert(ipv4.totalLength == 52)
        XCTAssert(ipv4.identification == 0)
        XCTAssert(ipv4.evilBit == false)
        XCTAssert(ipv4.dontFragmentFlag == true)
        XCTAssert(ipv4.moreFragmentsFlag == false)
        XCTAssert(ipv4.fragmentOffset == 0)
        XCTAssert(ipv4.ttl == 64)
        XCTAssert(ipv4.ipProtocol == 6)
        XCTAssert(ipv4.headerChecksum == 0xb959)
        XCTAssert(ipv4.options == nil)
        
    }
    func testIpv6Frame2() {
        let packetStream = "685b35890a04b07fb95d8ed286dd620d78a900200639260014061400049c00000000000023132601064748021620d5ae46fbf6c7a15401bbf0f198953ced5030c49a8011011623d200000101080a0243f4b91f79a97d"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 100)
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x86dd)
        XCTAssert(frame.data.count == 86)
        guard case .ipv6(let ipv6) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(ipv6.version == 6)
        XCTAssert(ipv6.trafficClass == 0x20)
        XCTAssert(ipv6.flowLabel == 0xd78a9)
        XCTAssert(ipv6.payloadLength == 32)
        XCTAssert(ipv6.nextHeader == 6)
        XCTAssert(ipv6.hopLimit == 57)
        XCTAssert(ipv6.sourceIP == IPv6Address("2600:1406:1400:49c::2313")!)
        XCTAssert(ipv6.destinationIP == IPv6Address("2601:647:4802:1620:d5ae:46fb:f6c7:a154")!)
    }
    func testBpdu() {
        let packetStream = "0180c20000004c710c19e3120027424203000002027c80004c710c19e30d0000000080004c710c19e30d80050000140002000f000000000000000000"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 60)
        XCTAssert(frame.frameFormat == .ieee8023)
        XCTAssert(frame.dstmac == "01:80:c2:00:00:00")
        XCTAssert(frame.srcmac == "4c:71:0c:19:e3:12")
        XCTAssert(frame.ieeeLength == 39)
        XCTAssert(frame.ieeeDsap == 0x42)
        XCTAssert(frame.ieeeControl == 0x3)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == nil)
        XCTAssert(frame.data.count == 60)
        guard case .bpdu(let bpdu) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(bpdu.protocolId == 0)
        XCTAssert(bpdu.bpduVersion == 2)
        XCTAssert(bpdu.type == 0x02)
        XCTAssert(bpdu.flagTopChangeAgree == false)
        XCTAssert(bpdu.flagAgreement == true)
        XCTAssert(bpdu.flagForwarding == true)
        XCTAssert(bpdu.flagLearning == true)
        XCTAssert(bpdu.portRole == 3) // designated
        XCTAssert(bpdu.flagProposal == false)
        XCTAssert(bpdu.flagTopChange == false)
        XCTAssert(bpdu.rootId == 0x80004c710c19e30d)
        XCTAssert(bpdu.rootCost == 0)
        XCTAssert(bpdu.bridgeId == 0x80004c710c19e30d)
        XCTAssert(bpdu.portId == 0x8005)
        XCTAssert(bpdu.age == 0.0)
        XCTAssert(bpdu.maxAge == 20.0)
        XCTAssert(bpdu.helloTime == 2.0)
        XCTAssert(bpdu.forwardDelay == 15.0)
    }
    func testCdp() {
        let packetStream = "01000ccccccc4c710c19e31200cdaaaa0300000c200002b469530001001034633731306331396533306400020049000000030101cc0004c0a800200208aaaa0300000086dd0010fe800000000000004e710cfffe19e30d0208aaaa0300000086dd0010260106474802162000000000000000010003000767693500040008000000290005000c322e342e352e373100060028436973636f2053473235302d303820285049443a53473235302d30382d4b39292d565344000a00060001000b0005010012000500001300050000140010737769746368313965333064"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 60)
        XCTAssert(frame.frameFormat == .ieee8023)
        XCTAssert(frame.dstmac == "01:00:0c:cc:cc:cc")
        XCTAssert(frame.srcmac == "4c:71:0c:19:e3:12")
        XCTAssert(frame.ieeeLength == 205)
        XCTAssert(frame.ieeeDsap == 0xaa)
        XCTAssert(frame.ieeeControl == 0x3)
        XCTAssert(frame.snapOrg == 0x00000c)
        XCTAssert(frame.snapType == 0x2000)
        XCTAssert(frame.ethertype == nil)
        XCTAssert(frame.data.count == 219)
        guard case .cdp(let cdp) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(cdp.version == 2)
        XCTAssert(cdp.ttl == 180)
        XCTAssert(cdp.checksum == 0x6953)
        XCTAssert(cdp.values.contains(.deviceId("4c710c19e30d")))
        XCTAssert(cdp.values.contains(.ipv4address(IPv4Address("192.168.0.32")!)))
        XCTAssert(cdp.values.contains(.ipv6address(IPv6Address("2601:647:4802:1620::1")!)))
        XCTAssert(cdp.values.contains(.ipv6address(IPv6Address("fe80::4e71:cff:fe19:e30d")!)))

    }
}
