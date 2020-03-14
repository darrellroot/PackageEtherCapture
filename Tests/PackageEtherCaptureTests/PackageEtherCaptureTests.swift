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
        XCTAssert(bpdu.v1Length == 0)
    }
    func testLldp() {
        let packetStream = "0180c200000e4c710c19e31288cc0207044c710c19e30d04040567693506020078fe0e00120f05001100110011001100110a0c7377697463683139653330640e0400140014100c0501c0a8002002000186a00010181102fe800000000000004e710cfffe19e30d02000186a0001018110220010db848021620000000000000000102000186a000fe060080c20100010000"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 60)
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "01:80:c2:00:00:0e")
        XCTAssert(frame.srcmac == "4c:71:0c:19:e3:12")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x88cc)
        XCTAssert(frame.data.count == 145)
        guard case .lldp(let lldp) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(lldp.values.count == 14)
        XCTAssert(lldp.values.contains(.chassisId(subtype: 4, id: "4c:71:0c:19:e3:0d")))
        XCTAssert(lldp.values.contains(.portId(subtype: 5, id: "gi5")))
        XCTAssert(lldp.values.contains(.ttl(120)))
        XCTAssert(lldp.values.contains(.systemName("switch19e30d")))
        XCTAssert(lldp.values.contains(.capabilityMacBridge))
        XCTAssert(lldp.values.contains(.capabilityRouter))
        XCTAssert(lldp.values.contains(.enabledMacBridge))
        XCTAssert(lldp.values.contains(.enabledRouter))
        XCTAssert(!lldp.values.contains(.capabilityRepeater))
        XCTAssert(!lldp.values.contains(.enabledDOCSIS))
        XCTAssert(lldp.values.contains(.endOfLldp))
        XCTAssert(lldp.values.contains(.managementAddressIPv4(address: IPv4Address("192.168.0.32")!, subType: 2, interface: 100000, oid: "")))
            
        XCTAssert(lldp.values.contains(.managementAddressIPv6(address: IPv6Address("fe80::4e71:cff:fe19:e30d")!, subType: 2, interface: 100000, oid: "")))
        XCTAssert(lldp.values.contains(.managementAddressIPv6(address: IPv6Address("2001:0db8:4802:1620::1")!, subType: 2, interface: 100000, oid: "")))
        XCTAssert(lldp.values.contains(.ouiSpecific(oui: "00:12:0f", subType: 5, info: "\0\u{11}\0\u{11}\0\u{11}\0\u{11}\0\u{11}")))
        XCTAssert(lldp.values.contains(.ouiSpecific(oui: "00:80:c2", subType: 1, info: "\0\u{01}")))
    }
    func testCdp() {
        let packetStream = "01000ccccccc4c710c19e31200cdaaaa0300000c200002b469530001001034633731306331396533306400020049000000030101cc0004c0a800200208aaaa0300000086dd0010fe800000000000004e710cfffe19e30d0208aaaa0300000086dd001020010db84802162000000000000000010003000767693500040008000000290005000c322e342e352e373100060028436973636f2053473235302d303820285049443a53473235302d30382d4b39292d565344000a00060001000b0005010012000500001300050000140010737769746368313965333064"
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
        XCTAssert(cdp.values.contains(.ipv6address(IPv6Address("2001:db8:4802:1620::1")!)))
        XCTAssert(cdp.values.contains(.ipv6address(IPv6Address("fe80::4e71:cff:fe19:e30d")!)))
        XCTAssert(cdp.values.contains(.capabilityRouter))
        XCTAssert(cdp.values.contains(.capabilitySwitch))
        XCTAssert(cdp.values.contains(.capabilityIgmp))
        XCTAssert(!cdp.values.contains(.capabilityBridge))
        XCTAssert(!cdp.values.contains(.capabilityMacRelay))
        XCTAssert(!cdp.values.contains(.capabilitySourceRouteBridge))
        XCTAssert(cdp.values.contains(.softwareVersion("2.4.5.71")))
        XCTAssert(cdp.values.contains(.platform("Cisco SG250-08 (PID:SG250-08-K9)-VSD")))
        XCTAssert(cdp.values.contains(.nativeVlan(1)))
        XCTAssert(cdp.values.contains(.duplex("Duplex Full")))
        XCTAssert(cdp.values.contains(.trustBitmap("Trust Bitmap 0x0")))
    
        XCTAssert(cdp.values.contains(.untrustedCos("Untrusted Port CoS 0x0")))
        XCTAssert(cdp.values.contains(.systemName("switch19e30d")))
    }
    func testIcmpV4EchoRequest() {
        let packetStream = "b07fb95d8ed2685b35890a04080045000054db2d000040010000c0a8000a040202010800df8a138500005e5b412b00017a6508090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 66)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.srcmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x0800)
        XCTAssert(frame.data.count == 98)
        guard case .ipv4(let ipv4) = frame.layer3 else {
            XCTFail()
            return
        }
        //IPv4 packet tests
        XCTAssert(ipv4.sourceIP == IPv4Address("192.168.0.10")!)
        XCTAssert(ipv4.destinationIP == IPv4Address("4.2.2.1")!)
        XCTAssert(ipv4.data.count == 84)
        XCTAssert(ipv4.version == 4)
        XCTAssert(ipv4.ihl == 5)
        XCTAssert(ipv4.dscp == 0)
        XCTAssert(ipv4.ecn == 0)
        XCTAssert(ipv4.totalLength == 84)
        XCTAssert(ipv4.identification == 0xdb2d)
        XCTAssert(ipv4.evilBit == false)
        XCTAssert(ipv4.dontFragmentFlag == false)
        XCTAssert(ipv4.moreFragmentsFlag == false)
        XCTAssert(ipv4.fragmentOffset == 0)
        XCTAssert(ipv4.ttl == 64)
        XCTAssert(ipv4.ipProtocol == 1)
        XCTAssert(ipv4.headerChecksum == 0x0000)
        XCTAssert(ipv4.options == nil)
        guard case .icmp4(let icmp4) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp4.type == 8)
        XCTAssert(icmp4.code == 0)
        XCTAssert(icmp4.icmpType == .echoRequest(identifer: 4997, sequence: 0))
    }
    func testIcmpV4EchoReply() {
        let packetStream = "685b35890a04b07fb95d8ed208004520005471b200003901492204020201c0a8000a0000e78a138500005e5b412b00017a6508090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 66)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x0800)
        XCTAssert(frame.data.count == 98)
        guard case .ipv4(let ipv4) = frame.layer3 else {
            XCTFail()
            return
        }
        //IPv4 packet tests
        XCTAssert(ipv4.sourceIP == IPv4Address("4.2.2.1")!)
        XCTAssert(ipv4.destinationIP == IPv4Address("192.168.0.10")!)
        XCTAssert(ipv4.data.count == 84)
        XCTAssert(ipv4.version == 4)
        XCTAssert(ipv4.ihl == 5)
        XCTAssert(ipv4.dscp == 8)
        XCTAssert(ipv4.ecn == 0)
        XCTAssert(ipv4.totalLength == 84)
        XCTAssert(ipv4.identification == 0x71b2)
        XCTAssert(ipv4.evilBit == false)
        XCTAssert(ipv4.dontFragmentFlag == false)
        XCTAssert(ipv4.moreFragmentsFlag == false)
        XCTAssert(ipv4.fragmentOffset == 0)
        XCTAssert(ipv4.ttl == 57)
        XCTAssert(ipv4.ipProtocol == 1)
        XCTAssert(ipv4.headerChecksum == 0x4922)
        XCTAssert(ipv4.options == nil)
        guard case .icmp4(let icmp4) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp4.type == 0)
        XCTAssert(icmp4.code == 0)
        XCTAssert(icmp4.icmpType == .echoReply(identifier: 4997, sequence: 0))
    }
    func testIcmpV4TtlExceeded() {
        let packetStream = "685b35890a0400015c63f84608004500003807cf00004001f19ac0a80001c0a8000a0b00bbe600000000450000348d8c000001116578c0a8000a040202018d8b829b002028d2"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 66)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "00:01:5c:63:f8:46")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x0800)
        XCTAssert(frame.data.count == 70)
        guard case .ipv4(let ipv4) = frame.layer3 else {
            XCTFail()
            return
        }
        //IPv4 packet tests
        XCTAssert(ipv4.sourceIP == IPv4Address("192.168.0.1")!)
        XCTAssert(ipv4.destinationIP == IPv4Address("192.168.0.10")!)
        XCTAssert(ipv4.data.count == 56)
        XCTAssert(ipv4.version == 4)
        XCTAssert(ipv4.ihl == 5)
        XCTAssert(ipv4.dscp == 0)
        XCTAssert(ipv4.ecn == 0)
        XCTAssert(ipv4.totalLength == 56)
        XCTAssert(ipv4.identification == 0x07cf)
        XCTAssert(ipv4.evilBit == false)
        XCTAssert(ipv4.dontFragmentFlag == false)
        XCTAssert(ipv4.moreFragmentsFlag == false)
        XCTAssert(ipv4.fragmentOffset == 0)
        XCTAssert(ipv4.ttl == 64)
        XCTAssert(ipv4.ipProtocol == 1)
        XCTAssert(ipv4.headerChecksum == 0xf19a)
        XCTAssert(ipv4.options == nil)
        guard case .icmp4(let icmp4) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp4.type == 11)
        XCTAssert(icmp4.code == 0)
        XCTAssert(icmp4.icmpType == .ttlExceeded)
    }
    func testIcmpV6EchoRequest() {
        let packetStream = "b07fb95d8ed2685b35890a0486dd600f93be00103a402601064748021620b1d12e6f4ecedded2001055900196098000000000000132480006bc30fbd00005e5c5d81000c17b4"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 66)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.srcmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x86dd)
        XCTAssert(frame.data.count == 70)
        guard case .ipv6(let ipv6) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(ipv6.version == 6)
        XCTAssert(ipv6.trafficClass == 0x00)
        XCTAssert(ipv6.flowLabel == 0xf93be)
        XCTAssert(ipv6.payloadLength == 16)
        XCTAssert(ipv6.nextHeader == 58)
        XCTAssert(ipv6.hopLimit == 64)
        XCTAssert(ipv6.sourceIP == IPv6Address("2601:647:4802:1620:b1d1:2e6f:4ece:dded")!)
        XCTAssert(ipv6.destinationIP == IPv6Address("2001:559:19:6098::1324")!)
        guard case .icmp6(let icmp6) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp6.type == 128)
        XCTAssert(icmp6.code == 0)
        XCTAssert(icmp6.icmpType == .echoRequest(identifier: 0x0fbd, sequence: 0))
        XCTAssert(icmp6.checksum == 0x6bc3)
    }
    func testIcmpV6EchoReply() {
        let packetStream = "685b35890a04b07fb95d8ed286dd6204f95e00103a3b200105590019609800000000000013242601064748021620b1d12e6f4ecedded8100667c0fbd00015e5c5d82000c1bf9"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 70)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x86dd)
        XCTAssert(frame.data.count == 70)
        guard case .ipv6(let ipv6) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(ipv6.version == 6)
        XCTAssert(ipv6.trafficClass == 0x20)
        XCTAssert(ipv6.flowLabel == 0x4f95e)
        XCTAssert(ipv6.payloadLength == 16)
        XCTAssert(ipv6.nextHeader == 58)
        XCTAssert(ipv6.hopLimit == 59)
        XCTAssert(ipv6.sourceIP == IPv6Address("2001:559:19:6098::1324")!)
        XCTAssert(ipv6.destinationIP == IPv6Address("2601:647:4802:1620:b1d1:2e6f:4ece:dded")!)
        guard case .icmp6(let icmp6) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp6.type == 129)
        XCTAssert(icmp6.code == 0)
        XCTAssert(icmp6.icmpType == .echoReply(identifier: 0x0fbd, sequence: 1))
        XCTAssert(icmp6.checksum == 0x667c)
    }
    func testIcmpV6TimeExceeded() {
        let packetStream = "685b35890a04b07fb95d8ed286dd6000000000403aff2601064748021620b27fb9fffe5d8ed22601064748021620b1d12e6f4ecedded03009dcf000000006000a81a001411012601064748021620b1d12e6f4ecedded20010559001960950000000000001324f804829b0014a1f6a4133a3ef07f0df3"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 118)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x86dd)
        XCTAssert(frame.data.count == 118)
        guard case .ipv6(let ipv6) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(ipv6.version == 6)
        XCTAssert(ipv6.trafficClass == 0x00)
        XCTAssert(ipv6.flowLabel == 0x00000)
        XCTAssert(ipv6.payloadLength == 64)
        XCTAssert(ipv6.nextHeader == 58)
        XCTAssert(ipv6.hopLimit == 255)
        XCTAssert(ipv6.sourceIP == IPv6Address("2601:647:4802:1620:b27f:b9ff:fe5d:8ed2")!)
        XCTAssert(ipv6.destinationIP == IPv6Address("2601:647:4802:1620:b1d1:2e6f:4ece:dded")!)
        guard case .icmp6(let icmp6) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp6.type == 3)
        XCTAssert(icmp6.code == 0)
        XCTAssert(icmp6.icmpType == .hopLimitExceeded)
        XCTAssert(icmp6.checksum == 0x9dcf)
    }
    func testIcmpV6NeighborSolicitation() {
        let packetStream = "685b35890a04b07fb95d8ed286dd6000000000203afffe80000000000000b27fb9fffe5d8ed2fe800000000000001867ff5dd25bad6787005ab000000000fe800000000000001867ff5dd25bad670101b07fb95d8ed2"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 86)
        //Frame tests
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
        XCTAssert(ipv6.trafficClass == 0x00)
        XCTAssert(ipv6.flowLabel == 0x00000)
        XCTAssert(ipv6.payloadLength == 32)
        XCTAssert(ipv6.nextHeader == 58)
        XCTAssert(ipv6.hopLimit == 255)
        XCTAssert(ipv6.sourceIP == IPv6Address("fe80::b27f:b9ff:fe5d:8ed2")!)
        XCTAssert(ipv6.destinationIP == IPv6Address("fe80::1867:ff5d:d25b:ad67")!)
        guard case .icmp6(let icmp6) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp6.type == 135)
        XCTAssert(icmp6.code == 0)
        XCTAssert(icmp6.checksum == 0x5ab0)
        XCTAssert(icmp6.icmpType == .neighborSolicitation(target: IPv6Address("fe80::1867:ff5d:d25b:ad67")!))
        XCTAssert(icmp6.options.count == 1)
        XCTAssert(icmp6.options.first! == Icmp6Option.sourceLinkAddress("b0:7f:b9:5d:8e:d2"))
    }
    func testIcmpV6NeighborAdvertisement() {
        let packetStream = "b07fb95d8ed2685b35890a0486dd6000000000183afffe800000000000001867ff5dd25bad67fe80000000000000b27fb9fffe5d8ed28800136940000000fe800000000000001867ff5dd25bad67"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 78)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.srcmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.dstmac == "b0:7f:b9:5d:8e:d2")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x86dd)
        XCTAssert(frame.data.count == 78)
        guard case .ipv6(let ipv6) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(ipv6.version == 6)
        XCTAssert(ipv6.trafficClass == 0x00)
        XCTAssert(ipv6.flowLabel == 0x00000)
        XCTAssert(ipv6.payloadLength == 24)
        XCTAssert(ipv6.nextHeader == 58)
        XCTAssert(ipv6.hopLimit == 255)
        XCTAssert(ipv6.destinationIP == IPv6Address("fe80::b27f:b9ff:fe5d:8ed2")!)
        XCTAssert(ipv6.sourceIP == IPv6Address("fe80::1867:ff5d:d25b:ad67")!)
        guard case .icmp6(let icmp6) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp6.type == 136)
        XCTAssert(icmp6.code == 0)
        XCTAssert(icmp6.checksum == 0x1369)
        XCTAssert(icmp6.icmpType == .neighborAdvertisement(target: IPv6Address("fe80::1867:ff5d:d25b:ad67")!,router: false, solicited: true, override: false))
        XCTAssert(icmp6.options.count == 0)
    }
    func testIcmpV6Redirect() {
        // source credit https://github.com/bro/bro/blob/master/testing/btest/Traces/icmp/icmp6-redirect.pcap
        let packetStream = "ffffffffffff00000000000086dd6000000000283afffe80000000000000000000000000deadfe80000000000000000000000000beef8900593e00000000fe80000000000000000000000000cafefe80000000000000000000000000babe"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 78)
        //Frame tests
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.srcmac == "00:00:00:00:00:00")
        XCTAssert(frame.dstmac == "ff:ff:ff:ff:ff:ff")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x86dd)
        XCTAssert(frame.data.count == 94)
        guard case .ipv6(let ipv6) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(ipv6.version == 6)
        XCTAssert(ipv6.trafficClass == 0x00)
        XCTAssert(ipv6.flowLabel == 0x00000)
        XCTAssert(ipv6.payloadLength == 40)
        XCTAssert(ipv6.nextHeader == 58)
        XCTAssert(ipv6.hopLimit == 255)
        XCTAssert(ipv6.destinationIP == IPv6Address("fe80::beef")!)
        XCTAssert(ipv6.sourceIP == IPv6Address("fe80::dead")!)
        guard case .icmp6(let icmp6) = frame.layer4 else {
            XCTFail()
            return
        }
        XCTAssert(icmp6.type == 137)
        XCTAssert(icmp6.code == 0)
        XCTAssert(icmp6.checksum == 0x593e)
        XCTAssert(icmp6.icmpType == .redirect(target: IPv6Address("fe80::cafe")!,destination: IPv6Address("fe80::babe")!))
        XCTAssert(icmp6.options.count == 0)
    }
    func testArpRequest() {
        let packetStream = "ffffffffffff685b35890a0408060001080006040001685b35890a04c0a8000a000000000000c0a8000b"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 42)
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "ff:ff:ff:ff:ff:ff")
        XCTAssert(frame.srcmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x0806)
        XCTAssert(frame.data.count == 42)
        guard case .arp(let arp) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(arp.hardwareType == 1)
        XCTAssert(arp.protocolType == 0x0800)
        XCTAssert(arp.hardwareSize == 6)
        XCTAssert(arp.protocolSize == 4)
        XCTAssert(arp.operation == .arpRequest)
        XCTAssert(arp.senderEthernet == "68:5b:35:89:0a:04")
        XCTAssert(arp.senderIp == IPv4Address("192.168.0.10")!)
        XCTAssert(arp.targetEthernet == "00:00:00:00:00:00")
        XCTAssert(arp.targetIp == IPv4Address("192.168.0.11")!)
    }
    func testArpReply() {
        let packetStream = "685b35890a046c709fd77258080600010800060400026c709fd77258c0a8000b685b35890a04c0a8000a000000000000000000000000000000000000"
        guard let data = Frame.makeData(packetStream: packetStream) else {
            XCTFail()
            return
        }
        let frame = Frame(data: data, timeval: timeval(), originalLength: 60)
        XCTAssert(frame.frameFormat == .ethernet)
        XCTAssert(frame.dstmac == "68:5b:35:89:0a:04")
        XCTAssert(frame.srcmac == "6c:70:9f:d7:72:58")
        XCTAssert(frame.ieeeLength == nil)
        XCTAssert(frame.ieeeDsap == nil)
        XCTAssert(frame.ieeeControl == nil)
        XCTAssert(frame.snapOrg == nil)
        XCTAssert(frame.snapType == nil)
        XCTAssert(frame.ethertype == 0x0806)
        XCTAssert(frame.data.count == 60)
        guard case .arp(let arp) = frame.layer3 else {
            XCTFail()
            return
        }
        XCTAssert(arp.hardwareType == 1)
        XCTAssert(arp.protocolType == 0x0800)
        XCTAssert(arp.hardwareSize == 6)
        XCTAssert(arp.protocolSize == 4)
        XCTAssert(arp.operation == .arpReply)
        XCTAssert(arp.senderEthernet == "6c:70:9f:d7:72:58")
        XCTAssert(arp.senderIp == IPv4Address("192.168.0.11")!)
        XCTAssert(arp.targetEthernet == "68:5b:35:89:0a:04")
        XCTAssert(arp.targetIp == IPv4Address("192.168.0.10")!)
    }
}
