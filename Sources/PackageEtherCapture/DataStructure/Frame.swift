//
//  Frame.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation
import Logging

/**
 Top-level data structure for a frame capture from the network.
 */
public struct Frame: CustomStringConvertible, EtherDisplay, Identifiable {
    static var frameCount = 0   // used to make frameNumber if not specified in initializer (which our pcap_loop cannot do because it cannot capture context
    /**
     - Parameter date: pcap timestamp the frame was captured
     */
    public let id = UUID()
    public let frameNumber: Int
    public let date: Date    // pcap timestamp of packet capture
    public let srcmac: String
    public let dstmac: String
    public var frameFormat: FrameFormat  //should be let but compiler complains
    // Had trouble getting compiler to admit next 5 variables initialized
    // so used var
    public var ieeeLength: UInt? = nil  //802.2 802.3 encapsulation
    public var ieeeDsap: UInt8? = nil
    public var ieeeSsap: UInt8? = nil
    public var ieeeControl: UInt8? = nil
    public var snapOrg: UInt? = nil  //802.2 SNAP header
    public var snapType: UInt? = nil   //802.2 SNAP header
    public var ethertype: UInt? = nil // ethernetII encapsulation
    public var originalLength: Int // used for generating pcap

    public var padding: Data?  // for 802.2 only
    public var paddingBytes = 0
    
    public var startIndex: [Field:Data.Index] = [:] //first byte of the field
    public var endIndex: [Field:Data.Index] = [:]  //1 past last byte of the field
    /**
     - Parameter layer3: Nested data structure with higher layer information
     */
    public var layer3: Layer3 = .unknown(Unknown.completely)
    
    public var layer4: Layer4? {
        switch self.layer3 {
        case .ipv4(let ipv4):
            return ipv4.layer4
        case .ipv6(let ipv6):
            return ipv6.layer4
        case .arp(_),.bpdu(_), .cdp(_), .lldp(_):
            return .noLayer4    // bpdu does not have layer 4
        case .unknown(let unknown):
            return nil
        }
    }
    
    /**
     - Parameter data: Total frame contents as captured
     */
    public let data: Data  // total frame contents
    
    public init(data: Data, timeval: timeval = timeval(), originalLength: Int, frameNumber: Int? = nil) {
        if let frameNumber = frameNumber {
            self.frameNumber = frameNumber
        } else {
            Frame.frameCount += 1
            self.frameNumber = Frame.frameCount
        }
        self.data = data
        self.originalLength = originalLength
        self.date = Date(timeIntervalSince1970: Double(timeval.tv_sec)) + Double(timeval.tv_usec)/1000000.0
        guard data.count > 17 else {
            EtherCapture.logger.error("Error: short frame detected size \(data.count) unable to analyze")
            self.srcmac = "unknown"
            self.dstmac = "unknown"
            self.frameFormat = .invalid
            let unknown = Unknown(data: Data())
            self.layer3 = .unknown(unknown)
            return
        }
        if data.count > 5 {
            dstmac = "\(data[data.startIndex + 0].hex):\(data[data.startIndex + 1].hex):\(data[data.startIndex + 2].hex):\(data[data.startIndex + 3].hex):\(data[data.startIndex + 4].hex):\(data[data.startIndex + 5].hex)"
            startIndex[.dstmac] = data.startIndex + 0
            endIndex[.dstmac] = data.startIndex + 6
        } else {
            dstmac = "unknown"
        }
        if data.count > 11 {
            srcmac = "\(data[data.startIndex + 6].hex):\(data[data.startIndex + 7].hex):\(data[data.startIndex + 8].hex):\(data[data.startIndex + 9].hex):\(data[data.startIndex + 10].hex):\(data[data.startIndex + 11].hex)"
            startIndex[.srcmac] = data.startIndex + 6
            endIndex[.srcmac] = data.startIndex + 12
        } else {
            srcmac = "unknown"
        }
        let unsure: UInt = UInt(data[data.startIndex + 12]) * 256 + UInt(data[data.startIndex + 13]) // could be ethertype or length
        
        let frameFormat: FrameFormat
        
        if unsure > 0x5dc {
            frameFormat = .ethernet
            ethertype = unsure
            startIndex[.ethertype] = data.startIndex + 12
            endIndex[.ethertype] = data.startIndex + 14
            self.frameFormat = .ethernet
            self.ieeeLength = nil
            self.ieeeDsap = nil
            self.ieeeSsap = nil
            
            
        } else {
            frameFormat = .ieee8023
            self.ieeeLength = unsure
            startIndex[.ieeeLength] = data.startIndex + 12
            endIndex[.ieeeLength] = data.startIndex + 14
            self.ieeeDsap = UInt8(data[data.startIndex + 14])
            startIndex[.ieeeDsap] = data.startIndex + 14
            endIndex[.ieeeDsap] = data.startIndex + 15
            self.ieeeSsap = UInt8(data[data.startIndex + 15])
            startIndex[.ieeeSsap] = data.startIndex + 15
            endIndex[.ieeeSsap] = data.startIndex + 16
            self.ieeeControl = UInt8(data[data.startIndex + 16])
            startIndex[.ieeeControl] = data.startIndex + 16
            endIndex[.ieeeControl] = data.startIndex + 17
            self.ethertype = nil
            
            if data.count > unsure + 14 {
                self.padding = data[data.startIndex + Int(unsure) + 14 ..< data.endIndex]
                startIndex[.padding] = data.startIndex + Int(unsure) + 14
                endIndex[.padding] = data.endIndex
                self.paddingBytes = data.endIndex - (data.startIndex + Int(unsure))
            }
        }
        self.frameFormat = frameFormat

        switch (frameFormat, unsure, UInt(data[data.startIndex + 14])) {
            
        case (.invalid,_,_):  // should not get here
            break
        case (.ieee8023,_,0x42): // spanning tree
            if let bpdu = Bpdu(data: data[data.startIndex + 17 ..< data.endIndex]) {
                self.layer3 = .bpdu(bpdu)
            } else {
                let unknown = Unknown(data: data[data.startIndex + 17 ..< data.endIndex])
                self.layer3 = .unknown(unknown)
            }
        case (.ieee8023,_,0x98): // ARP
            let unknown = Unknown(data: data[data.startIndex + 17..<data.endIndex])
            self.layer3 = .unknown(unknown)
        case (.ieee8023,_,0xaa): //SNAP, add 802.2 SNAP, might be CDP
            //TODO
            self.snapOrg = UInt(data[data.startIndex + 17]) * 256 * 256 + UInt(data[data.startIndex + 18]) * 256 + UInt(data[data.startIndex + 19])
            startIndex[.snapOrg] = data.startIndex + 17
            endIndex[.snapOrg] = data.startIndex + 20
            self.snapType = UInt(data[data.startIndex + 20]) * 256 + UInt(data[data.startIndex + 21])
            startIndex[.snapType] = data.startIndex + 20
            endIndex[.snapType] = data.startIndex + 22
            if self.snapOrg == 0xc, self.snapType == 0x2000, let cdp = Cdp(data: data[data.startIndex + 22..<data.endIndex]) {
                self.layer3 = .cdp(cdp)
            } else {
                let unknown = Unknown(data: data[data.startIndex + 22..<data.endIndex])
                self.layer3 = .unknown(unknown)
            }
        case (.ieee8023,_,_): // default case for 802.3
            let unknown = Unknown(data: data[data.startIndex + 17..<data.endIndex])
            self.layer3 = .unknown(unknown)
        case (.ethernet,0 ..< 0x5dc, _):     //802.3 length field detected in ethernet!
            // should not get here
            break
        case (.ethernet,0x0800,_):  // IPv4
            let ipv4TotalLength = Int(EtherCapture.getUInt16(data: data[data.startIndex + 16 ..< data.startIndex + 18]))
            if data.endIndex > 14 + ipv4TotalLength {
                self.padding = data[data.startIndex + 14 + ipv4TotalLength ..< data.endIndex]
                self.paddingBytes = self.padding?.count ?? 0
                startIndex[.padding] = data.startIndex + ipv4TotalLength + 14
                endIndex[.padding] = data.endIndex
            }
            if let ipv4 = IPv4(data: data[data.startIndex + 14..<data.endIndex - self.paddingBytes]) {
                self.layer3 = .ipv4(ipv4)
            } else {
                let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
                self.layer3 = .unknown(unknown)
            }
        case (.ethernet,0x0806,_):  // Arp
            if let arp = Arp(data: data[data.startIndex + 14..<data.endIndex]) {
                self.layer3 = .arp(arp)
            } else {
                let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
                self.layer3 = .unknown(unknown)
            }
        case (.ethernet,0x86dd,_): // IPv6
            if let ipv6 = IPv6(data: data[data.startIndex + 14..<data.endIndex]) {
                self.layer3 = .ipv6(ipv6)
            } else {
                let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
                self.layer3 = .unknown(unknown)
            }
        case (.ethernet,0x88cc,_): // LLDP
            if let lldp = Lldp(data: data[data.startIndex + 14..<data.endIndex]) {
                self.layer3 = .lldp(lldp)
            } else {
                let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
                self.layer3 = .unknown(unknown)
            }
        case (.ethernet,_,_): // other Ethernet
            let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
            self.layer3 = .unknown(unknown)
        /*@unknown default:
            let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
            self.layer3 = .unknown(unknown)*/
        }
    }
    
    //This function takes hexStream output from wireshark and turns it
    //into Data suitable for importing into the Frame initializer
    //Example:
    //let packetStream = "ffffffffffff685b35890a0408060001080006040001685b35890a04c0a8000a000000000000c0a8000b"
    //let data = Frame.makeData(packetStream: packetStream)!
    public static func makeData(packetStream: String) -> Data? {
        var total = 0
        var data = Data(capacity: (packetStream.count / 2 + 1))
        for (count,char) in packetStream.enumerated() {
            guard let charValue = Int(String(char), radix: 16) else {
                EtherCapture.logger.error("makeData: invalid char \(char) at position \(count)")
                return nil
            }
            if count % 2 == 0 {
                total = charValue * 16
            } else {
                total = total + charValue
                data.append(UInt8(total))
            }
        }
        return data
    }
    /**
     - Returns: One line verbose information frame header only
     */
    public var ieeeLengthString: String {
        if let ieeeLength = ieeeLength {
            return "LEN \(ieeeLength)"
        } else {
            return ""  //if optional does not exist, dont add ending space
        }
    }
    public var dsapString: String {
        if let ieeeDsap = ieeeDsap {
            return "DSAP 0x\(ieeeDsap.hex)"
        } else {
            return ""
        }
    }
    public var ssapString: String {
        if let ieeeSsap = ieeeSsap {
            return "SSAP 0x\(ieeeSsap.hex)"
        } else {
            return ""
        }
    }
    public var controlString: String {
        if let ieeeControl = ieeeControl {
            return "CONTROL 0x\(ieeeControl.hex)"
        } else {
            return ""
        }
    }
    public var orgString: String {
        if let snapOrg = snapOrg {
            return "SNAP Org 0x\(String(format: "%6x ",snapOrg))"
        } else {
            return ""
        }
    }
    public var snapTypeString: String {
        if let snapType = snapType {
            return "SnapType \(snapType.hex4)"
        } else {
            return ""
        }
    }
    public var ethertypeString: String {
        if let ethertype = ethertype {
            return "Ethertype \(ethertype.hex4)"
        } else {
            return ""
        }
    }
    public var verboseDescription: String {
        let length: String
        if let ieeeLength = ieeeLength {
            length = "LEN \(ieeeLength) "  //provide 1 space on end
        } else {
            length = ""  //if optional does not exist, dont add ending space
        }
        let padString: String
        if let padding = padding, padding.count > 0 {
            padString = "\(padding) padding "
        } else {
            padString = ""
        }
        let dsap: String
        if let ieeeDsap = ieeeDsap {
            dsap = "DSAP 0x\(ieeeDsap.hex) "
        } else {
            dsap = ""
        }
        let ssap: String
        if let ieeeSsap = ieeeSsap {
            ssap = "SSAP 0x\(ieeeSsap.hex) "
        } else {
            ssap = ""
        }
        let control: String
        if let ieeeControl = ieeeControl {
            control = "CONTROL 0x\(ieeeControl.hex) "
        } else {
            control = ""
        }
        let org: String
        if let snapOrg = snapOrg {
            org = "SNAP Org 0x\(String(format: "%6x ",snapOrg)) "
        } else {
            org = ""
        }
        let sType: String
        if let snapType = snapType {
            sType = "SType 0x\(String(format: "%4x ",snapType)) "
        } else {
            sType = ""
        }
        let eType: String
        if let ethertype = ethertype {
            eType = "Ethertype \(ethertype.hex4) "
        } else {
            eType = ""
        }

        //each optional has 1 space at end provided above
        return "\(srcmac) > \(dstmac) \(frameFormat) \(length)\(dsap)\(ssap)\(control)\(org)\(sType)\(eType)\(padString)"
    }
    /**
     - Returns: One line summary of the frame and packet contents
     */
    public var description: String {
        let ethertypeString: String
        if let ethertype = ethertype {
            ethertypeString = ethertype.hex4
        } else if let ieeeDsap = ieeeDsap, let ieeeSsap = ieeeSsap {
            ethertypeString = String(format: "0x%2x",ieeeDsap) + String(format: "%02x",ieeeSsap)
        } else {
            ethertypeString = "unknown"
        }
        return "\(srcmac) \(dstmac) \(frameFormat) \(ethertypeString) \(layer3) \(layer4?.description ?? "")"
    }
    
    /**
    - Returns: Hexdump printout of frame contents
    */
    public var hexdump: String {
        return self.data.hexdump
    }

    /**
     - Returns: A sample frame suitable for content view previews
     */
    public static let sampleFrame: Frame = Frame(data: makeData(packetStream: "685b35890a04c869cd2c0d50080045000034000040004006b959c0a80010c0a8000ac001de7ebc1aa99e868a316380100804203100000101080a872fd3281be79ab6")!, originalLength: 200)

    public static let sampleFrameUdp: Frame = Frame(data: makeData(packetStream: "01005e0000fb9ce65e8ed42608004500005f30340000ff11e992c0a80023e00000fb14e914e9004bccdc0000840000000001000000000f5f636f6d70616e696f6e2d6c696e6b045f746370056c6f63616c00000c00010000000000110e4c616e2773206950616420283229c00c")!, originalLength: 109)
    
    //icmp v4 echo request
    public static let sampleFrameIcmp4: Frame = Frame(data: makeData(packetStream: "b07fb95d8ed2685b35890a04080045000054db2d000040010000c0a8000a040202010800df8a138500005e5b412b00017a6508090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")!, originalLength: 98)
    
    // icmp v6 neighbor advertisement
    public static let sampleFrameIcmp6: Frame = Frame(data: makeData(packetStream: "b07fb95d8ed2685b35890a0486dd6000000000183afffe800000000000001867ff5dd25bad67fe80000000000000b27fb9fffe5d8ed28800136940000000fe800000000000001867ff5dd25bad67")!,originalLength: 78)
}
