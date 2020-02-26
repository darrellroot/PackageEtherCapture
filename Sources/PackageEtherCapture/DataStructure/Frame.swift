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
    
    /**
     - Parameter date: pcap timestamp the frame was captured
     */
    public let id = UUID()
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
        case .bpdu(let bpdu):
            return .noLayer4    // bpdu does not have layer 4
        case .unknown(let unknown):
            return nil
        }
    }
    
    /**
     - Parameter data: Total frame contents as captured
     */
    public let data: Data  // total frame contents
    
    public init(data: Data, timeval: timeval = timeval(), originalLength: Int) {
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
        } else {
            dstmac = "unknown"
        }
        if data.count > 11 {
            srcmac = "\(data[data.startIndex + 6].hex):\(data[data.startIndex + 7].hex):\(data[data.startIndex + 8].hex):\(data[data.startIndex + 9].hex):\(data[data.startIndex + 10].hex):\(data[data.startIndex + 11].hex)"
        } else {
            srcmac = "unknown"
        }
        let unsure: UInt = UInt(data[data.startIndex + 12]) * 256 + UInt(data[data.startIndex + 13]) // could be ethertype or length
        
        let frameFormat: FrameFormat
        
        if unsure > 0x5dc {
            frameFormat = .ethernet
            ethertype = unsure
            self.frameFormat = .ethernet
            self.ieeeLength = nil
            self.ieeeDsap = nil
            self.ieeeSsap = nil
        } else {
            frameFormat = .ieee8023
            self.ieeeLength = unsure
            self.ieeeDsap = UInt8(data[data.startIndex + 14])
            self.ieeeSsap = UInt8(data[data.startIndex + 15])
            self.ieeeControl = UInt8(data[data.startIndex + 16])
            self.ethertype = nil
            
            if data.count > unsure + 14 {
                self.padding = data.advanced(by: (Int(unsure + 14)))
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
            self.snapType = UInt(data[data.startIndex + 20]) * 256 + UInt(data[data.startIndex + 21])
            let unknown = Unknown(data: data[data.startIndex + 20..<data.endIndex])
            self.layer3 = .unknown(unknown)
        case (.ieee8023,_,_): // default case for 802.3
            let unknown = Unknown(data: data[data.startIndex + 17..<data.endIndex])
            self.layer3 = .unknown(unknown)
        case (.ethernet,0 ..< 0x5dc, _):     //802.3 length field detected in ethernet!
            // should not get here
            break
        case (.ethernet,0x0800,_):  // IPv4
            if let ipv4 = IPv4(data: data[data.startIndex + 14..<data.endIndex]) {
                self.layer3 = .ipv4(ipv4)
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
        case (.ethernet,_,_): // other Ethernet
            let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
            self.layer3 = .unknown(unknown)
        /*@unknown default:
            let unknown = Unknown(data: data[data.startIndex + 14..<data.endIndex])
            self.layer3 = .unknown(unknown)*/
        }
    }
    
    static func makeData(packetStream: String) -> Data? {
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
            eType = "Ethertype 0x\(String(format: "%4x ",ethertype)) "
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
            ethertypeString = String(format: "0x%4x",ethertype)
        } else if let ieeeDsap = ieeeDsap, let ieeeSsap = ieeeSsap {
            ethertypeString = String(format: "0x%2x",ieeeDsap) + String(format: "%02x",ieeeSsap)
        } else {
            ethertypeString = "unknown"
        }
        return "\(srcmac) \(dstmac) \(frameFormat) \(ethertypeString) \(layer3)"
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

}
