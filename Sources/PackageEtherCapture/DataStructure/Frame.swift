//
//  Frame.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

/**
 Top-level data structure for a frame capture from the network.
 */
public struct Frame: CustomStringConvertible, EtherDisplay {
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
     - Returns: One line verbose information frame header only
     */
    public var verboseDescription: String {
        let length: String
        if let ieeeLength = ieeeLength {
            length = "LEN \(ieeeLength) "  //provide 1 space on end
        } else {
            length = ""  //if optional does not exist, dont add ending space
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
        return "\(srcmac) > \(dstmac) \(frameFormat) \(length)\(dsap)\(ssap)\(control)\(org)\(sType)\(eType)"
    }
    
    /**
    - Returns: Hexdump printout of frame contents
    */
    public var hexdump: String {
        return self.data.hexdump
    }
    /**
     - Parameter date: pcap timestamp the frame was captured
     */
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
    /**
     - Parameter layer3: Nested data structure with higher layer information
     */
    public var layer3: Layer3 = .unknown(Unknown.completely)
    /**
     - Parameter data: Total frame contents as captured
     */
    public let data: Data  // total frame contents
    
    init(data: Data, timeval: timeval) {
        self.data = data
        self.date = Date(timeIntervalSince1970: Double(timeval.tv_sec)) + Double(timeval.tv_usec)/1000000.0
        guard data.count > 17 else {
            debugPrint("Error: short frame detected size \(data.count) unable to analyze")
            self.srcmac = "unknown"
            self.dstmac = "unknown"
            self.frameFormat = .invalid
            let unknown = Unknown(data: Data())
            self.layer3 = .unknown(unknown)
            return
        }
        if data.count > 5 {
            dstmac = "\(data[0].hex):\(data[1].hex):\(data[2].hex):\(data[3].hex):\(data[4].hex):\(data[5].hex)"
        } else {
            dstmac = "unknown"
        }
        if data.count > 11 {
            srcmac = "\(data[6].hex):\(data[7].hex):\(data[8].hex):\(data[9].hex):\(data[10].hex):\(data[11].hex)"
        } else {
            srcmac = "unknown"
        }
        let unsure: UInt = UInt(data[12]) * 256 + UInt(data[13]) // could be ethertype or length
        
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
            self.ieeeDsap = UInt8(data[14])
            self.ieeeSsap = UInt8(data[15])
            self.ieeeControl = UInt8(data[16])
            self.ethertype = nil
        }
        self.frameFormat = frameFormat

        switch (frameFormat, unsure, UInt(data[14])) {
            
        case (.invalid,_,_):  // should not get here
            break
        case (.ieee8023,_,0x42): // spanning tree
            //TODO
            let unknown = Unknown(data: data[17..<data.count])
            self.layer3 = .unknown(unknown)
        case (.ieee8023,_,0x98): // ARP
            let unknown = Unknown(data: data[17..<data.count])
            self.layer3 = .unknown(unknown)
        case (.ieee8023,_,0xaa): //SNAP, add 802.2 SNAP, might be CDP
            //TODO
            self.snapOrg = UInt(data[17]) * 256 * 256 + UInt(data[18]) * 256 + UInt(data[19])
            self.snapType = UInt(data[20]) * 256 + UInt(data[21])
            let unknown = Unknown(data: data[20..<data.count])
            self.layer3 = .unknown(unknown)
        case (.ieee8023,_,_): // default case for 802.3
            let unknown = Unknown(data: data[17..<data.count])
            self.layer3 = .unknown(unknown)
        case (.ethernet,0 ..< 0x5dc, _):     //802.3 length field detected in ethernet!
            // should not get here
            break
        case (.ethernet,0x0800,_):  // IPv4
            if let ipv4 = IPv4(data: data[14..<data.count]) {
                self.layer3 = .ipv4(ipv4)
            } else {
                let unknown = Unknown(data: data[14..<data.count])
                self.layer3 = .unknown(unknown)
            }
        case (.ethernet,0x86dd,_): // IPv6
            if let ipv6 = IPv6(data: data[14..<data.count]) {
                self.layer3 = .ipv6(ipv6)
            } else {
                let unknown = Unknown(data: data[14..<data.count])
                self.layer3 = .unknown(unknown)
            }
        case (.ethernet,_,_): // other Ethernet
            let unknown = Unknown(data: data[14..<data.count])
            self.layer3 = .unknown(unknown)
        /*@unknown default:
            let unknown = Unknown(data: data[14..<data.count])
            self.layer3 = .unknown(unknown)*/
        }
    }
}
