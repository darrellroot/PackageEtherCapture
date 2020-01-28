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
public struct Frame: CustomStringConvertible {
    /**
     - Returns: One line summary of the frame and packet contents
     */
    public var description: String {
        let ethertypeString = String(format: "%04x",ethertype)
        return "\(srcmac) \(dstmac) \(ethertypeString) \(layer3)"
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
    public let ethertype: UInt // ethertype of 0 is an error
    /**
     - Parameter layer3: Nested data structure with higher layer information
     */
    public let layer3: Layer3
    /**
     - Parameter data: Total frame contents as captured
     */
    public let data: Data  // total frame contents
    
    init(data: Data, timeval: timeval) {
        self.data = data
        self.date = Date(timeIntervalSince1970: Double(timeval.tv_sec)) + Double(timeval.tv_usec)/1000000.0
        if data.count > 5 {
            srcmac = "\(data[0].hex):\(data[1].hex):\(data[3].hex):\(data[4].hex):\(data[5].hex):\(data[6].hex)"
        } else {
            srcmac = "unknown"
        }
        if data.count > 11 {
            dstmac = "\(data[6].hex):\(data[7].hex):\(data[8].hex):\(data[9].hex):\(data[10].hex):\(data[11].hex)"
        } else {
            dstmac = "unknown"
        }
        if data.count > 13 {
            let unsure = UInt(data[12]) * 256 + UInt(data[13])
            if unsure >= 1500 {
                self.ethertype = unsure
            } else {
                if data.count > 15 {
                    self.ethertype = UInt(data[14]) * 256 + UInt(data[15])
                } else {
                    ethertype = 0
                }
            }
        } else {
            ethertype = 0
        }
        switch self.ethertype {
        case 0x0800:
            if let ipv4 = IPv4(data: data[14..<data.count]) {
                self.layer3 = .ipv4(ipv4)
            } else {
                let unknown = Unknown(data: data[14..<data.count])
                self.layer3 = .unknown(unknown)
            }
        case 0x86dd:
            if let ipv6 = IPv6(data: data[14..<data.count]) {
                self.layer3 = .ipv6(ipv6)
            } else {
                let unknown = Unknown(data: data[14..<data.count])
                self.layer3 = .unknown(unknown)
            }
        default:
            let unknown = Unknown(data: data[14..<data.count])
            self.layer3 = .unknown(unknown)
        }
        
    }
}
