//
//  Frame.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

public struct Frame: CustomStringConvertible {
    public var description: String {
        let ethertypeString = String(format: "%04x",ethertype)
        return "\(srcmac) \(dstmac) \(ethertypeString) \(contents)"
    }
    
    public var hexdump: String {
        debugPrint("generating frame hexdump")
        var output: String = ""
        output.reserveCapacity(data.count * 3)
        for (position,datum) in self.data.enumerated() {
            switch (position % 2 == 0, position % 16 == 0, position % 16 == 15) {
            case (false, false, false): // odd positions
                output.append(datum.hex)
                output.append(" ")
            case (false, false, true): // end of line, odd
                output.append(datum.hex)
                output.append("\n")
            case (true, true, false):  // beginning of line, even
                output.append(String(format: "0x%04x",position))
                output.append(datum.hex)
            case (true, false, false): // even but not beginning of line
                output.append(datum.hex)
            case (false, true, false),(false, true, true),(true, false, true),(true, true, true):  // invalid cases
                debugPrint("unexpected hexdump case")
            }
        }
        if data.count % 16 != 15 {  // adding newline if we didn't just do that
            output.append("\n")
        }
        return output
    }
    //var timeval: timeval
    public let date: Date    // pcap timestamp of packet capture
    public let srcmac: String
    public let dstmac: String
    public let ethertype: UInt // ethertype of 0 is an error
    public let contents: Layer3
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
                self.contents = .ipv4(ipv4)
            } else {
                let unknown = Unknown(data: data[14..<data.count])
                self.contents = .unknown(unknown)
            }
        case 0x86dd:
            if let ipv6 = IPv6(data: data[14..<data.count]) {
                self.contents = .ipv6(ipv6)
            } else {
                let unknown = Unknown(data: data[14..<data.count])
                self.contents = .unknown(unknown)
            }
        default:
            let unknown = Unknown(data: data[14..<data.count])
            self.contents = .unknown(unknown)
        }
        
    }
}
