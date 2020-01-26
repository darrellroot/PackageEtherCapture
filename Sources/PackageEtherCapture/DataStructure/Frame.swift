//
//  Frame.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

public struct Frame: CustomStringConvertible {
    var description: String {
        let ethertypeString = String(format: "%04x",ethertype)
        return "\(date) \(srcmac) \(dstmac) \(ethertypeString) \(contents)"
    }
    
    //var timeval: timeval
    var date: Date
    var srcmac: String = "unknown"
    var dstmac: String = "unknown"
    var ethertype: UInt = 0
    var contents: Layer3
    
    init(data: Data, timeval: timeval) {
        self.date = Date(timeIntervalSince1970: Double(timeval.tv_sec))
        self.date += Double(timeval.tv_usec)/1000000.0
        if data.count > 5 {
            srcmac = "\(data[0].hex):\(data[1].hex):\(data[3].hex):\(data[4].hex):\(data[5].hex):\(data[6].hex)"
        }
        if data.count > 11 {
            dstmac = "\(data[6].hex):\(data[7].hex):\(data[8].hex):\(data[9].hex):\(data[10].hex):\(data[11].hex)"
        }
        if data.count > 13 {
            let unsure = UInt(data[12]) * 256 + UInt(data[13])
            if unsure >= 1500 {
                self.ethertype = unsure
            } else {
                if data.count > 15 {
                    self.ethertype = UInt(data[14]) * 256 + UInt(data[15])
                }
            }
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
