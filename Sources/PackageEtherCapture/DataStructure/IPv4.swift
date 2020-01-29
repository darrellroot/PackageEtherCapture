//
//  IPv4.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation
import Network

public struct IPv4: CustomStringConvertible {
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
    
    public var description: String {
        return "IPv\(version) \(sourceIP) > \(destinationIP) Len \(totalLength) ttl \(ttl) ipProt \(ipProtocol)"
    }
    public var optionsAny: String {
        if options != nil {
            return "OPTIONS"
        } else {
            return ""
        }
    }
    public var verboseDescription: String {
        
        return "IPv\(version) \(sourceIP) > \(destinationIP) IHL \(ihl) DSCP \(dscp.hex) ECN \(ecn.hex) TotLen \(totalLength) id \(identification) NoFrag \(dontFragmentFlag) MoreFrag \(moreFragmentsFlag) FragOff \(fragmentOffset) TTL \(ttl) IpProt \(ipProtocol) HdrChecksum \(headerChecksum) \(optionsAny)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    init?(data: Data) {
        guard data.count >= 20 else {
            return nil
        }
        self.data = data
        self.version = (data[data.startIndex] & 0b11110000) >> 4
        let ihl = data[data.startIndex] & 0b00001111
        self.ihl = ihl
        self.dscp = (data[data.startIndex + 1] & 0b11111100) >> 2
        self.ecn = (data[data.startIndex + 1] & 0b00000011)
        self.totalLength = UInt(data[data.startIndex + 2]) * 256 + UInt(data[data.startIndex + 3])
        self.identification = UInt(data[data.startIndex + 4]) * 256 + UInt(data[data.startIndex + 5])

        self.dontFragmentFlag = data[data.startIndex + 6] & 0b01000000 != 0
        self.evilBit = data[data.startIndex + 6] & 0b10000000 != 0
        self.moreFragmentsFlag = data[data.startIndex + 6] & 0b00100000 != 0
        
        self.fragmentOffset = UInt(data[data.startIndex + 6] & 0b00011111) * 256 + UInt(data[data.startIndex + 7])
        
        self.ttl = data[data.startIndex + 8]
        self.ipProtocol = data[data.startIndex + 9]
        self.headerChecksum = UInt(data[data.startIndex + 10]) * 256 + UInt(data[data.startIndex + 11])
        
        if let sourceIP = IPv4Address(data[data.startIndex + 12 ..< data.startIndex + 16]) {
            self.sourceIP = sourceIP
        } else {
            return nil
        }
        if let destinationIP = IPv4Address(data[data.startIndex + 16 ..< data.startIndex + 20]) {
            self.destinationIP = destinationIP
        } else {
            return nil
        }
        
        if ihl > 20 && data.count >= ihl {
            self.options = data[data.startIndex + 20 ..< data.startIndex + Int(ihl)]
        } else {
            self.options = nil
        }
    }
}
