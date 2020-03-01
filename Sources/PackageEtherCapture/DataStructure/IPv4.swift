//
//  IPv4.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation
import Network
import Logging

public struct IPv4: CustomStringConvertible, EtherDisplay {
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
    public let padding: Data
    
    //public let payload: Data?
    /**
     - Parameter layer4: Nested data structure with higher layer information
     */
    public var layer4: Layer4 = .unknown(Unknown.completely)

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
        
        return "IPv\(version) \(sourceIP) > \(destinationIP) IHL \(ihl) DSCP \(dscp.hex) ECN \(ecn.hex) TotLen \(totalLength) id \(identification) NoFrag \(dontFragmentFlag) MoreFrag \(moreFragmentsFlag) FragOff \(fragmentOffset) TTL \(ttl) IpProt \(ipProtocol) HdrChecksum \(headerChecksum) \(optionsAny) Padding \(padding.count) Bytes"
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
        guard ihl >= 5 else {
            EtherCapture.logger.error("IPv4: Invalid ihl \(ihl) detected")
            return nil
        }
        self.dscp = (data[data.startIndex + 1] & 0b11111100) >> 2
        self.ecn = (data[data.startIndex + 1] & 0b00000011)
        let totalLength = UInt(data[data.startIndex + 2]) * 256 + UInt(data[data.startIndex + 3])
        self.totalLength = totalLength
        // deal with padding
        if data.count > totalLength {
            self.padding = data.advanced(by: Int(totalLength))
        } else {
            self.padding = Data()
        }
    
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
        
        let finalHeaderIndex = data.startIndex + 4 * Int(ihl)
        if data.count >= finalHeaderIndex, ihl > 5 {
            self.options = data[data.startIndex + 20 ..< finalHeaderIndex]
        } else {
            self.options = nil
        }
        
        if finalHeaderIndex >= data.endIndex {  // invalid case
            self.layer4 = .unknown(Unknown.completely)
        } else {
            switch ipProtocol {
            case 1:
                if let icmp4 = Icmp4(data: data[data.startIndex + 4 * Int(ihl) ..< data.endIndex]) {
                    self.layer4 = .icmp4(icmp4)
                } else {
                    self.layer4 = .unknown(Unknown(data: data[finalHeaderIndex ..< data.endIndex]))
                }
            case 6:
                //let myData = Data(data[data.startIndex + 4 * Int(ihl) ..< data.endIndex])
                //if let tcp = Tcp(data: myData) {
                if let tcp = Tcp(data: data[data.startIndex + 4 * Int(ihl) ..< data.endIndex]) {
                    self.layer4 = .tcp(tcp)
                } else {
                    self.layer4 = .unknown(Unknown(data: data[finalHeaderIndex ..< data.endIndex]))
                }
            case 17:
                if let udp = Udp(data: data[finalHeaderIndex ..< data.endIndex]) {
                    self.layer4 = .udp(udp)
                } else {
                    self.layer4 = .unknown(Unknown(data: data[finalHeaderIndex ..< data.endIndex]))
                }
            default:
                self.layer4 = .unknown(Unknown(data: data[finalHeaderIndex ..< data.endIndex]))
            }
            
        }// if finalHeaderIndex >= data.endIndex else
    }
}
