//
//  Udp.swift
//  
//
//  Created by Darrell Root on 1/29/20.
//

import Foundation
import Logging

public struct Udp: EtherDisplay {
    public var description: String {
        return "\(sourcePort) > \(destinationPort) length \(length)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    public var verboseDescription: String {
           return "UDP \(sourcePort) > \(destinationPort) length \(length) checksum \(checksum)"
    }
    
    public let data: Data
    public let payload: Data
    public let sourcePort: UInt
    public let destinationPort: UInt
    public let length: UInt
    public let checksum: UInt
    
    public var startIndex: [Field:Data.Index] = [:] //first byte of the field
    public var endIndex: [Field:Data.Index] = [:]  //1 past last byte of the field

    init?(data: Data) {
        guard data.count >= 8 else {
            EtherCapture.logger.error("incomplete UDP datagram detected")
            return nil
        }
        self.data = data
        self.sourcePort = UInt(data[data.startIndex]) * 256 + UInt(data[data.startIndex + 1])
        startIndex[.sourcePort] = data.startIndex
        endIndex[.sourcePort] = data.startIndex + 2
        
        self.destinationPort = UInt(data[data.startIndex + 2]) * 256 + UInt(data[data.startIndex + 3])
        startIndex[.destinationPort] = data.startIndex + 2
        endIndex[.destinationPort] = data.startIndex + 4

        self.length = UInt(data[data.startIndex + 4]) * 256 + UInt(data[data.startIndex + 5])
        startIndex[.length] = data.startIndex + 4
        endIndex[.destinationPort] = data.startIndex + 6

        self.checksum = UInt(data[data.startIndex + 6]) * 256 + UInt(data[data.startIndex + 7])
        startIndex[.checksum] = data.startIndex + 6
        endIndex[.checksum] = data.startIndex + 8

        self.payload = Data(data[(data.startIndex + 8) ..< data.endIndex])
        startIndex[.payload] = data.startIndex + 8
        endIndex[.payload] = data.endIndex

        //TODO possibly fix length and padding
    }
}
