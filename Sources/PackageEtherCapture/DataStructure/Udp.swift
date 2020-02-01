//
//  Udp.swift
//  
//
//  Created by Darrell Root on 1/29/20.
//

import Foundation

public struct Udp: EtherDisplay, Codable {
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
    
    init?(data: Data) {
        guard data.count >= 8 else {
            debugPrint("incomplete UDP datagram detected")
            return nil
        }
        self.data = data
        self.sourcePort = UInt(data[data.startIndex]) * 256 + UInt(data[data.startIndex + 1])
        self.destinationPort = UInt(data[data.startIndex + 2]) * 256 + UInt(data[data.startIndex + 3])
        self.length = UInt(data[data.startIndex + 4]) * 256 + UInt(data[data.startIndex + 5])
        self.checksum = UInt(data[data.startIndex + 6]) * 256 + UInt(data[data.startIndex + 7])
        self.payload = Data(data[(data.startIndex + 8) ..< data.endIndex])

    }
}
