//
//  Tcp.swift
//  
//
//  Created by Darrell Root on 1/29/20.
//

import Foundation

public struct Tcp: EtherDisplay {
    public var flags: String {
        var output = ""
        if self.syn {
            output.append("S")
        }
        if self.urg {
            output.append("U")
        }
        if self.ack {
            output.append("A")
        }
        if self.psh {
            output.append("P")
        }
        if self.rst {
            output.append("R")
        }
        if self.fin {
            output.append("F")
        }
        return output
    }
    public var description: String {
        return "TCP \(sourcePort) > \(destinationPort) flags \(flags) \(self.payload.count) bytes"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    public var verboseDescription: String {
           return "TCP \(sourcePort) > \(destinationPort) seq \(sequenceNumber) ack \(acknowledgementNumber) offset \(dataOffset) flags \(flags) window \(window) checksum \(checksum) urgentPtr \(urgentPointer)  \(payload.count) bytes"
    }
    public let data: Data
    public let sourcePort: UInt
    public let destinationPort: UInt
    public let sequenceNumber: UInt
    public let acknowledgementNumber: UInt
    public let dataOffset: UInt8
    public let urg: Bool
    public let ack: Bool
    public let psh: Bool
    public let rst: Bool
    public let syn: Bool
    public let fin: Bool
    public let window: UInt
    public let checksum: UInt
    public let urgentPointer: UInt
    public let options: Data?
    
    public let payload: Data
    
    init?(data: Data) {
        guard data.count >= 20 else {
            EtherCapture.logger.error("incomplete TCP header detected")
            return nil
        }
        self.data = Data(data)
        self.sourcePort = UInt(data[data.startIndex]) * 256 + UInt(data[data.startIndex + 1])
        self.destinationPort = UInt(data[data.startIndex + 2]) * 256 + UInt(data[data.startIndex + 3])
        self.sequenceNumber = UInt(data[data.startIndex + 4]) * 256 * 256 * 256 + UInt(data[data.startIndex + 5]) * 256 * 256 + UInt(data[data.startIndex + 6]) * 256 + UInt(data[data.startIndex + 7])
        self.acknowledgementNumber = UInt(data[data.startIndex + 8]) * 256 * 256 * 256 + UInt(data[data.startIndex + 9]) * 256 * 256 + UInt(data[data.startIndex + 10]) * 256 + UInt(data[data.startIndex + 11])
        self.dataOffset = (data[data.startIndex + 12] & 0b11110000) >> 4
        self.urg = (data[data.startIndex + 13] & 0b00100000) != 0
        self.ack = (data[data.startIndex + 13] & 0b00010000) != 0
        self.psh = (data[data.startIndex + 13] & 0b00001000) != 0
        self.rst = (data[data.startIndex + 13] & 0b00000100) != 0
        self.syn = (data[data.startIndex + 13] & 0b00000010) != 0
        self.fin = (data[data.startIndex + 13] & 0b00000001) != 0
        self.window = UInt(data[data.startIndex + 14]) * 256 + UInt(data[data.startIndex + 15])
        self.checksum = UInt(data[data.startIndex + 16]) * 256 + UInt(data[data.startIndex + 17])
        self.urgentPointer = UInt(data[data.startIndex + 18]) * 256 + UInt(data[data.startIndex + 19])
        
        //TODO TCP header options and variable size
        self.options = nil
        
        self.payload = Data(data[data.startIndex + 20 ..< data.endIndex])
    }
}
