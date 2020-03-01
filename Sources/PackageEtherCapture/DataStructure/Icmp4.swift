//
//  IcmpV4.swift
//  
//
//  Created by Darrell Root on 1/29/20.
//

import Foundation
import Logging
import Network

public enum IcmpType: Equatable, Hashable, CustomStringConvertible {
    case addressMaskRequest(identifier: Int, sequence: Int, mask: IPv4Address)
    case other
    
    public var description: String {
        switch self {
            
        case .addressMaskRequest(let identifier, let sequence, let mask):
            return "addressMaskRequest id \(identifier) sequence \(sequence) mask \(mask)"
        case .other:
            return "other"
        }
    }
}
public struct Icmp4: EtherDisplay {
    public var description: String {
        return "ICMPv4 type \(type) code \(code) checksum \(checksum) \(icmpType)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    public var verboseDescription: String {
           return "ICMPv4 type \(type) code \(code) checksum \(checksum) \(icmpType)"
    }
    
    public let data: Data
    public let payload: Data
    public let type: UInt
    public let code: UInt
    public let checksum: UInt16
    public let icmpType: IcmpType
    
    init?(data: Data) {
        guard data.count >= 4 else {
            EtherCapture.logger.error("incomplete ICMPv4 datagram detected")
            return nil
        }
        self.data = data
        let type = UInt(data[data.startIndex])
        self.type = type
        let code = UInt(data[data.startIndex + 1])
        self.code = code
        self.checksum = EtherCapture.getUInt16(data: data.advanced(by: 2))
        
        switch (self.type, self.code) {
        case (17,_):
            guard data.count >= 12, code == 0, let mask = IPv4Address(data[data.startIndex + 8 ..< data.startIndex + 12]) else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data: data.advanced(by: 6)))
            self.payload = Data()
            self.icmpType = IcmpType.addressMaskRequest(identifier: identifier, sequence: sequence, mask: mask)
            return
        case (_ , _):
            self.icmpType = IcmpType.other
            self.payload = data[data.startIndex + 4 ..< data.endIndex]
            return
        }// switch (self.type, self.code)
        //self.payload = Data(data[(data.startIndex + 8) ..< data.endIndex])

    }
}
