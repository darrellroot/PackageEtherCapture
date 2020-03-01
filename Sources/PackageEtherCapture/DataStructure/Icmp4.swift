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
    case echoReply(identifier: Int, sequence: Int)
    case echoRequest(identifer: Int, sequence: Int)
    case addressMaskRequest(identifier: Int, sequence: Int, mask: IPv4Address)
    case addressMaskReply(identifier: Int, sequence: Int, mask: IPv4Address)

    case other(type: Int, code: Int)
    
    public var typeString: String {
        switch self {
            
        case .echoReply(_, _):
            return "Echo Reply"
        case .echoRequest(_, _):
            return "Echo Request"
        case .addressMaskRequest(_, _, _):
            return "Address Mask Request"
        case .addressMaskReply(_ , _, _):
            return "Address Mask Reply"
        case .other(_, _):
            return "Other"
        }
    }
    public var description: String {
        return "\(typeString) \(details)"
    }
    public var details: String {
        switch self {
        
        case .echoReply(let identifier, let sequence):
            return "id \(identifier) sequence \(sequence)"
        case .echoRequest(let identifier, let sequence):
            return "id \(identifier) sequence \(sequence)"
        case .addressMaskRequest(let identifier, let sequence, let mask):
            return "id \(identifier) sequence \(sequence) mask \(mask)"
        case .addressMaskReply(let identifier, let sequence, let mask):
            return "id \(identifier) sequence \(sequence) mask \(mask)"
        case .other:
            return "unable to further analyze"
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
    public let type: Int
    public let code: Int
    public let checksum: UInt16
    public let icmpType: IcmpType
    
    init?(data: Data) {
        guard data.count >= 4 else {
            EtherCapture.logger.error("incomplete ICMPv4 datagram detected")
            return nil
        }
        self.data = data
        let type = Int(UInt(data[data.startIndex]))
        self.type = type
        let code = Int(UInt(data[data.startIndex + 1]))
        self.code = code
        self.checksum = EtherCapture.getUInt16(data: data.advanced(by: 2))
        
        switch (self.type, self.code) {
        case (0,0),(8,0):
            guard data.count >= 8 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data: data.advanced(by: 6)))
            self.payload = data[data.startIndex + 8 ..< data.endIndex]
            if type == 0 {
                self.icmpType = .echoReply(identifier: identifier, sequence: sequence)
            } else {
                self.icmpType = .echoRequest(identifer: identifier, sequence: sequence)
            }
            return
        case (17,0),(18,0):
            guard data.count >= 12, code == 0, let mask = IPv4Address(data[data.startIndex + 8 ..< data.startIndex + 12]) else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data: data.advanced(by: 6)))
            self.payload = Data()
            if type == 17 {
                self.icmpType = IcmpType.addressMaskRequest(identifier: identifier, sequence: sequence, mask: mask)
            } else {
                self.icmpType = IcmpType.addressMaskReply(identifier: identifier, sequence: sequence, mask: mask)
            }
            return
        case (_ , _):
            self.icmpType = IcmpType.other(type: type, code: code)
            self.payload = data[data.startIndex + 4 ..< data.endIndex]
            return
        }// switch (self.type, self.code)
        //self.payload = Data(data[(data.startIndex + 8) ..< data.endIndex])

    }
}
