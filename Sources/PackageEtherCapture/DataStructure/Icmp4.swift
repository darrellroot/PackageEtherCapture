//
//  IcmpV4.swift
//  
//
//  Created by Darrell Root on 1/29/20.
//

import Foundation
import Logging
import Network

//TODO add icmp extensions, see rfc 4950 and 4884
public enum Icmp4Type: Equatable, Hashable, CustomStringConvertible {
    case echoReply(identifier: Int, sequence: Int)
    case echoRequest(identifer: Int, sequence: Int)
    case addressMaskRequest(identifier: Int, sequence: Int, mask: IPv4Address)
    case addressMaskReply(identifier: Int, sequence: Int, mask: IPv4Address)
    case timestampRequest(identifier: Int, sequence: Int, originate: UInt32, receive: UInt32, transmit: UInt32)
    case timestampReply(identifier: Int, sequence: Int, originate: UInt32, receive: UInt32, transmit: UInt32)
    case netUnreachable
    case hostUnreachable
    case portUnreachable
    case protocolUnreachable
    case fragmentationNeeded
    case sourceRouteFailed
    case otherUnreachable(code: Int)
    case ttlExceeded
    case parameterProblem(pointer: Int)
    case fragmentReassemblyTimeExceeded
    case sourceQuench
    case redirectNetwork(IPv4Address)
    case redirectHost(IPv4Address)
    case redirectTosNetwork(IPv4Address)
    case redirectTosHost(IPv4Address)
    case informationRequest(identifier: Int, sequence: Int)
    case informationReply(identifier: Int, sequence: Int)
    case other(type: Int, code: Int)
    
    public var typeString: String {
        switch self {
            
        case .other(_, _):
            return "Other"
        case .echoReply(_, _):
            return "Echo Reply"
        case .echoRequest(_, _):
            return "Echo Request"
        case .addressMaskRequest(_, _, _):
            return "Address Mask Request"
        case .addressMaskReply(_ , _, _):
            return "Address Mask Reply"
        case .timestampRequest( _, _, _, _, _):
            return "Timestamp Request"
        case .timestampReply( _, _, _, _, _):
            return "Timestamp Reply"
        case .netUnreachable:
            return "Net Unreachable"
        case .hostUnreachable:
            return "Host Unreachable"
        case .portUnreachable:
            return "Port Unreachable"
        case .protocolUnreachable:
            return "Protocol Unreachable"
        case .fragmentationNeeded:
            return "Fragmentation Needed But DF Bit Set"
        case .sourceRouteFailed:
            return "Source Route Failed"
        case .otherUnreachable(_):
            return "Unreachable"
        case .ttlExceeded:
            return "TTL Exceeded"
        case .fragmentReassemblyTimeExceeded:
            return "Fragment Rassembly Time Exceeded"
        case .parameterProblem(_):
            return "Parameter Problem"
        case .sourceQuench:
            return "Source Quench"
        case .redirectHost(_):
            return "Redirect Host"
        case .redirectNetwork(_):
            return "Redirect Network"
        case .redirectTosHost(_):
            return "Redirect Type of Service Host"
        case .redirectTosNetwork(_):
            return "Redirect Type of Service Network"
        case .informationRequest(_):
            return "Information Request"
        case .informationReply(_):
            return "Information Reply"
        }
    }
    public var description: String {
        return "\(typeString) \(details)"
    }
    public var details: String {
        switch self {
            
        case .other:
            return "unable to further analyze"
        case .echoReply(let identifier, let sequence):
            return "id \(identifier) sequence \(sequence)"
        case .echoRequest(let identifier, let sequence):
            return "id \(identifier) sequence \(sequence)"
        case .addressMaskRequest(let identifier, let sequence, let mask):
            return "DEPRECATED id \(identifier) sequence \(sequence) mask \(mask)"
        case .addressMaskReply(let identifier, let sequence, let mask):
            return "DEPRECATED id \(identifier) sequence \(sequence) mask \(mask)"
        case .timestampRequest(let identifier, let sequence, let originate, let receive, let transmit):
            return "id \(identifier) sequence \(sequence) originate \(originate) receive \(receive) transmit \(transmit)"
        case .timestampReply(let identifier, let sequence, let originate, let receive, let transmit):
            return "id \(identifier) sequence \(sequence) originate \(originate) receive \(receive) transmit \(transmit)"
        case .netUnreachable:
            return ""
        case .hostUnreachable:
            return ""
        case .portUnreachable:
            return ""
        case .protocolUnreachable:
            return ""
        case .fragmentationNeeded:
            return ""
        case .sourceRouteFailed:
            return ""
        case .otherUnreachable(let code):
            return "Code \(code)"
        case .ttlExceeded:
            return ""
        case .fragmentReassemblyTimeExceeded:
            return ""
        case .parameterProblem(let pointer):
            return "Pointer: \(pointer)"
        case .sourceQuench:
            return "DEPRECATED RFC 6633"
        case .redirectHost(let ipv4),.redirectNetwork(let ipv4), .redirectTosHost(let ipv4), .redirectTosNetwork(let ipv4):
            return "\(ipv4.debugDescription)"
        case .informationRequest(let identifier, let sequence):
            return "DEPRECATED id \(identifier) sequence \(sequence)"
        case .informationReply(let identifier,let sequence):
            return "DEPRECATED id \(identifier) sequence \(sequence)"

        }
    }
}
public struct Icmp4: EtherDisplay {
    public var description: String {
        return "ICMPv4 \(icmpType)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    public var verboseDescription: String {
        return "ICMPv4 type \(type) code \(code) checksum \(checksum) \(icmpType) PayloadLength \(payloadLength)"
    }
    
    public let data: Data
    public let payload: Data
    public var payloadLength: Int = 0 // payload length rfc 4884
    public let type: Int
    public let code: Int
    public let checksum: UInt16
    public let icmpType: Icmp4Type
    
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
        case (3, let code):
            guard data.count >= 8 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let payloadLength = Int(data[data.startIndex + 5])
            self.payloadLength = payloadLength
            if payloadLength > 0, data.count >= payloadLength + 8 {
                self.payload = data[data.startIndex + 8 ..< data.startIndex + 8 + payloadLength]
            } else {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            }
            switch code {
            case 0:
                self.icmpType = .netUnreachable
            case 1:
                self.icmpType = .hostUnreachable
            case 2:
                self.icmpType = .protocolUnreachable
            case 3:
                self.icmpType = .portUnreachable
            case 4:
                self.icmpType = .fragmentationNeeded
            case 5:
                self.icmpType = .sourceRouteFailed
            default:
                self.icmpType = .otherUnreachable(code: code)
            }
        case (4, 0):
            guard data.count >= 8 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            self.payload = data[data.startIndex + 8 ..< data.endIndex]
            self.icmpType = .sourceQuench
        case (5,0),(5,1),(5,2),(5,3):
            guard data.count >= 8, let ipv4 = IPv4Address(data[data.startIndex + 4 ..< data.startIndex + 8]) else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            self.payload = data[data.startIndex + 8 ..< data.endIndex]
            switch code {
            case 0:
                self.icmpType = .redirectHost(ipv4)
            case 1:
                self.icmpType = .redirectNetwork(ipv4)
            case 2:
                self.icmpType = .redirectTosHost(ipv4)
            case 3:
                self.icmpType = .redirectTosNetwork(ipv4)
            default:
                EtherCapture.logger.error("unexpected ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                self.icmpType = .other(type: type, code: code)
            }
            return
        case (11,let code):
            guard data.count >= 8 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let payloadLength = Int(data[data.startIndex + 5])
            self.payloadLength = payloadLength
            if payloadLength > 0, data.count >= payloadLength + 8 {
                self.payload = data[data.startIndex + 8 ..< data.startIndex + 8 + payloadLength]
            } else {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            }
            switch code {
            case 0:
                self.icmpType = .ttlExceeded
            case 1:
                self.icmpType = .fragmentReassemblyTimeExceeded
            default:
                EtherCapture.logger.error("invalid ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                self.icmpType = .other(type: type, code: code)
            }
            return
        case (12,0):
            guard data.count >= 8 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let payloadLength = Int(data[data.startIndex + 5])
            self.payloadLength = payloadLength
            if payloadLength > 0, data.count >= payloadLength + 8 {
                self.payload = data[data.startIndex + 8 ..< data.startIndex + 8 + payloadLength]
            } else {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            }
            let pointer = Int(data[data.startIndex + 4])
            self.icmpType = .parameterProblem(pointer: pointer)
            return
        case (13,0),(14,0):
            guard data.count >= 0 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data: data.advanced(by: 6)))
            self.payload = Data()
            let originate = EtherCapture.getUInt32(data: data.advanced(by: 8))
            let receive = EtherCapture.getUInt32(data: data.advanced(by: 12))
            let transmit = EtherCapture.getUInt32(data: data.advanced(by: 16))
            if type == 13 {
                self.icmpType = .timestampRequest(identifier: identifier, sequence: sequence, originate: originate, receive: receive, transmit: transmit)
            } else {
                self.icmpType = .timestampReply(identifier: identifier, sequence: sequence, originate: originate, receive: receive, transmit: transmit)
            }
            return
        case (15,0),(16,0):
            guard data.count >= 0 else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data: data.advanced(by: 6)))
            self.payload = Data()
            if type == 15 {
                self.icmpType = .informationRequest(identifier: identifier, sequence: sequence)
            } else {
                self.icmpType = .informationReply(identifier: identifier, sequence: sequence)
            }
        case (17,0),(18,0):
            guard data.count >= 12, code == 0, let mask = IPv4Address(data[data.startIndex + 8 ..< data.startIndex + 12]) else {
                EtherCapture.logger.error("incomplete ICMPv4 datagram detected type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data: data.advanced(by: 6)))
            self.payload = Data()
            if type == 17 {
                self.icmpType = Icmp4Type.addressMaskRequest(identifier: identifier, sequence: sequence, mask: mask)
            } else {
                self.icmpType = Icmp4Type.addressMaskReply(identifier: identifier, sequence: sequence, mask: mask)
            }
            return
        case (_ , _):
            self.icmpType = Icmp4Type.other(type: type, code: code)
            self.payload = data[data.startIndex + 4 ..< data.endIndex]
            return
        }// switch (self.type, self.code)
        //self.payload = Data(data[(data.startIndex + 8) ..< data.endIndex])
        
    }
}
