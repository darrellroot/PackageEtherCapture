//
//  Icmp6.swift
//  
//
//  Created by Darrell Root on 3/1/20.
//

import Foundation
import Logging
import Network

public enum Icmp6Option: Equatable, Hashable, CustomStringConvertible {
    public var description: String {
        switch self {
            
        case .sourceLinkAddress(let source):
            return "Source Link Address \(source)"
        case .targetLinkAddress(let target):
            return "Target Link Address \(target)"
        case .prefixInfo(let prefixLength, let onLink, let autoconfig, let validLifetime, let preferredLifetime, let prefix):
            return "Prefix \(prefix.debugDescription)/\(prefixLength) onlink:\(onLink) autoconfig:\(autoconfig) ValidLifetime \(validLifetime) PreferredLifetime \(preferredLifetime)"
        case .redirectedHeader(let data):
            return "Redirected Header \(data.count) bytes"
        case .mtu(let mtu):
            return "MTU \(mtu)"
        case .other(let type, let length):
            return "Other Icmp6Option type \(type) length \(length)"
        }
    }
    
    case sourceLinkAddress(String)
    case targetLinkAddress(String)
    case prefixInfo(prefixLength: Int,onLink: Bool, autoconfig: Bool, validLifetime: Int, preferredLifetime: Int, prefix: IPv6Address)
    case redirectedHeader(Data)
    case mtu(Int)
    case other(type: Int, length: Int)
    
    static func getOptions(data: Data) -> [Icmp6Option] {
        guard data.count >= 8 else {
            return []
        }
        var position = 0
        var results: [Icmp6Option] = []
        while position <= data.count - 8 {
            let type = data[data.startIndex + position]
            let length = 8 * Int(data[data.startIndex + position + 1])
            guard length > 0 else {
                EtherCapture.logger.error("Icmp6Option.getOptions: invalid length \(length) position \(position)")
                return results
            }
            switch type {
            case 1:
                if let linkAddress = EtherCapture.getMac(data: data.advanced(by: position + 2)) {
                    results.append(.sourceLinkAddress(linkAddress))
                } else {
                    EtherCapture.logger.error("Icmp6Option.getOptions: unable to decode type \(type) length \(length) position \(position)")
                }
                position = position + length
            case 2:
                if let linkAddress = EtherCapture.getMac(data: data.advanced(by: position + 2)) {
                    results.append(.targetLinkAddress(linkAddress))
                } else {
                    EtherCapture.logger.error("Icmp6Option.getOptions: unable to decode type \(type) length \(length) position \(position)")
                }
                position = position + length
            case 3:
                guard data.count >= position + 32,length == 32 else {
                    EtherCapture.logger.error("Icmp6Option.getOptions: unable to decode type \(type) length \(length) position \(position)")
                    return results
                }
                let prefixLength = Int(data[data.startIndex + position + 2])
                let flags = data[data.startIndex + position + 3]
                let onLink = (flags & 0b10000000 != 0)
                let autoconfig = (flags & 0b01000000 != 0)
                let validLifetime = Int(EtherCapture.getUInt32(data: data.advanced(by: position + 4)))
                let preferredLifetime = Int(EtherCapture.getUInt32(data: data.advanced(by: position + 8)))
                if let prefix = IPv6Address(data[data.startIndex + position + 16 ..< data.startIndex + position + 32]) {
                    let result = Icmp6Option.prefixInfo(prefixLength: prefixLength, onLink: onLink, autoconfig: autoconfig, validLifetime: validLifetime, preferredLifetime: preferredLifetime, prefix: prefix)
                    results.append(result)
                } else {
                    EtherCapture.logger.error("Icmp6Option.getOptions: unable to decode type \(type) length \(length) position \(position)")
                }
                position = position + length // length always 32 here
            case 4:
                guard data.count >= position + length else {
                    EtherCapture.logger.error("Icmp6Option.getOptions: unable to decode type \(type) length \(length) position \(position)")
                    return results
                }
                let redirectedData = data[data.startIndex + position + 8 ..< data.startIndex + position + length]
                let result = Icmp6Option.redirectedHeader(redirectedData)
                results.append(result)
                position = position + length
            case 5:
                guard length == 8 else {
                    EtherCapture.logger.error("Icmp6Option.getOptions: unable to decode type \(type) length \(length) position \(position)")
                    return results
                }
                let mtu = Int(EtherCapture.getUInt32(data: data.advanced(by: position + 4)))
                let result = Icmp6Option.mtu(mtu)
                results.append(result)
                position = position + length
            default:
                let result = Icmp6Option.other(type: Int(type), length: length)
                results.append(result)
                position = position + length
            }// switch type
        }// while position
        return results
    }// static func getOptions
}// struct Icmp6Option

public enum Icmp6Type: Equatable, Hashable, CustomStringConvertible {
    case other(type: Int, code: Int)
    case unreachableNoRoute
    case unreachableProhibited
    case unreachableScope
    case unreachableAddress
    case unreachablePort
    case unreachableSource
    case unreachableRejectRoute
    
    case packetTooBig
    case hopLimitExceeded
    case fragmentReassemblyTimeExceeded
    case parameterProblem(code: Int, pointer: Int)
    case echoRequest(identifier: Int, sequence: Int)
    case echoReply(identifier: Int, sequence: Int)
    case neighborSolicitation(target: IPv6Address)
    case neighborAdvertisement(target: IPv6Address, router: Bool, solicited: Bool, override: Bool)
    case redirect(target: IPv6Address, destination: IPv6Address)
    
    public var typeString: String {
        switch self {
            
        case .other(_, _):
            return "Other"
        case .unreachableNoRoute:
            return "Unreachable No Route"
        case .unreachableProhibited:
            return "Unreachable Admin Prohibited"
        case .unreachableScope:
            return "Unreachable Scope"
        case .unreachableAddress:
            return "Unreachable Address"
        case .unreachablePort:
            return "Unreachable Port"
        case .unreachableSource:
            return "Unreachable Source Rejected"
        case .unreachableRejectRoute:
            return "Unreachable Route Rejected"
        case .packetTooBig:
            return "Packet Too Big"
        case .hopLimitExceeded:
            return "Hop Limit Exceeded"
        case .fragmentReassemblyTimeExceeded:
            return "Fragment Reassembly Time Exceeded"
        case .parameterProblem:
            return "Parameter Problem"
        case .echoRequest:
            return "Echo Request"
        case .echoReply:
            return "Echo Reply"
        case .neighborSolicitation(_):
            return "Neighbor Solicitation"
        case .neighborAdvertisement(_,_,_,_):
            return "Neighbor Advertisement"
        case .redirect(_,_):
            return "Redirect"
        }
    }
    public var description: String {
        return "\(typeString) \(details)"
    }

    public var details: String {
        switch self {
            
        case .other(let type, let code):
            return "type \(type) code \(code)"
        case .unreachableNoRoute:
            return ""
        case .unreachableProhibited:
            return ""
        case .unreachableScope:
            return ""
        case .unreachableAddress:
            return ""
        case .unreachablePort:
            return ""
        case .unreachableSource:
            return ""
        case .unreachableRejectRoute:
            return ""
        case .packetTooBig:
            return ""
        case .hopLimitExceeded:
            return ""
        case .fragmentReassemblyTimeExceeded:
            return ""
        case .parameterProblem(let code, let pointer):
            switch code {
            case 0:
                return "Erroneous header field at \(pointer)"
            case 1:
                return "Unrecognized next header at \(pointer)"
            case 2:
                return "Unrecognized IPv6 option at \(pointer)"
            default:
                return "code \(code) at \(pointer)"
            }
        case .echoRequest(let identifier, let sequence):
            return "identifier \(identifier) sequence \(sequence)"
        case .echoReply(let identifier, let sequence):
            return "identifier \(identifier) sequence \(sequence)"
        case .neighborSolicitation(let target):
            return "Target \(target.debugDescription)"
        case .neighborAdvertisement(let target, let router, let solicited, let override):
            return "Target \(target.debugDescription) router:\(router) solicited:\(solicited) override:\(override)"
        case .redirect(let target, let destination):
            return "Target \(target.debugDescription) Destination \(destination.debugDescription)"
        }
    }
}
public struct Icmp6: EtherDisplay {
    public var description: String {
        return "ICMPv6 type \(type) code \(code) \(icmpType)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    public var verboseDescription: String {
        return "ICMPv6 type \(type) code \(code) checksum \(checksum) \(icmpType) PayloadLength \(payloadLength) \(options.count) options"
    }
    public let data: Data
    public let payload: Data
    public var payloadLength: Int = 0 // payload length rfc 4884
    public let type: Int
    public let code: Int
    public let checksum: UInt16
    public let icmpType: Icmp6Type
    public var options: [Icmp6Option] = []
    

    init?(data: Data) {
        guard data.count >= 8 else {
            EtherCapture.logger.error("incomplete ICMPv6 datagram detected")
            return nil
        }
        self.data = data
        let type = Int(UInt(data[data.startIndex]))
        self.type = type
        let code = Int(UInt(data[data.startIndex + 1]))
        self.code = code
        self.checksum = EtherCapture.getUInt16(data: data.advanced(by: 2))
        
        switch (self.type, self.code) {
        case (1,_):
            if data.count > 8 {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            } else {
                self.payload = Data()
            }
            switch code {
            case 0:
                self.icmpType = .unreachableNoRoute
            case 1:
                self.icmpType = .unreachableProhibited
            case 2:
                self.icmpType = .unreachableScope
            case 3:
                self.icmpType = .unreachableAddress
            case 4:
                self.icmpType = .unreachablePort
            case 5:
                self.icmpType = .unreachableSource
            case 6:
                self.icmpType = .unreachableRejectRoute
            default:
                self.icmpType = .other(type: type, code: code)
            }
            return
        case (2,_):
            if data.count > 8 {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            } else {
                self.payload = Data()
            }
            self.icmpType = .packetTooBig
            return
        case (3,_):
            if data.count > 8 {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            } else {
                self.payload = Data()
            }
            if code == 0 {
                self.icmpType = .hopLimitExceeded
            } else if code == 1 {
                self.icmpType = .fragmentReassemblyTimeExceeded
            } else {
                self.icmpType = .other(type: type, code: code)
            }
        case (4,_):
            if data.count > 8 {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            } else {
                self.payload = Data()
            }
            let pointer = Int(EtherCapture.getUInt32(data: data.advanced(by: 4)))
            self.icmpType = .parameterProblem(code: code, pointer: pointer)
            return
        case (128,0),(129,0):
            if data.count > 8 {
                self.payload = data[data.startIndex + 8 ..< data.endIndex]
            } else {
                self.payload = Data()
            }
            let identifier = Int(EtherCapture.getUInt16(data: data.advanced(by: 4)))
            let sequence = Int(EtherCapture.getUInt16(data:data.advanced(by: 6)))
            if type == 128 {
                self.icmpType = .echoRequest(identifier: identifier, sequence: sequence)
            } else if type == 129 {
                self.icmpType = .echoReply(identifier: identifier, sequence: sequence)
            } else {
                //should not get here
                self.icmpType = .other(type: type, code: code)
            }
            return
        case (135,0):
            guard data.count >= 24, let target = IPv6Address(data[data.startIndex + 8 ..< data.startIndex + 24]) else {
                EtherCapture.logger.error("Incomplete ICMPv6 message type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            
            self.payload = Data()
            self.options = Icmp6Option.getOptions(data: data[data.startIndex + 24 ..< data.endIndex])
            self.icmpType = .neighborSolicitation(target: target)
            return
        case (136,0):
            guard data.count >= 24, let target = IPv6Address(data[data.startIndex + 8 ..< data.startIndex + 24]) else {
                EtherCapture.logger.error("Incomplete ICMPv6 message type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            self.payload = Data()
            let flags = data[data.startIndex + 4]
            let routerFlag = (flags & 0b10000000) != 0
            let solicitedFlag = (flags & 0b01000000) != 0
            let overrideFlag = (flags & 0b00100000) != 0

            self.options = Icmp6Option.getOptions(data: data[data.startIndex + 24 ..< data.endIndex])
            self.icmpType = .neighborAdvertisement(target: target, router: routerFlag, solicited: solicitedFlag, override: overrideFlag)
            return
        case (137,0):
            guard data.count >= 40, let target = IPv6Address(data[data.startIndex + 8 ..< data.startIndex + 24]), let destination = IPv6Address(data[data.startIndex + 24 ..< data.startIndex + 40]) else {
                EtherCapture.logger.error("Incomplete ICMPv6 message type \(type) code \(code) \(data.count) bytes")
                return nil
            }
            self.payload = Data()
            self.options = Icmp6Option.getOptions(data: data[data.startIndex + 40 ..< data.endIndex])
            self.icmpType = .redirect(target: target, destination: destination)
            return
        default:
            self.icmpType = .other(type: type, code: code)
            self.payload = Data()
            return
        }// switch (type, code)
    }
}
