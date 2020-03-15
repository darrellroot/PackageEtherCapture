//
//  Cdp.swift
//  Decode for Cisco Discovery Protocol
//
//  Created by Darrell Root on 2/26/20.
//

import Foundation
import Network
import Logging

public enum CdpType: Hashable, Equatable {
    case deviceId(String)
    case ipv4address(IPv4Address)
    case ipv6address(IPv6Address)
    case portId(String)
    case capabilityRouter
    case capabilityBridge
    case capabilitySourceRouteBridge
    case capabilitySwitch
    case capabilityHost
    case capabilityIgmp
    case capabilityRepeater
    case capabilityVoip
    case capabilityRemoteManaged
    case capabilityVtCamera
    case capabilityMacRelay
    case softwareVersion(String)
    case platform(String)
    case trustBitmap(String)
    case untrustedCos(String)
    case duplex(String)
    case nativeVlan(Int)
    case systemName(String)
    case unknown(Data)
}

public struct CdpValue: Equatable, Hashable {

    // Indexes do not matter for equatable
    public static func == (lhs: CdpValue, rhs: CdpValue) -> Bool {
        return lhs.cdpType == rhs.cdpType
    }
    public var cdpType: CdpType
    public var startIndex: Data.Index?
    public var endIndex: Data.Index?

    public var description: String {
        switch self.cdpType {
            
        case .deviceId(let device):
            return "deviceID \(device)"
        case .ipv4address(let ipv4Address):
            return "ipv4 \(ipv4Address)"
        case .ipv6address(let ipv6Address):
            return "ipv6 \(ipv6Address)"
        case .portId(let portId):
            return "portID \(portId)"
        case .capabilityRouter:
            return "Router"
        case .capabilityBridge:
            return "Bridge"
        case .capabilitySourceRouteBridge:
            return "SourceRouteBridge"
        case .capabilitySwitch:
            return "Switch"
        case .capabilityHost:
            return "Host"
        case .capabilityIgmp:
            return "IGMP-Speaker"
        case .capabilityRepeater:
            return "Repeater"
        case .capabilityVoip:
            return "VOIP"
        case .capabilityRemoteManaged:
            return "Remote Managed"
        case .capabilityVtCamera:
            return "CVTA/STP Dispute Resolution/Cisco VT Camera"
        case .capabilityMacRelay:
            return "Mac Relay"
        case .softwareVersion(let version):
            return "Version \(version)"
        case .platform(let platform):
            return "Platform \(platform)"
        case .nativeVlan(let vlan):
            return "NativeVLAN \(vlan)"
        case .unknown(let unknown):
            return "UnknownCdpValue \(unknown.count) bytes type \(unknown[1])"
        case .trustBitmap(let bitmap):
            return bitmap
        case .duplex(let duplex):
            return duplex
        case .systemName(let systemName):
            return "Device Name \(systemName)"
        case .untrustedCos(let cos):
            return cos
        }
    }
    public static func getValues(data: Data) throws -> [CdpValue] {
        let type = EtherCapture.getUInt16(data: data)
        let length = Int(EtherCapture.getUInt16(data: data[data.startIndex + 2 ..< data.startIndex + 4]))
        guard data.count >= length, length > 4 else {
            throw EtherCaptureError.genericError("CDP decode failed length \(length) data \(data.count)")
        }

        switch type {
        case 1:
            let subdata = data[(data.startIndex + 4) ..< (data.startIndex + length)]
            if let string = String(data: subdata,  encoding: .utf8) {
                let cdpValue = CdpValue(cdpType: CdpType.deviceId(string), startIndex: data.startIndex, endIndex: data.startIndex + length)
                return [cdpValue]
            } else {
                throw EtherCaptureError.genericError("cdp type 1: unable to decode deviceId string")
            }
        case 2: // type case
            let numberAddresses = EtherCapture.getUInt32(data: data[data.startIndex + 4 ..< data.startIndex + 8])
            var position = 8
            var results: [CdpValue] = []
            for loop in 0 ..< numberAddresses {
                let protocolType = data[data.startIndex + position]
                let protocolLength = Int(data[data.startIndex + position + 1])
                switch protocolLength {
                case 1: // 1 byte protocol length usually ipv4
                    guard data.count >= position + 9 else {
                        return results
                    }
                    let protocolNumber = data[data.startIndex + position + 2]
                    let addressLength = Int(EtherCapture.getUInt16(data: data[data.startIndex + position + 2 + protocolLength ..< data.startIndex + position + 4 + protocolLength]))
                    if protocolNumber != 0xcc {
                        position = position + 2 + protocolLength + 2 + addressLength
                        EtherCapture.logger.error("CDP: unsupported address protocol \(protocolNumber)")
                    } else { //protocolNumber is 0xcc == IPv4
                        if let ipv4Address = IPv4Address(data[data.startIndex + position + 4 + protocolLength ..< data.startIndex + position + protocolLength + 8]) {
                            let result = CdpValue(cdpType: .ipv4address(ipv4Address), startIndex: data.startIndex + position, endIndex: data.startIndex + position + protocolLength + 8)
                            results.append(result)
                        }
                        position = position + 2 + protocolLength + 2 + addressLength
                    }
                case 8: //8 byte protocol usually ipv6
                    guard data.count >= position + 28 else {
                        return results
                    }
                    let protocolNumber = EtherCapture.getUInt64(data: data[data.startIndex + position + 2 ..< data.startIndex + position + 2 + 8])
                    let addressLength = Int(EtherCapture.getUInt16(data: data[data.startIndex + position + 2 + protocolLength ..< data.startIndex + position + 2 + protocolLength + 2]))
                    if protocolNumber != UInt64(0xaaaa0300000086dd) {
                        EtherCapture.logger.error("CDP: unsupported address protocol \(protocolNumber)")

                        position = position + 2 + protocolLength + 2 + addressLength
                    } else { // protocol is ipv6
                        if let ipv6address = IPv6Address(data[data.startIndex + position + 4 + protocolLength ..< data.startIndex + position + protocolLength + 20]) {
                            let result = CdpValue(cdpType: .ipv6address(ipv6address), startIndex: data.startIndex + position, endIndex: data.startIndex + position + protocolLength + 20)
                            results.append(result)
                        }
                        position = position + 2 + protocolLength + 2 + addressLength
                    }
                default: // default protocolLength
                    EtherCapture.logger.error("Cdp: unexpected protocol length \(protocolLength)")
                    guard data.count >= position + 2 + protocolLength + 2 else {
                        return results
                    }
                    let addressLength = Int(EtherCapture.getUInt16(data: data[data.startIndex + position + 2 + protocolLength ..< data.startIndex + position + 2 + protocolLength + 2]))
                    position = position + 2 + protocolLength + 2 + addressLength

                } // switch protocolLength
            } // for loop in numberAddresses
            return results
        case 3: // type case 3 port id
            let subdata = data[(data.startIndex + 4) ..< (data.startIndex + length)]
            if let string = String(data: subdata,  encoding: .utf8) {
                let cdpValue = CdpValue(cdpType: .portId(string), startIndex: data.startIndex + 2, endIndex: data.startIndex + length)
                return [cdpValue]
            } else {
                throw EtherCaptureError.genericError("cdp type 3: unable to decode portId string")
            }
        case 4: // type case 4 capabilities
            guard length == 8 else {
                throw EtherCaptureError.genericError("cdp type 4: length \(length) unable to decode capabilities")
            }
            var results: [CdpValue] = []
            let octet3 = data[data.startIndex + 6]
            let octet4 = data[data.startIndex + 7]
            if octet4 & 0x01 != 0 {
                results.append(CdpValue(cdpType: .capabilityRouter, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x02 != 0 {
                results.append(CdpValue(cdpType: .capabilityBridge, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x04 != 0 {
                results.append(CdpValue(cdpType: .capabilitySourceRouteBridge, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x08 != 0 {
                results.append(CdpValue(cdpType: .capabilitySwitch, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x10 != 0 {
                results.append(CdpValue(cdpType: .capabilityHost, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x20 != 0 {
                results.append(CdpValue(cdpType: .capabilityIgmp, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x40 != 0 {
                results.append(CdpValue(cdpType: .capabilityRepeater, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet4 & 0x80 != 0 {
                results.append(CdpValue(cdpType: .capabilityVoip, startIndex: data.startIndex + 7, endIndex: data.startIndex + 8))
            }
            if octet3 & 0x01 != 0 {
                results.append(CdpValue(cdpType: .capabilityRemoteManaged, startIndex: data.startIndex + 6, endIndex: data.startIndex + 7))
            }
            if octet3 & 0x02 != 0 {
                results.append(CdpValue(cdpType: .capabilityVtCamera, startIndex: data.startIndex + 6, endIndex: data.startIndex + 7))
            }
            if octet3 & 0x04 != 0 {
                results.append(CdpValue(cdpType: .capabilityMacRelay, startIndex: data.startIndex + 6, endIndex: data.startIndex + 7))
            }
            return results
        case 5: // type case 5 version
            let subdata = data[(data.startIndex + 4) ..< (data.startIndex + length)]
            if let string = String(data: subdata,  encoding: .utf8) {
                let cdpValue = CdpValue(cdpType: .softwareVersion(string), startIndex: data.startIndex + 2, endIndex: data.startIndex + length)
                return [cdpValue]
            } else {
                throw EtherCaptureError.genericError("cdp type 5: unable to decode software version")
            }
        case 6: // type case 6 platform
            let subdata = data[(data.startIndex + 4) ..< (data.startIndex + length)]
            if let string = String(data: subdata,  encoding: .utf8) {
                let cdpValue = CdpValue(cdpType: .platform(string), startIndex: data.startIndex + 2, endIndex: data.startIndex + length)
                return [cdpValue]
            } else {
                throw EtherCaptureError.genericError("cdp type \(type): unable to decode platform")
            }
        case 10: // type case 10 (0xa) native vlan
            guard length == 6 else {
                throw EtherCaptureError.genericError("cdp type \(type) length \(length) invalid")
            }
            let vlan = Int(EtherCapture.getUInt16(data: data[data.startIndex + 4 ..< data.startIndex + 6]))
            let cdpValue = CdpValue(cdpType: .nativeVlan(vlan), startIndex: data.startIndex + 2, endIndex: data.startIndex + 6)
            return [cdpValue]
        case 11: // type case 11 (0xb) duplex
            guard length == 5 else {
                throw EtherCaptureError.genericError("cdp type \(type) length \(length) invalid")
            }
            let duplexNum = data[data.startIndex + 4]
            switch duplexNum {
            case 1:
                let cdpValue = CdpValue(cdpType: .duplex("Duplex Full"), startIndex: data.startIndex + 2, endIndex: data.startIndex + 5)
                return [cdpValue]
            default:
                let cdpValue = CdpValue(cdpType: .duplex("Duplex value \(duplexNum)"), startIndex: data.startIndex + 2, endIndex: data.startIndex + 5)
                return [cdpValue]
            }
        case 0x12: // type case (0x12) Trust bitmap
            guard length == 5 else {
                throw EtherCaptureError.genericError("cdp type \(type) length \(length) invalid")
            }
            let trustNum = data[data.startIndex + 4]
            let trustString = String(format: "Trust Bitmap 0x%x",trustNum)
            let cdpValue = CdpValue(cdpType: .trustBitmap(trustString), startIndex: data.startIndex + 2, endIndex: data.startIndex + 5)
            return [cdpValue]
        case 0x13: // untrusted port CoS
            guard length == 5 else {
                throw EtherCaptureError.genericError("cdp type \(type) length \(length) invalid")
            }
            let cosNum = data[data.startIndex + 4]
            let cosString = String(format: "Untrusted Port CoS 0x%x",cosNum)
            let cdpValue = CdpValue(cdpType: .untrustedCos(cosString), startIndex: data.startIndex + 2, endIndex: data.startIndex + 5)
            return [cdpValue]
        case 0x14: // system name
            let subdata = data[(data.startIndex + 4) ..< (data.startIndex + length)]
            guard let string = String(data: subdata,  encoding: .utf8) else {
                throw EtherCaptureError.genericError("cdp type \(type): unable to decode platform")
            }
            let cdpValue = CdpValue(cdpType: .systemName(string), startIndex: data.startIndex + 2, endIndex: data.startIndex + length)
            return [cdpValue]
        default: // type case
            let alldata = data[(data.startIndex + 0) ..< (data.startIndex + length)]
            let cdpValue = CdpValue(cdpType: .unknown(alldata), startIndex: data.startIndex + 0, endIndex: data.startIndex + length)
            return [cdpValue]
        }// switch type
    }// func getValues
}//enum CdpValue

public struct Cdp: CustomStringConvertible, EtherDisplay {
    
    public var description: String {
        return "CDP"
    }
    public var verboseDescription: String {
        return "CDP version \(version) \(values.count) values"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    
    public var version: UInt8
    public var ttl: UInt8
    public var checksum: UInt16
    
    public var ipv4addresses: [IPv4Address] = []
    public var ipv6addresses: [IPv6Address] = []
    public var data: Data
    public var values: [CdpValue] = []
    
    init?(data: Data) {
        self.data = data
        guard data.count > 9 else { return nil }
        self.version = data[data.startIndex]
        self.ttl = data[data.startIndex + 1]
        self.checksum = EtherCapture.getUInt16(data: data[data.startIndex + 2 ..< data.startIndex + 4])
        var position = 4
        while data.count > position + 5 {
            let type = EtherCapture.getUInt16(data: data[data.startIndex + position ..< data.startIndex + position + 2])
            let length = Int(EtherCapture.getUInt16(data: data[data.startIndex + position + 2 ..< data.startIndex + position + 4]))
            guard data.count >= position + Int(length) else {
                return
            }
            do {
                let cdpValues = try CdpValue.getValues(data: data[data.startIndex + position ..< data.endIndex])
                self.values.append(contentsOf: cdpValues)
            } catch {
                EtherCapture.logger.error("Cdp: error decoding cdpValue at position \(position) type \(type) length \(length) error \(error)")
                return
            }
            position = position + length
            if length < 5 {  // extra safeguard to ensure loop termination
                return
            }
        }
        return
    }
}
