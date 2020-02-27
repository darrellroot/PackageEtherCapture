//
//  Cdp.swift
//  Decode for Cisco Discovery Protocol
//
//  Created by Darrell Root on 2/26/20.
//

import Foundation
import Network
import Logging

public enum CdpValue: CustomStringConvertible, Hashable {
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
    case softwareVersion(String)
    case platform(String)
    case nativeVlan(Int)
    case unknown(Data)
    
    public var description: String {
        switch self {
            
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
        case .softwareVersion(let version):
            return "Version \(version)"
        case .platform(let platform):
            return "Platform \(platform)"
        case .nativeVlan(let vlan):
            return "NativeVLAN \(vlan)"
        case .unknown(let unknown):
            return "UnknownCdpValue \(unknown.count) bytes type \(unknown[1])"
        }
    }
    public static func getValues(data: Data) throws -> [CdpValue] {
        let type = data[data.startIndex]
        let length = Int(EtherCapture.getUInt16(data: data.advanced(by: 1)))
        guard data.count >= length else {
            throw EtherCaptureError.genericError("length \(length) data \(data.count)")
        }
        switch type {
        case 1:
            let subdata = data[(data.startIndex + 2) ..< (data.startIndex + length)]
            if let string = String(data: subdata,  encoding: .utf8) {
                let cdpValue = CdpValue.deviceId(string)
                return [cdpValue]
            } else {
                throw EtherCaptureError.genericError("cdp type 1: unable to decode deviceId string")
            }
        
        default:
            let alldata = data[(data.startIndex + 0) ..< (data.startIndex + length)]
            let cdpValue = CdpValue.unknown(alldata)
            return [cdpValue]
        }
    }
}

public struct Cdp: CustomStringConvertible, EtherDisplay {
    
    public var description: String {
        return "CDP"
    }
    public var verboseDescription: String {
        return "CDP Verbose"
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
        self.checksum = EtherCapture.getUInt16(data: data.advanced(by: 2))
        var position = 4
        while data.count > position + 5 {
            let type = EtherCapture.getUInt16(data: data.advanced(by: position))
            let length = Int(EtherCapture.getUInt16(data: data.advanced(by: position + 2)))
            guard data.count >= position + Int(length) else {
                return
            }
            do {
                let cdpValues = try CdpValue.getValues(data: data.advanced(by: position))
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
