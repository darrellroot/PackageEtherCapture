//
//  Lldp.swift
//  
//
//  Created by Darrell Root on 2/28/20.
//

import Foundation
import Network
import Logging

public enum LldpType: Equatable, Hashable {
    case endOfLldp
    case chassisId(subtype: UInt8, id: String)
    case portId(subtype: UInt8, id: String)
    case portDescription(String)
    case systemName(String)
    case ttl(Int)
    case managementAddressIPv4(address: IPv4Address, subType: Int, interface: Int, oid: String)
    case managementAddressIPv6(address: IPv6Address, subType: Int, interface: Int, oid: String)
    case ouiSpecific(oui: String, subType: Int, info: String)
    case capabilityOther
    case capabilityRepeater
    case capabilityMacBridge
    case capabilityAccessPoint
    case capabilityRouter
    case capabilityTelephone
    case capabilityDOCSIS
    case capabilityStationOnly
    case capabilityCVLAN
    case capabilitySVLAN
    case capabilityMacRelay
    case capabilityReserved
    case enabledOther
    case enabledRepeater
    case enabledMacBridge
    case enabledAccessPoint
    case enabledRouter
    case enabledTelephone
    case enabledDOCSIS
    case enabledStationOnly
    case enabledCVLAN
    case enabledSVLAN
    case enabledMacRelay
    case enabledReserved

    case unknown(Int)  //TLV type is in the int

    public init(_ lldpType: LldpType) {
        self = lldpType
    }
}
public struct LldpValue: Equatable, Hashable {
    
    public var lldpType: LldpType
    public var startIndex: Data.Index?
    public var endIndex: Data.Index?
    
    public static func getCapabilities(data: Data) -> [LldpValue] {
        let tlvHeader = EtherCapture.getUInt16(data: data)
        let tlvLength = Int(tlvHeader & 0x01ff)
        let tlvType = Int((tlvHeader & 0xfe00) >> 9)
        guard tlvType == 7, data.count >= 6 else {
            return []
        }
        var results: [LldpValue] = []

        var flags = EtherCapture.getUInt16(data: data[data.startIndex + 2 ..< data.startIndex + 4])
        
        if flags & 0x0001 != 0 {
            results.append(LldpValue(lldpType: .capabilityOther, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0002 != 0 {
            results.append(LldpValue(lldpType: .capabilityRepeater, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0004 != 0 {
            results.append(LldpValue(lldpType: .capabilityMacBridge, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0008 != 0 {
            results.append(LldpValue(lldpType: .capabilityAccessPoint, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0010 != 0 {
            results.append(LldpValue(lldpType: .capabilityRouter, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0020 != 0 {
            results.append(LldpValue(lldpType: .capabilityTelephone, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0040 != 0 {
            results.append(LldpValue(lldpType: .capabilityDOCSIS, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0080 != 0 {
            results.append(LldpValue(lldpType: .capabilityStationOnly, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0100 != 0 {
            results.append(LldpValue(lldpType: .capabilityCVLAN, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0200 != 0 {
            results.append(LldpValue(lldpType: .capabilitySVLAN, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0x0400 != 0 {
            results.append(LldpValue(lldpType: .capabilityMacRelay, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        if flags & 0xf800 != 0 {
            results.append(LldpValue(lldpType: .capabilityReserved, startIndex: data.startIndex + 2, endIndex: data.startIndex + 4))
        }
        
        flags = EtherCapture.getUInt16(data: data[data.startIndex + 4 ..< data.startIndex + 6])
        
        if flags & 0x0001 != 0 {
            results.append(LldpValue(lldpType: .enabledOther, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0002 != 0 {
            results.append(LldpValue(lldpType: .enabledRepeater, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0004 != 0 {
            results.append(LldpValue(lldpType: .enabledMacBridge, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0008 != 0 {
            results.append(LldpValue(lldpType: .enabledAccessPoint, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0010 != 0 {
            results.append(LldpValue(lldpType: .enabledRouter, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0020 != 0 {
            results.append(LldpValue(lldpType: .enabledTelephone, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0040 != 0 {
            results.append(LldpValue(lldpType: .enabledDOCSIS, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0080 != 0 {
            results.append(LldpValue(lldpType: .enabledStationOnly, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0100 != 0 {
            results.append(LldpValue(lldpType: .enabledCVLAN, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0200 != 0 {
            results.append(LldpValue(lldpType: .enabledSVLAN, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0x0400 != 0 {
            results.append(LldpValue(lldpType: .enabledMacRelay, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        if flags & 0xf800 != 0 {
            results.append(LldpValue(lldpType: .enabledReserved, startIndex: data.startIndex + 4, endIndex: data.startIndex + 6))
        }
        return results

    }
    init(lldpType: LldpType, startIndex: Data.Index?, endIndex: Data.Index?) {
        self.lldpType = lldpType
        self.startIndex = startIndex
        self.endIndex = endIndex
    }
    init?(data: Data) {
        let tlvHeader = EtherCapture.getUInt16(data: data)
        let tlvLength = Int(tlvHeader & 0x01ff)
        let tlvType = Int((tlvHeader & 0xfe00) >> 9)
        guard data.count >= tlvLength + 2 else {
            return nil
        }
        self.startIndex = data.startIndex
        self.endIndex = data.startIndex + 2 + tlvLength
        switch tlvType {
        case 0:
            self.lldpType = LldpType(.endOfLldp)
            return
        case 1:
            let subtype = data[data.startIndex + 2]
            let subdata = data[data.startIndex + 3 ..< data.startIndex + 2 + tlvLength]
            switch subtype {
            case 4: // mac address
                if let id = EtherCapture.getMac(data: subdata) {
                    self.lldpType = LldpType(.chassisId(subtype: subtype, id: id))
                    return
                } else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                    return nil
                }
            case 5: // network address
                let addressType = data[data.startIndex + 3]
                let addressData = data[data.startIndex + 4 ..< data.endIndex]
                switch addressType {
                case 1: // ipv4?
                    guard data.count >= 8 else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                        return nil
                    }
                    let addressData = data[data.startIndex + 4 ..< data.startIndex + 8]
                    guard let ipv4Address = IPv4Address(addressData) else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) ipv4 address")
                        return nil
                    }
                    let ipv4String = ipv4Address.debugDescription
                    self.lldpType = LldpType(.chassisId(subtype: subtype, id: ipv4String))
                    return
                case 2: // ipv6?
                    guard data.count >= 20 else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                        return nil
                    }
                    let addressData = data[data.startIndex + 4 ..< data.startIndex + 20]
                    guard let ipv6Address = IPv6Address(addressData) else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) ipv6 address")
                        return nil
                    }
                    let ipv6String = ipv6Address.debugDescription
                    self.lldpType = LldpType(.chassisId(subtype: subtype, id: ipv6String))
                    return
                default: // unknown address type
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) addressType \(addressType)")
                    return nil
                }
            case 1,2,3,6,7: // Strings
                if let id = String(data: subdata, encoding: .utf8) {
                    self.lldpType = LldpType(.chassisId(subtype: subtype, id: id))
                    return
                } else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                    return nil
                }
            default:
                if let id = String(data: subdata, encoding: .utf8) {
                    self.lldpType = LldpType(.chassisId(subtype: subtype, id: id))
                    return
                } else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                    return nil
                }
            }
        case 2:  // tlv type 2 port
            let subtype = data[data.startIndex + 2]
            let subdata = data[data.startIndex + 3 ..< data.startIndex + 2 + tlvLength]
            switch subtype {
            case 3: // mac address
                if let id = EtherCapture.getMac(data: subdata) {
                    self.lldpType = LldpType(.portId(subtype: subtype, id: id))
                    return
                } else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                    return nil
                }
            case 4: // network address
                let addressType = data[data.startIndex + 3]
                let addressData = data[data.startIndex + 4 ..< data.endIndex]
                switch addressType {
                case 1: // ipv4?
                    guard data.count >= 8 else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                        return nil
                    }
                    let addressData = data[data.startIndex + 4 ..< data.startIndex + 8]
                    guard let ipv4Address = IPv4Address(addressData) else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) ipv4 address")
                        return nil
                    }
                    let ipv4String = ipv4Address.debugDescription
                    self.lldpType = LldpType(.portId(subtype: subtype, id: ipv4String))
                    return
                case 2: // ipv6?
                    guard data.count >= 20 else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                        return nil
                    }
                    let addressData = data[data.startIndex + 4 ..< data.startIndex + 20]
                    guard let ipv6Address = IPv6Address(addressData) else {
                        EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) ipv6 address")
                        return nil
                    }
                    let ipv6String = ipv6Address.debugDescription
                    self.lldpType = LldpType(.portId(subtype: subtype, id: ipv6String))
                    return
                default: // unknown address type
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) addressType \(addressType)")
                    return nil
                }
            case 1,2,5,6,7: // Strings
                if let id = String(data: subdata, encoding: .utf8) {
                    self.lldpType = LldpType(.portId(subtype: subtype, id: id))
                    return
                } else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                    return nil
                }
            default:
                if let id = String(data: subdata, encoding: .utf8) {
                    self.lldpType = LldpType(.portId(subtype: subtype, id: id))
                    return
                } else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                    return nil
                }
            }
        case 3: //ttl
            guard data.count >= 4 else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count)")
                return nil
            }
            let ttl = Int(EtherCapture.getUInt16(data: data[data.startIndex + 2 ..< data.startIndex + 4]))
            self.lldpType = LldpType(.ttl(ttl))
            return
        case 4: // port description
            guard data.count >= tlvLength + 2 else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count)")
                return nil
            }
            if let portDescription = String(data: data[data.startIndex + 2 ..< data.startIndex + 2 + tlvLength], encoding: .utf8) {
                self.lldpType = LldpType(.portDescription(portDescription))
                return
            } else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                return nil
            }
        case 5: // system name
            guard data.count >= tlvLength + 2 else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count)")
                return nil
            }
            if let systemName = String(data: data[data.startIndex + 2 ..< data.startIndex + 2 + tlvLength], encoding: .utf8) {
                self.lldpType = LldpType(.systemName(systemName))
                return
            } else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                return nil
            }
        case 6: // system description
            guard data.count >= tlvLength + 2 else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count)")
                return nil
            }
            if let systemDescription = String(data: data[data.startIndex + 2 ..< data.startIndex + 2 + tlvLength], encoding: .utf8) {
                self.lldpType = LldpType(.systemName(systemDescription))
                return
            } else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType)")
                return nil
            }
        case 8: //
            guard data.count >= 11 else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count)")
                return nil
            }
            let addressLength = Int(data[data.startIndex + 2])
            let addressSubtype = data[data.startIndex + 3]
            guard data.count >= 9 + addressLength else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count)")
                return nil
            }
            switch addressSubtype {
            case 1: // IPv4
                guard addressLength == 5 else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count) addressLength \(addressLength) addressSubtype \(addressSubtype)")
                    return nil
                }
                let addressData = data[data.startIndex + 4 ..< data.startIndex + 8]
                guard let ipv4Address = IPv4Address(addressData) else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) ipv4 address")
                    return nil
                }
                let intSubtype = Int(data[data.startIndex + 3 + addressLength])
                let intNumber = Int(EtherCapture.getUInt32(data: data[data.startIndex + 4 + addressLength ..< data.startIndex + 8 + addressLength]))
                let oidLength = Int(data[data.startIndex + 8 + addressLength])
                let oidString = String(data: data[data.startIndex + 9 + addressLength ..< data.startIndex + 9 + addressLength + oidLength], encoding: .utf8) ?? ""
                self.lldpType = LldpType(.managementAddressIPv4(address: ipv4Address, subType: intSubtype, interface: intNumber, oid: oidString))
            case 2: // ipv6
                guard addressLength == 17 else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count) addressLength \(addressLength) addressSubtype \(addressSubtype)")
                    return nil
                }
                let addressData = data[data.startIndex + 4 ..< data.startIndex + 20]
                guard let ipv6Address = IPv6Address(addressData) else {
                    EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) ipv4 address")
                    return nil
                }
                let intSubtype = Int(data[data.startIndex + 3 + addressLength])
                let intNumber = Int(EtherCapture.getUInt32(data: data[data.startIndex + 4 + addressLength ..< data.startIndex + 8 + addressLength]))
                let oidLength = Int(data[data.startIndex + 8 + addressLength])
                let oidString = String(data: data[data.startIndex + 9 + addressLength ..< data.startIndex + 9 + addressLength + oidLength], encoding: .utf8) ?? ""
                self.lldpType = LldpType(.managementAddressIPv6(address: ipv6Address, subType: intSubtype, interface: intNumber, oid: oidString))

            default:
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) data.count \(data.count) addressLength \(addressLength) addressSubtype \(addressSubtype)")
                return nil
            }
        case 127: // vendor specific
            guard data.count >= tlvLength + 2, let ouiIdentifier = EtherCapture.getOui(data: data[data.startIndex + 2 ..< data.startIndex + 5]) else {
                EtherCapture.logger.error("LLDP: unable to decode type \(tlvType) length \(tlvLength) data.count \(data.count)")
                return nil
            }
            let ouiSubtype = Int(data[data.startIndex + 5])
            let ouiString = String(data: data[data.startIndex + 6 ..< data.startIndex + 2 + tlvLength], encoding: .utf8) ?? ""
            self.lldpType = LldpType(.ouiSpecific(oui: ouiIdentifier, subType: ouiSubtype, info: ouiString))
            return
        default: // tlvtype
            self.lldpType = LldpType(.unknown(tlvType))
            return
        } // end switch tlv type
    }
    public var description: String {
        switch self.lldpType {
            
        case .endOfLldp:
            return "End Of LLDP"
        case .chassisId(let subtype, let id):
            let subtypeString: String
            switch subtype {
            case 0:
                subtypeString = "Reserved"
            case 1:
                subtypeString = "Chassis Component"
            case 2:
                subtypeString = "Interface alias"
            case 3:
                subtypeString = "Port Component"
            case 4:
                subtypeString = "MAC Address"
            case 5:
                subtypeString = "Network Address"
            case 6:
                subtypeString = "Interface Name"
            case 7:
                subtypeString = "Locally Assigned"
            default:
                subtypeString = "Reserved"
            }
            return "Chassis Id \(subtypeString) \(id)"
        case .portId(let subtype, let id):
            let subtypeString: String
            switch subtype {
            case 0:
                subtypeString = "Reserved"
            case 1:
                subtypeString = "Interface alias"
            case 2:
                subtypeString = "Port Component"
            case 3:
                subtypeString = "MAC Address"
            case 4:
                subtypeString = "Network Address"
            case 5:
                subtypeString = "Interface Name"
            case 6:
                subtypeString = "Agent Circuit ID"
            case 7:
                subtypeString = "Locally Assigned"
            default:
                subtypeString = "Reserved"
            }
            return "Port Id \(subtypeString) \(id)"
        case .ttl(let ttl):
            return "TTL \(ttl)"
        case .portDescription(let portDescription):
            return "Port Description \(portDescription)"
        case .unknown(let type):
            return "Unknown LLDP TLV Type \(type)"
        case .systemName(let systemName):
            return "System Name \(systemName)"
        case .capabilityOther:
            return "capabilityOther"
        case .capabilityRepeater:
            return "capabilityRepeater"
        case .capabilityMacBridge:
            return "capabilityMacBridge"
        case .capabilityAccessPoint:
            return "capabilityAccessPoint"
        case .capabilityRouter:
            return "capabilityRouter"
        case .capabilityTelephone:
            return "capabilityTelephone"
        case .capabilityDOCSIS:
            return "capabilityDOCSIS"
        case .capabilityStationOnly:
            return "capabilityStationOnly"
        case .capabilityCVLAN:
            return "capabilityCVLAN"
        case .capabilitySVLAN:
            return "capabilitySVLAN"
        case .capabilityMacRelay:
            return "capabilityMacRelay"
        case .capabilityReserved:
            return "capabilityReserved"
        case .enabledOther:
            return "enabledOther"
        case .enabledRepeater:
            return "enabledRepeater"
        case .enabledMacBridge:
            return "enabledMacBridge"
        case .enabledAccessPoint:
            return "enabledAccessPoint"
        case .enabledRouter:
            return "enabledRouter"
        case .enabledTelephone:
            return "enabledTelephone"
        case .enabledDOCSIS:
            return "enabledDOCSIS"
        case .enabledStationOnly:
            return "enabledStationOnly"
        case .enabledCVLAN:
            return "enabledCVLAN"
        case .enabledSVLAN:
            return "enabledSVLAN"
        case .enabledMacRelay:
            return "enabledMacRelay"
        case .enabledReserved:
            return "enabledReserved"
        case .managementAddressIPv4(let address, let subType, let interface, let oid):
            return "ManagementAddress \(address.debugDescription) InterfaceSubtype \(subType) interface \(interface) oid \(oid)"
        case .managementAddressIPv6(let address, let subType, let interface, let oid):
            return "ManagementAddress \(address.debugDescription) InterfaceSubtype \(subType) interface \(interface) oid \(oid)"
        case .ouiSpecific(let oui, let subType, let info):
            return "OUI \(oui) subType \(subType) \(info.asciiEscaped)"
        }
    }
}
public struct Lldp: CustomStringConvertible, EtherDisplay {
    
    public var description: String {
        return "LLDP \(self.values.count) TLV values"
    }
    public var verboseDescription: String {
        var retval = "LLDP "
        for value in self.values {
            retval = retval + value.description + " "
        }
        return retval
    }
    public var hexdump: String {
        return self.data.hexdump
    }
    public var data: Data
    public var values: [LldpValue] = []
    
    init?(data: Data) {
        self.data = data
        guard data.count >= 2 else {
            return nil
        }
        var position = 0
        while position <= data.count - 2 {
            let tlvHeader = EtherCapture.getUInt16(data: data[data.startIndex + position ..< data.startIndex + position + 2])
            let tlvLength = Int(tlvHeader & 0x01ff)
            let tlvType = (tlvHeader & 0xfe00) >> 9
            guard data.count >= position + tlvLength + 2 else {
                return nil
            }
            if tlvType == 7 {  // capabilities special case
                let capabilities = LldpValue.getCapabilities(data: data[data.startIndex + position ..< data.startIndex + position + tlvLength + 2])
                self.values.append(contentsOf: capabilities)
            } else if let value = LldpValue(data: data[data.startIndex + position ..< data.startIndex + position + tlvLength + 2]) {
                self.values.append(value)
            }
            position = position + tlvLength + 2
        }
        return
    }
}
