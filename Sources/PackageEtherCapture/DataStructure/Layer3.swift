//
//  Layer3.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

/**
 Enumeration containing anything encapsulated in the ethernet frame.
 Usually layer-3 (IPv4, IPv6) but could be encapsulated Layer 2
 (LDP, CDP, STP)
 */
public enum Layer3: CustomStringConvertible, EtherDisplay {
    case ipv4(IPv4)
    case ipv6(IPv6)
    case arp(Arp)
    case bpdu(Bpdu)
    case cdp(Cdp)
    case lldp(Lldp)
    case unknown(Unknown)
    

/*    public var layer4: Any {
        switch self {
            case .ipv4(let ipv4):
                return ipv4
            case .ipv6(let ipv6):
                return ipv6
            case .bpdu(let bpdu):
                return bpdu
            case .cdp(let cdp):
                return cdp
            case .unknown(let unknown):
                return unknown
        }
    }*/
    public var description: String {
        switch self {
            
        case .ipv4(let ipv4):
            return ipv4.description
        case .ipv6(let ipv6):
            return ipv6.description
        case .arp(let arp):
            return arp.description
        case .bpdu(let bpdu):
            return bpdu.description
        case .cdp(let cdp):
            return cdp.description
        case .lldp(let lldp):
            return lldp.description
        case .unknown(let unknown):
            return unknown.description
        }
    }
    
    public var hexdump: String {
        switch self {
            
        case .ipv4(let ipv4):
            return ipv4.hexdump
        case .ipv6(let ipv6):
            return ipv6.hexdump
        case .arp(let arp):
            return arp.hexdump
        case .bpdu(let bpdu):
            return bpdu.hexdump
        case .cdp(let cdp):
            return cdp.hexdump
        case .lldp(let lldp):
            return lldp.hexdump
        case .unknown(let unknown):
            return unknown.hexdump
        }
    }
    
    public var verboseDescription: String {
        switch self {
            
        case .ipv4(let ipv4):
            return ipv4.verboseDescription
        case .ipv6(let ipv6):
            return ipv6.verboseDescription
        case .arp(let arp):
            return arp.verboseDescription
        case .bpdu(let bpdu):
            return bpdu.verboseDescription
        case .cdp(let cdp):
            return cdp.verboseDescription
        case .lldp(let lldp):
            return lldp.verboseDescription
        case .unknown(let unknown):
            return unknown.verboseDescription
        }
    }

}
