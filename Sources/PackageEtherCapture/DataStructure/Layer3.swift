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
    
    /*enum Layer3DecodingError: Error {
        case decoding(String)
    }

    enum CodingKeys: CodingKey {
        case ipv4
        case ipv6
        case unknown
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .ipv4 (let ipv4):
            try container.encode(ipv4, forKey: .ipv4)
        case .ipv6 (let ipv6):
            try container.encode(ipv6, forKey: .ipv6)
        case .unknown (let unknown):
            try container.encode(unknown, forKey: .unknown)
        }
    }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let ipv4 = try? container.decode(IPv4.self, forKey: .ipv4) {
            self = .ipv4(ipv4)
            return
        }
        if let ipv6 = try? container.decode(IPv6.self, forKey: .ipv6) {
            self = .ipv6(ipv6)
            return
        }
        if let unknown = try? container.decode(Unknown.self, forKey: .unknown) {
            self = .unknown(unknown)
            return
        }
        throw Layer3DecodingError.decoding("Decoding error for \(container)")
    }*/

}
