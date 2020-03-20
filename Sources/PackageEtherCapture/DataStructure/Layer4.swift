//
//  Layer4.swift
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
public enum Layer4: CustomStringConvertible, EtherDisplay {
    case tcp(Tcp)
    case udp(Udp)
    case igmp4(Igmp4)
    case icmp4(Icmp4)
    case icmp6(Icmp6)
    case unknown(Unknown)
    case noLayer4     // used when we know there is no layer4 for this frame
    
    /*enum Layer4DecodingError: Error {
        case decoding(String)
    }*/
    
    public var description: String {
        switch self {
            
        case .tcp(let tcp):
            return tcp.description
        case .udp(let udp):
            return udp.description
        case .igmp4(let igmp4):
            return igmp4.description
        case .icmp4(let icmp4):
            return icmp4.description
        case .icmp6(let icmp6):
            return icmp6.description
        case .noLayer4:
            return ""
        case .unknown(let unknown):
            return unknown.description
        }
    }
    
    public var hexdump: String {
        switch self {
            
        case .tcp(let tcp):
            return tcp.hexdump
        case .udp(let udp):
            return udp.hexdump
        case .igmp4(let igmp4):
            return igmp4.hexdump
        case .icmp4(let icmp4):
            return icmp4.hexdump
        case .icmp6(let icmp6):
            return icmp6.hexdump
        case .noLayer4:
            return ""
        case .unknown(let unknown):
            return unknown.hexdump
        }
    }
    
    public var verboseDescription: String {
        switch self {
            
        case .tcp(let tcp):
            return tcp.verboseDescription
        case .udp(let udp):
            return udp.verboseDescription
        case .igmp4(let igmp4):
            return igmp4.verboseDescription
        case .icmp4(let icmp4):
            return icmp4.verboseDescription
        case .icmp6(let icmp6):
            return icmp6.verboseDescription
        case .noLayer4:
            return ""
        case .unknown(let unknown):
            return unknown.verboseDescription
        }
    }
    /*enum CodingKeys: CodingKey {
        case tcp
        case udp
        case unknown
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .tcp (let tcp):
            try container.encode(tcp, forKey: .tcp)
        case .udp (let udp):
            try container.encode(udp, forKey: .udp)
        case .unknown (let unknown):
            try container.encode(unknown, forKey: .unknown)
        }
    }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let tcp = try? container.decode(Tcp.self, forKey: .tcp) {
            self = .tcp(tcp)
            return
        }
        if let udp = try? container.decode(Udp.self, forKey: .udp) {
            self = .udp(udp)
            return
        }
        if let unknown = try? container.decode(Unknown.self, forKey: .unknown) {
            self = .unknown(unknown)
            return
        }
        throw Layer4DecodingError.decoding("Decoding error for \(container)")
    }*/
}

