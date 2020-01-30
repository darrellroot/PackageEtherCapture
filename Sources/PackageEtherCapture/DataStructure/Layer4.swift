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
    case unknown(Unknown)
    
    public var description: String {
        switch self {
            
        case .tcp(let tcp):
            return tcp.description
        case .udp(let udp):
            return udp.description
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
        case .unknown(let unknown):
            return unknown.verboseDescription
        }
    }

}
