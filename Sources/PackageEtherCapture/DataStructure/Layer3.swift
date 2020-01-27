//
//  Layer3.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

public enum Layer3: CustomStringConvertible {
    case ipv4(IPv4)
    case ipv6(IPv6)
    case unknown(Unknown)
    
    public var description: String {
        switch self {
            
        case .ipv4(let ipv4):
            return ipv4.description
        case .ipv6(let ipv6):
            return ipv6.description
        case .unknown(let unknown):
            return unknown.description
        }
    }
}
