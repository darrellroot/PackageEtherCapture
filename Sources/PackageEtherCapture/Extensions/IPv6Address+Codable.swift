//
//  IPv6Address+Codable.swift
//  
//
//  Created by Darrell Root on 1/31/20.
//

import Foundation
import Network

extension IPv6Address: Codable {
    enum CodingKeys: String, CodingKey {
        case ipv6String
    }
    enum IPv6AddressDecodingError: Error {
        case decoding(String)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let addressString = self.debugDescription
        try container.encode(addressString, forKey: .ipv6String)
    }
    
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let addressString = try values.decode(String.self, forKey: .ipv6String)
        guard let ipv6Address = IPv6Address(addressString) else {
            throw IPv6AddressDecodingError.decoding("unable to decode IPv6 address from \(values)")
        }
        self = ipv6Address
    }
}
