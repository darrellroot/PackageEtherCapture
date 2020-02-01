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
        case ipv6Data
    }
    enum IPv6AddressDecodingError: Error {
        case decoding(String)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let addressData = self.rawValue
        try container.encode(addressData, forKey: .ipv6Data)
    }
    
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let addressData = try values.decode(Data.self, forKey: .ipv6Data)
        guard let ipv6Address = IPv6Address(addressData) else {
            throw IPv6AddressDecodingError.decoding("unable to decode IPv6 address from \(values)")
        }
        self = ipv6Address
    }
}
