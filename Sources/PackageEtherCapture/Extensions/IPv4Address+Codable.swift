//
//  IPv4Address+Codable.swift
//  
//
//  Created by Darrell Root on 1/31/20.
//

import Foundation
import Network

extension IPv4Address: Codable {
    enum CodingKeys: String, CodingKey {
        case ipv4String
    }
    enum IPv4AddressDecodingError: Error {
        case decoding(String)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let addressString = self.description
        try container.encode(addressString, forKey: .ipv4String)
    }
    
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let addressString = try values.decode(String.self, forKey: .ipv4String)
        guard let ipv4Address = IPv4Address(addressString) else {
            throw IPv4AddressDecodingError.decoding("unable to decode IPv4 address from \(values)")
        }
        self = ipv4Address
    }
}
