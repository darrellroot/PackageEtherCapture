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
        case ipv4Data
    }
    enum IPv4AddressDecodingError: Error {
        case decoding(String)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let addressData = self.rawValue
        try container.encode(addressData, forKey: .ipv4Data)
    }
    
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let addressData = try values.decode(Data.self, forKey: .ipv4Data)
        guard let ipv4Address = IPv4Address(addressData) else {
            throw IPv4AddressDecodingError.decoding("unable to decode IPv4 address from \(values)")
        }
        self = ipv4Address
    }
}
