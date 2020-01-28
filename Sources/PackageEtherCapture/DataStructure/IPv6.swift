//
//  IPv6.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation
import Network

public struct IPv6 {
    public let sourceIP: IPv6Address
    public let destinationIP: IPv6Address
    public var description: String {
        return "\(sourceIP.debugDescription) \(destinationIP.debugDescription)"
    }

    init?(data: Data) {
        if data.count >= 24, let sourceIP = IPv6Address(data[data.startIndex + 8 ..< data.startIndex + 24]) {
            self.sourceIP = sourceIP
        } else {
            return nil
        }
        if data.count >= 39, let destinationIP = IPv6Address(data[data.startIndex + 24 ..< data.startIndex + 40]) {
            self.destinationIP = destinationIP
        } else {
            return nil
        }
    }
}
