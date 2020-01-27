//
//  IPv4.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation
import Network

public struct IPv4: CustomStringConvertible {
    public var description: String {
        return "\(sourceIP) \(destinationIP)"
    }
    let sourceIP: IPv4Address
    let destinationIP: IPv4Address

    init?(data: Data) {
        if data.count > 15, let sourceIP = IPv4Address(data[data.startIndex + 12 ..< data.startIndex + 16]) {
            self.sourceIP = sourceIP
        } else {
            return nil
        }
        if data.count > 19, let destinationIP = IPv4Address(data[data.startIndex + 16 ..< data.startIndex + 20]) {
            self.destinationIP = destinationIP
        } else {
            return nil
        }
    }
}
