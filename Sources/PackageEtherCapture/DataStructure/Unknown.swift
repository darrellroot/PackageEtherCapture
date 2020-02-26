//
//  Unknown.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

public struct None: CustomStringConvertible, EtherDisplay {
    public let data: Data
    
    public var description: String {
        return "none \(data.count) bytes"
    }
    
    public var verboseDescription: String {
        return "none \(data.count) bytes"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }

    init(data: Data) {
        self.data = data
    }
}
