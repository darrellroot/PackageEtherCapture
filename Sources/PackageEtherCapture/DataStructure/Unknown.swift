//
//  Unknown.swift
//  packetCapture1
//
//  Created by Darrell Root on 1/24/20.
//  Copyright © 2020 com.darrellroot. All rights reserved.
//

import Foundation

struct Unknown: CustomStringConvertible {
    var description: String {
        return "unknown"
    }
    let data: Data
    init(data: Data) {
        self.data = data
    }
}
