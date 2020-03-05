//
//  UInt16+extensions.swift
//  
//
//  Created by Darrell Root on 3/4/20.
//

import Foundation

extension UInt16 {
    var hex: String {
        if self < 0x0010 {
            return String(format: "0x000%x",self)
        } else if self < 0x0100 {
            return String(format: "0x00%x",self)
        } else if self < 0x1000 {
            return String(format: "0x0%x",self)
        } else {
            return String(format: "0x%x",self)
        }
    }
}
