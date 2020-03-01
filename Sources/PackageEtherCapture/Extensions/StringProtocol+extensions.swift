//
//  StringProtocol+extensions.swift
//  
//
//  Created by Darrell Root on 2/29/20.
//

import Foundation
extension StringProtocol {
    var asciiEscaped: String {
        unicodeScalars.map{$0.escaped(asASCII: true)}.joined()
    }
}
