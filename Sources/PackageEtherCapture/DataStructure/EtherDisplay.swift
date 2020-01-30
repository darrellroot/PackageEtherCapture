//
//  File.swift
//  
//
//  Created by Darrell Root on 1/29/20.
//

import Foundation

public protocol EtherDisplay {
    var description: String { get }
    var verboseDescription: String { get }
    var hexdump: String { get }
    
}
