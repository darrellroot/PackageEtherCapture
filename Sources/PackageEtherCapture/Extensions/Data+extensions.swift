//
//  File.swift
//  
//
//  Created by Darrell Root on 1/28/20.
//

import Foundation

extension Data {
    public var hexdump: String {
        var output: String = ""
        output.reserveCapacity(self.count * 3)
        for (position,datum) in self.enumerated() {
            switch (position % 2 == 0, position % 16 == 0, position % 16 == 15) {
            case (false, false, false): // odd positions
                output.append(datum.hex)
                output.append(" ")
            case (false, false, true): // end of line, odd
                output.append(datum.hex)
                output.append("\n")
            case (true, true, false):  // beginning of line, even
                output.append(String(format: "0x%04x ",position))
                output.append(datum.hex)
            case (true, false, false): // even but not beginning of line
                output.append(datum.hex)
            case (false, true, false),(false, true, true),(true, false, true),(true, true, true):  // invalid cases
                EtherCapture.logger.error("unexpected hexdump case")
            }
        }
        if self.count % 16 != 0 {  // adding newline if we didn't just do that
            output.append("\n")
        }
        return output
    }
}
extension Data {
    //https://stackoverflow.com/questions/39075043/how-to-convert-data-to-hex-string-in-swift/40089462#40089462
    private static let hexAlphabet = "0123456789abcdef".unicodeScalars.map { $0 }

    public func hexEncodedString() -> String {
        return String(self.reduce(into: "".unicodeScalars, { (result, value) in
            result.append(Data.hexAlphabet[Int(value/16)])
            result.append(Data.hexAlphabet[Int(value%16)])
        }))
    }
}
