//
//  socket-extensions.swift
//  stevens-ch1-daytime
//
//  Created by Darrell Root on 10/4/18.
//  Copyright © 2018 Darrell Root. All rights reserved.
//

import Foundation
import Network
import CFNetwork
//import DLog

//var targetaddr: sockaddr_in = sockaddr_in(sin_len: mysize, sin_family: sa_family_t(AF_INET), sin_port: 0, sin_addr: in_addr(s_addr: targetIP), sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))


/*extension sockaddr_in {
    init?(ipv4string: String, port: UInt16) {
        self.init()
        self.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        self.sin_family = sa_family_t(AF_INET)
        self.sin_port = port
        let split = ipv4string.components(separatedBy: ".")
        //var ip: UInt32 = 0
        guard let octet1 = UInt8(split[0]) else { return nil }
        guard let octet2 = UInt8(split[1]) else { return nil }
        guard let octet3 = UInt8(split[2]) else {return nil}
        guard let octet4 = UInt8(split[3]) else { return nil}
        let ip: UInt32 = UInt32(octet1) + UInt32(octet2) * 256 + UInt32(octet3) * 256 * 256 + UInt32(octet4) * 256 * 256 * 256
        self.sin_addr = in_addr(s_addr: ip)
        self.sin_zero = (0,0,0,0,0,0,0,0)
    }
}*/

//var targetaddr2: sockaddr = sockaddr(sa_len: mysize, sa_family: sa_family_t(AF_INET), sa_data: (0, 0, Int8, Int8, Int8, Int8, 0, 0, 0, 0, 0, 0, 0, 0))

extension sockaddr {
/*    init?(ipv4string: String, port: UInt16) {
        self.init()
        self.sa_len = UInt8(MemoryLayout<sockaddr>.size)
        self.sa_family = sa_family_t(AF_INET)
        self.sa_data.0 = Int8(port / 256)
        self.sa_data.1 = Int8(port % 256)
        let split = ipv4string.components(separatedBy: ".")
        guard split.count == 4 else { return nil}
        guard let s2 = Int8(split[0]) else { return nil }
        self.sa_data.2 = s2
        guard let s3 = Int8(split[1]) else { return nil }
        self.sa_data.3 = s3
        guard let s4 = Int8(split[2]) else { return nil }
        self.sa_data.4 = s4
        guard let s5 = Int8(split[3]) else { return nil }
        self.sa_data.5 = s5
        //old version did not work, not sure why
        //guard case self.sa_data.5 = Int8(split[3])! else { print("split 4 failed");return nil}
        self.sa_data.6 = 0
        self.sa_data.7 = 0
        self.sa_data.8 = 0
        self.sa_data.9 = 0
        self.sa_data.10 = 0
        self.sa_data.11 = 0
        self.sa_data.12 = 0
        self.sa_data.13 = 0
    }*/
    var printout: String {
        var answer = ""
        switch self.sa_family {
        case 30:
            let tupleMirror = Mirror(reflecting: self.sa_data)
            let tupleElements = tupleMirror.children.map({ $0.value }) as! [Int8]
            for tuple in tupleElements {
                answer = answer + String(format:"%02x", tuple)
            }
        case 2:
            let tupleMirror = Mirror(reflecting: self.sa_data)
            let tupleElements = tupleMirror.children.map({ $0.value }) as! [Int8]
            var skipDot = true
            for tuple in tupleElements[2..<6] {
                let octet: Int
                if tuple < 0 {
                    octet = Int(tuple) + 256
                } else {
                    octet = Int(tuple)
                }
                if skipDot {
                    skipDot = false
                } else {
                    answer = answer + "."
                }
                answer = answer + String(octet)
            }
        case 18:
            answer = "sa_family 18, ignoring"
        default:
            answer = "\(self)"
        }
        return answer
    }
}

/*extension sockaddr_in6 {
    init?(ipv6: IPv6Address) {
        self.init()
        self.sin6_len = 24
        self.sin6_family = UInt8(AF_INET6)
        self.sin6_port = 0
        self.sin6_flowinfo = 0
        var ipv6outputOptional: in6_addr?
        
        _ = ipv6.rawValue.withUnsafeBytes { (ipv6input: UnsafePointer<in6_addr>) in
            ipv6outputOptional = ipv6input.pointee
        }
        guard let ipv6output = ipv6outputOptional else {
            print("sockaddr_in6 creation failed")
            return nil
        }
        print("sockaddr_in6 creation successful")
        self.sin6_addr = ipv6output
    }
}*/
/*extension sockaddr_in6 {
    init?(ipv6addr: in6_addr, port: in_port_t) {
        self.init()
        self.sin6_len = 24
        self.sin6_family = UInt8(AF_INET6)
        self.sin6_port = port
        self.sin6_flowinfo = 0
        self.sin6_addr = ipv6addr
    }
    init?(ipv6: IPv6Address, port: in_port_t) {
        self.init()
        self.sin6_len = 24
        self.sin6_family = UInt8(AF_INET6)
        self.sin6_port = port
        self.sin6_flowinfo = 0
        let retval = inet_pton(AF_INET6, ipv6.debugDescription, &(self.sin6_addr))
        //DLog.log(.dataIntegrity,"inet_pton \(ipv6.debugDescription)")
        //self.printout()
        if retval != 1 {
            //DLog.log(.dataIntegrity,"inet_pton failed")
            return nil
        }
    }
    func printout() {
        //DLog.log(.monitor,"printing sockaddr_in6")
        //DLog.log(.monitor,"length \(self.sin6_len)")
        //DLog.log(.monitor,"family \(self.sin6_family)")
        //DLog.log(.monitor,"port \(self.sin6_port)")
        //DLog.log(.monitor,"flowinfo \(self.sin6_flowinfo)")
        print("sin6 addr \(self.sin6_addr)")
        var tmpaddr = self.sin6_addr
        var bytecount = 0
        withUnsafeBytes(of: &tmpaddr) { bytes in
            for byte in bytes {
                if byte == 0 {
                    print("00",terminator: "")
                } else if byte < 16 {
                    print(String(format: "0%1x",byte),terminator: "")
                } else {
                    print(String(format: "%2x",byte),terminator: "")
                }
                bytecount += 1
                if bytecount % 2 == 0 && bytecount < 16 {
                    print(":",terminator: "")
                }
            }
        }
        print("")
    }
    var string: String {
        var tmpaddr = self.sin6_addr
        var stringvalue = ""
        var bytecount = 0
        withUnsafeBytes(of: &tmpaddr) { bytes in
            for byte in bytes {
                if byte == 0 {
                    stringvalue += "00"
                } else if byte < 16 {
                    stringvalue += String(format: "0%1x",byte)
                } else {
                    stringvalue += String(format: "%2x",byte)
                }
                bytecount += 1
                if (bytecount % 2 == 0) && bytecount < 16 {
                    stringvalue += ":"
                }
            }
        }
        return stringvalue
    }
}*/

