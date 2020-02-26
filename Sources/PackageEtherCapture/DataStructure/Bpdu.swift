//
//  Bpdu.swift
//  
//
//  Created by Darrell Root on 2/25/20.
//

import Foundation
import Network
import Logging

public struct Bpdu: CustomStringConvertible, EtherDisplay {
    
    public var description: String {

        return "BPDU version \(bpduVersion) type \(type) rootID \(rootIdString) bridgeID \(bridgeIdString) rootCost \(rootCost) portId \(portId)"
    }
    
    public var verboseDescription: String {
        return "BPDU protocol \(protocolId) version \(bpduVersion) type \(type) flags \(flagsString) portRole \(portRole) rootID \(rootIdString) rootCost \(rootCost) bridgeID \(bridgeIdString) portId \(portId) age \(age) maxAge \(maxAge) helloTime \(helloTime) forwardDelay \(forwardDelay) \(data.count) bytes"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }
    public var rootIdString: String {
        return String(format: "0x%x",rootId)
    }
    public var bridgeIdString: String {
        return String(format: "0x%x",bridgeId)
    }
    public var flagsString: String {
        var flags = ""
        if flagTopChangeAgree {
            flags += "TCA "
        }
        if flagAgreement {
            flags += "AGR "
        }
        if flagForwarding {
            flags += "FOR "
        }
        if flagTopChange {
            flags += "TCH "
        }
        return flags
    }
    
    public let protocolId: UInt16
    public let bpduVersion: UInt8
    public let type: UInt8
    public let flagTopChangeAgree: Bool
    public let flagAgreement: Bool
    public let flagForwarding: Bool
    public let flagLearning: Bool
    public let portRole: UInt8
    public let flagProposal: Bool
    public let flagTopChange: Bool
    public let rootId: UInt64
    public let rootCost: UInt32
    public let bridgeId: UInt64
    public let portId: UInt16
    public let age: UInt16
    public let maxAge: UInt16
    public let helloTime: UInt16
    public let forwardDelay: UInt16
    public let data: Data
    
    public var layer4: Layer4 = .unknown(Unknown.completely)

    init?(data: Data) {
        guard data.count >= 35 else {
            EtherCapture.logger.error("Unable to decode Bpdu from \(data.count) bytes")
            return nil
        }
        self.data = data
        self.protocolId = EtherCapture.getUInt16(data: data)
        self.bpduVersion = data[data.startIndex + 2]
        self.type = data[data.startIndex + 3]
        let flags: UInt8 = data[data.startIndex + 4]
        self.flagTopChangeAgree = (flags & UInt8(0x80)) != 0
        self.flagAgreement = (flags & UInt8(0x40)) != 0
        self.flagForwarding = (flags & UInt8(0x20)) != 0
        self.flagLearning = (flags & UInt8(0x10)) != 0
        self.portRole = (flags & UInt8(0x0c)) >> 2 // 3 = designated
        self.flagProposal = (flags & UInt8(0x02)) != 0
        self.flagTopChange = (flags & UInt8(0x01)) != 0
        
        self.rootId = EtherCapture.getUInt64(data: data.advanced(by: 5))
        self.rootCost = EtherCapture.getUInt32(data: data.advanced(by: 13))
        self.bridgeId = EtherCapture.getUInt64(data: data.advanced(by: 17))
        self.portId = EtherCapture.getUInt16(data: data.advanced(by: 25))
        self.age = EtherCapture.getUInt16(data: data.advanced(by: 27))
        self.maxAge = EtherCapture.getUInt16(data: data.advanced(by: 29))
        self.helloTime = EtherCapture.getUInt16(data: data.advanced(by: 31))
        self.forwardDelay = EtherCapture.getUInt16(data: data.advanced(by: 33))
        
    }
}
