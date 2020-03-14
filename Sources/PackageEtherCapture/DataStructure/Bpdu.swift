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
        return "0x" + String(rootId, radix: 16, uppercase: false)
        //return String(format: "0x%x",rootId)
    }
    public var bridgeIdString: String {
        return "0x" + String(bridgeId, radix: 16, uppercase: false)
        //return String(format: "0x%x",bridgeId)
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
    public let age: Double
    public let maxAge: Double
    public let helloTime: Double
    public let forwardDelay: Double
    public let v1Length: UInt8
    public let data: Data
    
    public var startIndex: [Field:Data.Index] = [:] //first byte of the field
    public var endIndex: [Field:Data.Index] = [:]  //1 past last byte of the field
    
    public var layer4: Layer4 = .unknown(Unknown.completely)

    init?(data: Data) {
        guard data.count >= 36 else {
            EtherCapture.logger.error("Unable to decode Bpdu from \(data.count) bytes")
            return nil
        }
        self.data = data
        self.protocolId = EtherCapture.getUInt16(data: data)
        startIndex[.protocolId] = data.startIndex
        endIndex[.protocolId] = data.startIndex + 2

        self.bpduVersion = data[data.startIndex + 2] // 0=STP, 2=RSTP
        startIndex[.bpduVersion] = data.startIndex + 2
        endIndex[.bpduVersion] = data.startIndex + 3

        self.type = data[data.startIndex + 3] // 0=config, ? = top change, 2 = RSTP
        startIndex[.type] = data.startIndex + 3
        endIndex[.type] = data.startIndex + 4

        let flags: UInt8 = data[data.startIndex + 4]
        startIndex[.flags] = data.startIndex + 4
        endIndex[.flags] = data.startIndex + 5
        self.flagTopChangeAgree = (flags & UInt8(0x80)) != 0
        self.flagAgreement = (flags & UInt8(0x40)) != 0
        self.flagForwarding = (flags & UInt8(0x20)) != 0
        self.flagLearning = (flags & UInt8(0x10)) != 0
        self.portRole = (flags & UInt8(0x0c)) >> 2 // 0=unknown, 1=alternate, 2=root,3 = designated
        self.flagProposal = (flags & UInt8(0x02)) != 0
        self.flagTopChange = (flags & UInt8(0x01)) != 0
        
        self.rootId = EtherCapture.getUInt64(data: data[data.startIndex + 5 ..< data.startIndex + 13])
        startIndex[.rootId] = data.startIndex + 5
        endIndex[.rootId] = data.startIndex + 13

        self.rootCost = EtherCapture.getUInt32(data: data[data.startIndex + 13 ..< data.startIndex + 17])
        startIndex[.rootCost] = data.startIndex + 13
        endIndex[.rootCost] = data.startIndex + 17

        self.bridgeId = EtherCapture.getUInt64(data: data[data.startIndex + 17 ..< data.startIndex + 25])
        startIndex[.bridgeId] = data.startIndex + 17
        endIndex[.bridgeId] = data.startIndex + 25

        self.portId = EtherCapture.getUInt16(data: data[data.startIndex + 25 ..< data.startIndex + 27])
        startIndex[.portId] = data.startIndex + 25
        endIndex[.portId] = data.startIndex + 27

        self.age = Double(data[data.startIndex + 27]) + Double(data[data.startIndex + 28]) / 256.0
        startIndex[.age] = data.startIndex + 27
        endIndex[.age] = data.startIndex + 29

        self.maxAge = Double(data[data.startIndex + 29]) + Double(data[data.startIndex + 30]) / 256.0
        startIndex[.maxAge] = data.startIndex + 29
        endIndex[.maxAge] = data.startIndex + 31

        self.helloTime = Double(data[data.startIndex + 31]) + Double(data[data.startIndex + 32]) / 256.0
        startIndex[.helloTime] = data.startIndex + 31
        endIndex[.helloTime] = data.startIndex + 33

        self.forwardDelay = Double(data[data.startIndex + 33]) + Double(data[data.startIndex + 34]) / 256.0
        startIndex[.forwardDelay] = data.startIndex + 33
        endIndex[.forwardDelay] = data.startIndex + 35
        
        self.v1Length = data[data.startIndex + 35]
        startIndex[.v1Length] = data.startIndex + 35
        endIndex[.v1Length] = data.startIndex + 36
    }
}
