//
//  Igmp4.swift
//  
//
//  Created by Darrell Root on 3/20/20.
//

import Foundation
import Network

public enum IgmpType: EtherDisplay, Equatable {
    
    case membershipQuery
    case membershipQueryGeneral
    case membershipReportV2
    case membershipReportV3
    case leaveGroup
    case membershipReportV1
    case unknown(Int)
    
    init(type: Int, address: IPv4Address) {
        if type == 0x11 && address == IPv4Address("0.0.0.0")! {
            self = .membershipQueryGeneral
            return
        }
        switch type {
        case 0x11:
            self = .membershipQuery
        case 0x16:
            self = .membershipReportV2
        case 0x17:
            self = .leaveGroup
        case 0x12:
            self = .membershipReportV1
        case 0x22:
            self = .membershipReportV3
        default:
            self = .unknown(type)
        }
    }
    public var description: String {
        switch self {
        case .membershipQueryGeneral:
            return "Membership Query General"
        case .membershipQuery:
            return "Membership Query"
        case .membershipReportV2:
            return "Membership Report V2"
        case .membershipReportV1:
            return "Membership Report V1"
        case .membershipReportV3:
            return "Membership Report V3"
        case .leaveGroup:
            return "Leave Group"
        case .unknown(let type):
            return "Unknown type \(type)"
        }
    }
    
    public var verboseDescription: String {
        return self.description
    }
    
    public var hexdump: String {
        return ""
    }

}
public struct Igmp4: EtherDisplay {
    
    public let type: IgmpType
    public var maxResponseTime: Double
    public let checksum: UInt16
    public let address: IPv4Address
    public let data: Data
    public let version: Int
    public let supressFlag: Bool?
    public let querierRobustness: UInt8?
    public let queryInterval: Int?
    public let numberOfSources: Int?
    public var sources: [IPv4Address] = []
    
    public var startIndex: [Field:Data.Index] = [:] //first byte of the field
    public var endIndex: [Field:Data.Index] = [:]  //1 past last byte of the field
    
    init?(data: Data) {
        self.data = data
        guard data.count >= 8 else {
            EtherCapture.logger.error("incomplete IGMPv2 Header detected")
            return nil
        }
        
        //type moved to bottom so we can use address in type initializer
        
        //Later if this is IGMPv3 we recalculate maxResponseTime
        self.maxResponseTime = Double(data[data.startIndex + 1]) / 10.0
        startIndex[.maxResponseTime] = data.startIndex + 1
        endIndex[.maxResponseTime] = data.startIndex + 2
        
        self.checksum = EtherCapture.getUInt16(data: data[data.startIndex + 2 ..< data.startIndex + 4])
        startIndex[.checksum] = data.startIndex + 2
        endIndex[.checksum] = data.startIndex + 4
        
        guard let address = IPv4Address(data[data.startIndex + 4 ..< data.startIndex + 8]) else {
            EtherCapture.logger.error("unable to decode address")
            return nil
        }
        self.address = address
        startIndex[.address] = data.startIndex + 4
        endIndex[.address] = data.startIndex + 8
        
        let type = IgmpType(type: Int(data[data.startIndex]), address: address)
        self.type = type
        startIndex[.type] = data.startIndex
        endIndex[.type] = data.startIndex + 1
        
        guard data.count >= 12 else {
            self.version = 2
            self.supressFlag = nil
            self.querierRobustness = nil
            self.queryInterval = nil
            self.numberOfSources = nil
            return
        }
        guard type == .membershipQuery || type == .membershipQueryGeneral || type == .membershipReportV3 else {
            self.version = 2
            self.supressFlag = nil
            self.querierRobustness = nil
            self.queryInterval = nil
            self.numberOfSources = nil
            return
        }
        //IGMPv3 based on length after this point
        self.version = 3
        if data[data.startIndex + 1] > 127 {
            //recalculate max response time based for igmpv3
            let exponent = UInt32(data[data.startIndex + 1] & 0b01110000)
            let mantissa = UInt32(data[data.startIndex + 1] & 0b00001111) | 0x00000010
            let calculatedTime = mantissa << (exponent + 3)
            self.maxResponseTime = Double(calculatedTime) / 10.0
        }
        self.supressFlag = (data[data.startIndex + 8] & 0b00001000) != 0
        self.querierRobustness = (data[data.startIndex + 8] & 0b00000111)
        
        let queryIntervalCode = data[data.startIndex + 9]
        if queryIntervalCode < 128 {
            self.queryInterval = Int(queryIntervalCode)
        } else {
            let exponent = UInt32(0b01110000 & queryIntervalCode)
            let mantissa = UInt32((0b00001111 & queryIntervalCode) | 0b00010000)
            self.queryInterval = Int(mantissa << (exponent + 3))
        }
        let numberOfSources = Int(EtherCapture.getUInt16(data: data[data.startIndex + 10 ..< data.startIndex + 12]))
        self.numberOfSources = numberOfSources
        
        guard data.count >= numberOfSources * 4 + 12 else {
            EtherCapture.logger.error("IGMP4 v3 decoder \(data.count) bytes expected \(numberOfSources * 4 + 12) bytes")
            return nil
        }
        for sourceNum in 0 ..< numberOfSources {
            if let source = IPv4Address(data[data.startIndex + 12 + sourceNum * 4 ..< data.startIndex + 16 + sourceNum * 4]) {
                sources.append(source)
            }
        }
        
    }
    public var description: String {
        return "IGMP \(self.type)"
    }
    
    public var verboseDescription: String {
        let time = Double(maxResponseTime) / 10.0
        return "IGMP \(self.type) group \(address.debugDescription) MaxResponseTime \(time) seconds checksump \(checksum.hex)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }

}
