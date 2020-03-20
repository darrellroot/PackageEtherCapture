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
    public let maxResponseTime: Int
    public let checksum: UInt16
    public let address: IPv4Address
    public let data: Data
    
    public var startIndex: [Field:Data.Index] = [:] //first byte of the field
    public var endIndex: [Field:Data.Index] = [:]  //1 past last byte of the field
    
    init?(data: Data) {
        self.data = data
        guard data.count >= 8 else {
            EtherCapture.logger.error("incomplete IGMPv2 Header detected")
            return nil
        }
        
        //type moved to bottom so we can use address in type initializer
        
        self.maxResponseTime = Int(data[data.startIndex + 1])
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
        
        self.type = IgmpType(type: Int(data[data.startIndex]), address: address)
        startIndex[.type] == data.startIndex
        endIndex[.type] == data.startIndex + 1
        
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
