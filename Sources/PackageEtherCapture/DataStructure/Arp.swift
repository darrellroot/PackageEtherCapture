//
//  Arp.swift
//  
//
//  Created by Darrell Root on 3/4/20.
//

import Foundation
import Network
import Logging

public enum ArpOperation: String {
    case arpRequest = "ARP Request"
    case arpReply = "ARP Reply"
    case rarpRequest = "RARP Request"
    case rarpReply = "RARP Reply"
    
    init?(operation: Int) {
        switch operation {
        case 1:
            self = .arpRequest
        case 2:
            self = .arpReply
        case 3:
            self = .rarpRequest
        case 4:
            self = .rarpReply
        default:
            return nil
        }
    }
}
public struct Arp: CustomStringConvertible, EtherDisplay {
    
    
    public var description: String {

        return "\(self.operation.rawValue) sender \(senderEthernet) \(senderIp.debugDescription) target \(targetEthernet) \(targetIp.debugDescription)"
    }
    
    public var verboseDescription: String {
        
        return "\(self.description) hwType \(hardwareType) protType \(protocolType.hex) hwSize \(hardwareSize) protSize \(protocolSize)"
    }
    
    public var hexdump: String {
        return self.data.hexdump
    }

    public let hardwareType: UInt16
    public let protocolType: UInt16
    public let hardwareSize: Int
    public let protocolSize: Int
    public let operation: ArpOperation
    public let senderEthernet: String
    public let senderIp: IPv4Address
    public let targetEthernet: String
    public let targetIp: IPv4Address
    public let data: Data
    
    public var startIndex: [Field:Data.Index] = [:] //first byte of the field
    public var endIndex: [Field:Data.Index] = [:]  //1 past last byte of the field
    
    public var layer4: Layer4 = .unknown(Unknown.completely)

    init?(data: Data) {
        guard data.count >= 28 else {
            EtherCapture.logger.error("Unable to decode ARP from \(data.count) bytes")
            return nil
        }
        self.data = data
        self.hardwareType = EtherCapture.getUInt16(data: data)
        startIndex[.hardwareType] = data.startIndex
        endIndex[.hardwareType] = data.startIndex + 2
        
        self.protocolType = EtherCapture.getUInt16(data: data[data.startIndex + 2 ..< data.startIndex + 4])
        startIndex[.protocolType] = data.startIndex + 2
        endIndex[.protocolType] = data.startIndex + 4
        
        self.hardwareSize = Int(data[data.startIndex + 4])
        startIndex[.hardwareSize] = data.startIndex + 4
        endIndex[.hardwareSize] = data.startIndex + 5

        self.protocolSize = Int(data[data.startIndex + 5])
        startIndex[.protocolSize] = data.startIndex + 5
        endIndex[.protocolSize] = data.startIndex + 6

        let operationInt = Int( EtherCapture.getUInt16(data: data[data.startIndex + 6 ..< data.startIndex + 8]))
        startIndex[.operation] = data.startIndex + 6
        endIndex[.operation] = data.startIndex + 8
        guard let operation = ArpOperation(operation: operationInt) else {
            EtherCapture.logger.error("EtherCapture.Arp: invalid ARP operation \(operationInt)")
            return nil
        }
        self.operation = operation
        
        guard let senderEthernet = EtherCapture.getMac(data: data[data.startIndex + 8 ..< data.startIndex + 14]),
        let senderIp = IPv4Address(data[data.startIndex + 14 ..< data.startIndex + 18]),
        let targetEthernet = EtherCapture.getMac(data: data[data.startIndex + 18 ..< data.startIndex + 24]),
        let targetIp = IPv4Address(data[data.startIndex + 24 ..< data.startIndex + 28]) else {
            EtherCapture.logger.error("EtherCapture.Arp: unable to decode ARP from \(data.count) bytes")
            return nil
        }
        self.senderEthernet = senderEthernet
        startIndex[.senderEthernet] = data.startIndex + 8
        endIndex[.senderEthernet] = data.startIndex + 14

        self.senderIp = senderIp
        startIndex[.senderIp] = data.startIndex + 14
        endIndex[.senderIp] = data.startIndex + 18

        self.targetEthernet = targetEthernet
        startIndex[.targetEthernet] = data.startIndex + 18
        endIndex[.targetEthernet] = data.startIndex + 24

        self.targetIp = targetIp
        startIndex[.targetIp] = data.startIndex + 24
        endIndex[.targetIp] = data.startIndex + 28

        guard hardwareType == 1, protocolType == 0x0800, hardwareSize == 6, protocolSize == 4 else {
            EtherCapture.logger.error("EtherCapture.Arp: invalid types or sizes detected")
            return nil
        }
    }
}
