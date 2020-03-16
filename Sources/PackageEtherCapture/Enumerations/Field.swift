//
//  File.swift
//  
//
//  Created by Darrell Root on 3/12/20.
//

import Foundation

// this is intended for fields with corresponding StartIndex and EndIndex values
// for highlighting bytes
public enum Field {
    // Frame Fields
    case srcmac
    case dstmac
    case ethertype
    case ieeeLength
    case ieeeDsap
    case ieeeSsap
    case ieeeControl
    case snapOrg
    case snapType
    case etherType
    case padding
    // ARP Fields
    case hardwareType
    case protocolType
    case hardwareSize
    case protocolSize
    case operation
    case senderEthernet
    case senderIp
    case targetEthernet
    case targetIp
    // BPDU Fields
    case protocolId
    case bpduVersion
    case type
    case flags
    case rootId
    case rootCost
    case bridgeId
    case portId
    case age
    case maxAge
    case helloTime
    case forwardDelay
    case v1Length
    
    // CDP field
    //version
    // ttl
    // checksum
    //ICMP4 fields
    //case type //duplicate above but can reuse
    case code
    case checksum
    case payload
    
    // IPv4 fields
    case sourceIP
    case destinationIP
    case version
    case ihl
    case dscp
    case ecn
    case totalLength
    case identification
    //case flags // reuse
    case fragmentOffset
    case ttl
    case ipProtocol
    case headerChecksum
    case options
    //case padding // reuse
    
    //IPv6 fields
    // case version // reuse
    case trafficClass
    case flowLabel
    case payloadLength
    case nextHeader
    case hopLimit
    // case sourceIP // reuse
    // case destinationIP // reuse
    // case padding // reuse
    
    //TCP fields
    case sourcePort
    case destinationPort
    case sequenceNumber
    case acknowledgementNumber
    case dataOffset
    //case flags
    case window
    // case checksum
    case urgentPointer
    //case options
    // case payload
    
    //UDP fields
    //case payload
    //case sourcePort
    //case destinationPort
    case length
    // case checksum
    
    //ICMP4 fields
    //case type
    //case code
    // case checksum
    // case payload
    case sequence
    case identifier
    case mask
    case pointer
    case originate
    case receive
    case transmit
    case address
    case payloadLength
}
