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
}
