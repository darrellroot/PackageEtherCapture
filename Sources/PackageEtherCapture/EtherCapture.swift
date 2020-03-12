
import Foundation
import Darwin
import PackageEtherCaptureC
import Logging

public enum EtherCaptureError: Error, CustomStringConvertible {
    
    case pcap_open_live_failed(message: String)
    case pcap_lookupnet_failed(message: String)
    case pcap_lookupdev_failed(message: String)
    case pcap_compile_failed(message: String)
    case pcap_setfilter_failed(message: String)
    case pcap_max_captures_exceeded
    case unsupported_datalink(message: String)
    case genericError(String)
    
    
    public var localizedDescription: String {
        return self.description
    }
    public var description: String {
        switch self {
            
        case .pcap_open_live_failed(let message):
            return "pcap_open_live failed with error \(message)"
        case .pcap_lookupnet_failed(let message):
            return "pcap_lookupnet failed with error \(message)"
        case .pcap_lookupdev_failed(let message):
            return "pcap_lookupdev failed with error \(message)"
        case .pcap_compile_failed(let message):
            return "pcap_compile failed with error \(message)"
        case .pcap_setfilter_failed(let message):
            return "pcap_setupfilter failed with error \(message)"
        case .pcap_max_captures_exceeded:
            return "pcap max captures exceeded"
        case .unsupported_datalink(let message):
            return "unsupported pcap datalink type: \(message)"
        case .genericError(let message):
            return "unexpected error \(message)"
        }
    }
}
public class EtherCapture {
    public static var logger = Logger(label: "net.networkmom.PackageEtherCapture")
    var errbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PCAP_ERRBUF_SIZE))
    var datalink: Int32
    var interfaceNames: [String] = []
    var pcap: OpaquePointer
    var fcode: UnsafeMutablePointer<bpf_program>
    var packetCount = 0
    //var callback: ((Frame) -> Void)? = nil
    
    static var callbacks: [((Frame) -> Void)] = []
    public init(interface: String, count: Int32 = 0, command: String, snaplen: Int = 96, promiscuous: Bool = true, _ callback: @escaping (Frame) -> Void) throws {
        EtherCapture.logger.warning("Executing etherdump on interface \(interface) count \(count) snaplen \(snaplen) promiscuous \(promiscuous) command \(command)")
        //alldevs!.initialize(to: nil)
        //pcap_findalldevs(2,3)
        //var retval = pcap_findalldevs(&alldevs, errbuf)
        /*debugPrint("pcap_findalldevs retval \(retval)")
        if retval == -1 {
            let errString = String(cString: errbuf)
            debugPrint("pcap_findalldevs error \(errString)")
            return nil
        }*/
        
        /*var nextdev: UnsafeMutablePointer<pcap_if_t>? = alldevs
        repeat {
            if let thisdevPtr = nextdev {
                let thisdev = thisdevPtr.pointee
                if thisdev.name != nil {
                    let name = String(cString: thisdev.name)
                    debugPrint("name \(name)")
                    interfaceNames.append(name)
                }
                if thisdev.description != nil {
                    let description = String(cString: thisdev.description)
                    debugPrint("description \(description)")
                }
                // TODO ipv6 address information learned via pcap seems incorrect
                if let addresses = thisdev.addresses {
                    var nextAddress: UnsafeMutablePointer<pcap_addr>? = addresses
                    repeat {
                        if let thisAddress = nextAddress {
                            if let address = thisAddress.pointee.addr?.pointee {
                                debugPrint("address \(address.printout)")
                            }
                            if let netmask = thisAddress.pointee.netmask?.pointee {
                                debugPrint("netmask \(netmask.printout)")
                            }
                            if let broadcastAddress = thisAddress.pointee.broadaddr?.pointee {
                                debugPrint("broadcast \(broadcastAddress.printout)")
                            }
                            if let dstaddr = thisAddress.pointee.dstaddr?.pointee {
                                debugPrint("p2p destination address \(dstaddr.printout)")
                            }
                            nextAddress = thisAddress.pointee.next
                        } else {
                            nextAddress = nil // terminates loop
                        }
                    } while nextAddress != nil
                }
                let flags = thisdev.flags
                debugPrint("flags %x", flags)
                nextdev = thisdev.next
            } else {
                nextdev = nil  // can only happen on first round if already nil, but just in case
            }
        } while nextdev != nil*/
        
        let promiscuousInt: Int32 = promiscuous ? 1 : 0
        let snaplen = Int32(snaplen)
        guard let pcap = pcap_open_live(interface, snaplen, promiscuousInt, 1000, errbuf) else {
            let errString = String(cString: errbuf)
            //debugPrint("pcap_open_live failed \(errString)")
            throw EtherCaptureError.pcap_open_live_failed(message: errString)
        }
        self.pcap = pcap
        let localnet = UnsafeMutablePointer<bpf_u_int32>.allocate(capacity: 1)
        let netmask = UnsafeMutablePointer<bpf_u_int32>.allocate(capacity: 1)
        
        var retval = pcap_lookupnet(interface, localnet, netmask, errbuf)
        if retval < 0 {
            let errString = String(cString: errbuf)
            //debugPrint("pcap_lookupnet failed \(errString)")
            throw EtherCaptureError.pcap_lookupnet_failed(message: errString)
        }
        //let localnetString = String(format:"%2x", localnet.pointee)  // TODO byte order issue here
        //let netmaskString = String(format: "%2x", netmask.pointee)
        //debugPrint("localnet \(localnetString) \(netmaskString)")
        
        //let cmd = UnsafePointer<Int8>((NSString("port 443")).utf8String)
        let cmd = UnsafePointer<Int8>((NSString(string: command)).utf8String)
        fcode = UnsafeMutablePointer<bpf_program>.allocate(capacity: 1)
        //We set pcap_compile to optimize, TODO fix netmask
        retval = pcap_compile(pcap, fcode, cmd, 1, netmask.pointee)
        if retval < 0 {
            let errString: String
            if let error = pcap_geterr(pcap) {
                errString = String(cString: error)
            } else {
                errString = "unknown error"
            }
            //debugPrint("pcap_compile failed \(errString)")
            throw EtherCaptureError.pcap_compile_failed(message: errString)
        }
        retval = pcap_setfilter(pcap, fcode)  // this starts the capture!
        guard retval >= 0 else {
            let errString: String
            if let error = pcap_geterr(pcap) {
                errString = String(cString: error)
            } else {
                errString = "unknown error"
            }
            //debugPrint("pcap_setfilter failed \(errString)")
            throw EtherCaptureError.pcap_setfilter_failed(message: errString)
        }
        self.datalink = pcap_datalink(pcap)
        // see http://www.tcpdump.org/linktypes.html for return value information
        // datalink 1 is Ethernet, datalink 105 is 802.11
        guard self.datalink == DLT_EN10MB || self.datalink == DLT_IEEE802_11 else {
            //debugPrint("datalink type \(self.datalink)")
            throw EtherCaptureError.unsupported_datalink(message: String(self.datalink))
        }
        //debugPrint("datalink type \(self.datalink)")
        
        EtherCapture.callbacks.append(callback)
        guard EtherCapture.callbacks.count < 256 else {
            throw EtherCaptureError.pcap_max_captures_exceeded
        }
        var callbackIndex: u_char = u_char(EtherCapture.callbacks.count - 1)
        let callbackIndexPointer = UnsafeMutablePointer<u_char>.allocate(capacity: 1)
        callbackIndexPointer.initialize(from: &callbackIndex, count: 1)
        
        Frame.frameCount = 0 // cannot put frameCount context into the C callback
        // so we hope the static variable will count accurately for us
        // if there are 2 simultaneous captures, the counting will be off
        
        DispatchQueue.global().async {
            
            
            pcap_loop(self.pcap, count,
                {
                    (args: UnsafeMutablePointer<UInt8>?,
                     header:UnsafePointer<pcap_pkthdr>?,
                     ptr: UnsafePointer<UInt8>?) -> () in
                    if let header = header, let ptr = ptr {
                        let timestamp = header.pointee.ts
                        //let packetLength = header.pointee.len  //we may not capture whole packet
                        let captureLength = Int(header.pointee.caplen)
                        let originalLength = Int(header.pointee.len)
                        let data = Data(bytes: ptr, count: captureLength)
                        let frame = Frame(data: data, timeval: timestamp, originalLength: originalLength)
                        if let pointee = args?.pointee,                        Int(pointee) < EtherCapture.callbacks.count {
                            EtherCapture.callbacks[Int(pointee)](frame)
                        } else {
                            EtherCapture.logger.error("Invalid PackageEtherCapture callback")
                        }
                    }
                                
                },
            callbackIndexPointer)

        }

    }//init
    
    /*old code from prior to switch to pcap_loop
    public func nextPacket() -> Frame? {
        
        var header = pcap_pkthdr()
        
        let ptr = pcap_next(pcap, &header)
        let timestamp = header.ts
        let packetLength = header.len  //we may not capture whole packet
        let captureLength = Int(header.caplen)
        //debugPrint("packet \(self.packetCount) ptr \(String(describing: ptr))")
        self.packetCount = self.packetCount + 1
        if let ptr = ptr {
            let data = Data(bytes: ptr, count: captureLength)
            let frame = Frame(data: data, timeval: timestamp)
            
            /*for offset in 0..<captureLength {
                let offsetPtr = ptr + offset
                print(String(format: "%02x", offsetPtr.pointee), terminator:"")
            }*/
            //print("\n")
            return frame
        } else {
            return nil
        }
    }*/
    /**
     Cancels the pcap_loop
     */
    public func cancel() {
        EtherCapture.logger.warning("EtherCapture.cancel: Cancelling pcap_loop")
        pcap_breakloop(pcap)
    }
    public static func defaultInterface() throws -> String {
        let errbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PCAP_ERRBUF_SIZE))
        guard let dev = pcap_lookupdev(errbuf) else {
            let errString = String(cString: errbuf)
            throw EtherCaptureError.pcap_lookupdev_failed(message: errString)
        }
        return(String(cString: dev))
    }
    
    public static func pcapVersion() -> String {
        guard let versionC = pcap_lib_version() else {
            return "unknown"
        }
        let version: String = String(cString: versionC)
        return version
    }
    public static func listInterfaces() -> [String]? {
        // This does not seem to work on my system.  I think it used to work.
        var alldevs: UnsafeMutablePointer<pcap_if_t>? = nil
        let errbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PCAP_ERRBUF_SIZE))
        var interfaceNames: [String] = []
        //alldevs!.initialize(to: nil)
        let retval = pcap_findalldevs(&alldevs, errbuf)
        //debugPrint("pcap_findalldevs retval \(retval)")
        if retval == -1 {
            let errString = String(cString: errbuf)
            EtherCapture.logger.error("pcap_findalldevs error \(errString)")
            return nil
        }
        
        var nextdev: UnsafeMutablePointer<pcap_if_t>? = alldevs
        repeat {
            if let thisdevPtr = nextdev {
                let thisdev = thisdevPtr.pointee
                if thisdev.name != nil {
                    let name = String(cString: thisdev.name)
                    //debugPrint("name \(name)")
                    interfaceNames.append(name)
                }
                /*if thisdev.description != nil {
                    let description = String(cString: thisdev.description)
                    debugPrint("description \(description)")
                }*/
                // TODO ipv6 address information learned via pcap seems incorrect
                /*if let addresses = thisdev.addresses {
                    var nextAddress: UnsafeMutablePointer<pcap_addr>? = addresses
                    repeat {
                        if let thisAddress = nextAddress {
                            if let address = thisAddress.pointee.addr?.pointee {
                                debugPrint("address \(address.printout)")
                            }
                            if let netmask = thisAddress.pointee.netmask?.pointee {
                                debugPrint("netmask \(netmask.printout)")
                            }
                            if let broadcastAddress = thisAddress.pointee.broadaddr?.pointee {
                                debugPrint("broadcast \(broadcastAddress.printout)")
                            }
                            if let dstaddr = thisAddress.pointee.dstaddr?.pointee {
                                debugPrint("p2p destination address \(dstaddr.printout)")
                            }
                            nextAddress = thisAddress.pointee.next
                        } else {
                            nextAddress = nil // terminates loop
                        }
                    } while nextAddress != nil
                }*/
                //let flags = thisdev.flags
                //debugPrint("flags %x", flags)
                nextdev = thisdev.next
            } else {
                nextdev = nil  // can only happen on first round if already nil, but just in case
            }
        } while nextdev != nil
        pcap_freealldevs(alldevs)
        return interfaceNames
    }
    
    public static func makePcap(frames: [Frame]) -> Data {
        // https://wiki.wireshark.org/Development/LibpcapFileFormat
            
        guard frames.count > 0 else {
            return Data()  // no frames return empty Data
        }
        var totalSize = 24 + 256 // 256 more than we need
        var maxSize:UInt32 = 0  // we will assume this is snaplen.  not really true
        for frame in frames {
            totalSize = totalSize + 16 + frame.data.count
            if frame.data.count > maxSize {
                maxSize = UInt32(frame.data.count)
            }
        }
        var returnData = Data(capacity: totalSize)
        returnData.append((UInt32(0xa1b2c3d4)).data)
        returnData.append((UInt16(2)).data)
        returnData.append((UInt16(4)).data)
        returnData.append((Int32(0)).data)
        returnData.append((UInt32(0)).data)
        returnData.append(maxSize.data)
        returnData.append(UInt32(1).data) // assume ethernet
        
        // credit https://stackoverflow.com/questions/31396301/getting-the-decimal-part-of-a-double-in-swift
        let numberOfPlaces:Double = 6.0
        let powerOfTen:Double = pow(10.0, numberOfPlaces)

        for frame in frames {
            let seconds = UInt32(frame.date.timeIntervalSince1970)
            let fractionalSeconds = frame.date.timeIntervalSince1970.truncatingRemainder(dividingBy: 1.0)
            let microSeconds = UInt32(fractionalSeconds * powerOfTen)
            returnData.append(seconds.data)
            returnData.append(microSeconds.data)
            returnData.append(UInt32(frame.data.count).data)
            returnData.append(UInt32(frame.originalLength).data)
            returnData.append(frame.data)
        }
        return returnData
    }
    
    static let bigEndian = true // refers to the endianness of the data we get
    
    static func getUInt32(data: Data)-> UInt32 {
        let octet0: UInt32 = UInt32(data[data.startIndex])
        let octet1: UInt32 = UInt32(data[data.startIndex + 1])
        let octet2: UInt32 = UInt32(data[data.startIndex + 2])
        let octet3: UInt32 = UInt32(data[data.startIndex + 3])
        if EtherCapture.bigEndian == false {
            return octet0 + octet1 << 8 + octet2 << 16 + octet3 << 24
        } else {
            return octet0 << 24 + octet1 << 16 + octet2 << 8 + octet3
        }
    }
    static func getUInt16(data: Data)-> UInt16 {
        let octet0: UInt16 = UInt16(data[data.startIndex])
        let octet1: UInt16 = UInt16(data[data.startIndex + 1])
        if EtherCapture.bigEndian == false {
            return octet0 + octet1 << 8
        } else {
            return octet0 << 8 + octet1
        }
    }
    static func getInt64(data: Data)-> Int64 {
        let first4 = getUInt32(data: data)
        let second4 = getUInt32(data: data[data.startIndex + 4 ..< data.startIndex + 8])
        if EtherCapture.bigEndian == false {
            return Int64(UInt64(first4) << 32 + UInt64(second4))
        } else {
            return Int64(UInt64(first4) + UInt64(second4) << 32)
        }
    }
    static func getUInt64(data: Data)-> UInt64 {
        let first4 = getUInt32(data: data)
        let second4 = getUInt32(data: data[data.startIndex + 4 ..< data.startIndex + 8])
        if EtherCapture.bigEndian == true {
            return UInt64(first4) << 32 + UInt64(second4)
        } else {
            return UInt64(first4) + UInt64(second4) << 32
        }
    }
    static func getOui(data: Data) -> String? {
        //input: 3 octets of data
        //output: returns a string in mac address format
        guard data.count >= 3 else {
            return nil
        }
        var hexEncodedString = data[data.startIndex ..< data.startIndex + 3].hexEncodedString()
        guard hexEncodedString.count >= 6 else {
            return hexEncodedString
        }
        var index = hexEncodedString.endIndex
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        return hexEncodedString
    }

    static func getMac(data: Data) -> String? {
        //input: 6 octets of data
        //output: returns a string in mac address format
        guard data.count >= 6 else {
            return nil
        }
        var hexEncodedString = data[data.startIndex ..< data.startIndex + 6].hexEncodedString()
        guard hexEncodedString.count >= 12 else {
            return hexEncodedString
        }
        var index = hexEncodedString.endIndex
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        index = hexEncodedString.index(index, offsetBy: -2)
        hexEncodedString.insert(":", at: index)
        return hexEncodedString
    }
    static func getCStrings(data: Data) -> [String] {
        guard let bigString = String(data: data, encoding: .utf8) else {
            EtherCapture.logger.error("Unable to decode strings from data \(data)")
            return []
        }
        let substrings = bigString.split(separator: "\0", omittingEmptySubsequences: true)
        return substrings.map{String($0)}
    }

}

// keeping these extensions private
// from https://gist.github.com/bpolania/704901156020944d3e20fef515e73d61
extension UInt8 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt8>.size)
    }
}
extension UInt16 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt16>.size)
    }
}
extension UInt32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }
}


extension Int32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<Int32>.size)
    }
}


