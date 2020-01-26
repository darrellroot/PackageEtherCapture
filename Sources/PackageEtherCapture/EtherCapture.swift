
import Foundation
import Darwin
import PackageEtherCaptureC

class EtherCapture {
    var errbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PCAP_ERRBUF_SIZE))
    var alldevs: UnsafeMutablePointer<pcap_if_t>? = nil
    var datalink: Int32
    var interfaceNames: [String] = []
    var pcap: OpaquePointer
    var fcode: UnsafeMutablePointer<bpf_program>
    var packetCount = 0
    public init?(interface: String, command: String) {
        //alldevs!.initialize(to: nil)
        //pcap_findalldevs(2,3)
        var retval = pcap_findalldevs(&alldevs, errbuf)
        debugPrint("pcap_findalldevs retval \(retval)")
        if retval == -1 {
            let errString = String(cString: errbuf)
            debugPrint("pcap_findalldevs error \(errString)")
            return nil
        }
        
        var nextdev: UnsafeMutablePointer<pcap_if_t>? = alldevs
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
        } while nextdev != nil
        
        guard let pcap = pcap_open_live(interface, 200, 0, 2000, errbuf) else {
            let errString = String(cString: errbuf)
            debugPrint("pcap_open_live failed \(errString)")
            return nil
        }
        self.pcap = pcap
        var localnet = UnsafeMutablePointer<bpf_u_int32>.allocate(capacity: 1)
        var netmask = UnsafeMutablePointer<bpf_u_int32>.allocate(capacity: 1)
        
        retval = pcap_lookupnet(interface, localnet, netmask, errbuf)
        if retval < 0 {
            let errString = String(cString: errbuf)
            debugPrint("pcap_lookupnet failed \(errString)")
            return nil
        }
        let localnetString = String(format:"%2x", localnet.pointee)  // TODO byte order issue here
        let netmaskString = String(format: "%2x", netmask.pointee)
        debugPrint("localnet \(localnetString) \(netmaskString)")
        
        var cmd = UnsafePointer<Int8>((NSString("port 443")).utf8String)
        fcode = UnsafeMutablePointer<bpf_program>.allocate(capacity: 1)
        retval = pcap_compile(pcap, fcode, cmd, 0, PCAP_NETMASK_UNKNOWN)
        if retval < 0 {
            let errString: String
            if let error = pcap_geterr(pcap) {
                errString = String(cString: error)
            } else {
                errString = "unknown error"
            }
            debugPrint("pcap_compile failed \(errString)")
            return nil
        }
        retval = pcap_setfilter(pcap, fcode)  // this starts the capture!
        guard retval >= 0 else {
            let errString: String
            if let error = pcap_geterr(pcap) {
                errString = String(cString: error)
            } else {
                errString = "unknown error"
            }
            debugPrint("pcap_setfilter failed \(errString)")
            return nil
        }
        datalink = pcap_datalink(pcap)
        // see http://www.tcpdump.org/linktypes.html for return value information
        debugPrint("datalink type \(datalink)")
    }//init
    
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
            print("\n")
            return frame
        } else {
            return nil
        }
    }
}
