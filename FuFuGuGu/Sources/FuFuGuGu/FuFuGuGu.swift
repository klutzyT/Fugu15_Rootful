//
//  C.swift
//  FuFuGuGu
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import CBridge
import SwiftUtils
import SwiftXPCCBindings
import SwiftXPC
import Darwin


var console: Int32 = 0
//def some consts
let S_ISUID = mode_t(0004000)
let S_ISGID = mode_t(0002000)
let P_SUGID = UInt64(0x00000100)

func myStripPtr(_ ptr: OpaquePointer) -> UInt64 {
    UInt64(UInt(bitPattern: stripPtr(ptr)))
}

public func log(_ str: String) {
}

func consolelog(_ str: String) {
    var inf = str + "\n"
    let logger = URL(fileURLWithPath: "/var/mobile/Documents/console")
    do{
        if let handle = try? FileHandle(forWritingTo: logger) {
            handle.seekToEndOfFile()
            handle.write(inf.data(using: .utf8)!)
            handle.closeFile()
        }
    } catch{
        print("Error writing")
    }
}


/*
                            0x36001025
 #define CS_HARD            0x00000100  /* don't load invalid pages */
 #define CS_KILL            0x00000200  /* kill process if it becomes invalid */
 #define CS_RESTRICT        0x00000800  /* tell dyld to treat restricted */
 #define CS_ENFORCEMENT     0x00001000  /* require enforcement */
 #define CS_REQUIRE_LV      0x00002000  /* require library validation */
 #define CS_PLATFORM_BINARY 0x04000000  /* this is a platform binary */
 */

func fix_setuid(request: XPCDict) -> UInt64 {
//    consolelog("fix_setuid")
    guard let pid = request["pid"] as? UInt64 else {return 1}
//    consolelog("pid: \(pid)")
    guard let proc = try? Proc(pid: pid_t(pid))?.address as? UInt64 else {return 2}
//    consolelog("proc: \(proc)")
    guard let path = request["path"] as? String else {return 3}
//    consolelog("binary: \(path)")
    var sb = stat()
    if stat(path, &sb) == 0 {/*something must have been here...*/}
    if #available(iOS 15.2, *) {
        let ro = try! KRW.rPtr(virt:proc &+ 0x20)
        let ucred = try! KRW.rPtr(virt:ro &+ 0x20)
        let cr_posix_ptr = ucred &+ 0x18
        
        if (sb.st_mode & S_ISUID) != 0 {
            try? KRW.w32(virt: proc &+ 0x44, value: sb.st_uid)        //proc svuid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x8, value:sb.st_uid)  //ucred svuid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x0, value: sb.st_uid) //ucred uid set
        }
        if (sb.st_mode & S_ISGID) != 0 {
            try? KRW.w32(virt: proc &+ 0x48, value: sb.st_gid)         //proc svgid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x54, value: sb.st_gid) //ucred svgid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x10, value: sb.st_gid) //ucred cr_groups set
        }
        var p_flag = try! KRW.rPtr(virt: proc &+ 0x264)
        if (p_flag & P_SUGID) != 0 {
            p_flag &= ~P_SUGID
            try? KRW.w32(virt: proc &+ 0x264, value: UInt32(p_flag)) //proc p_flag set
        }
        // hardcode is my everything...
    }
    else {
        let ucred = try! KRW.rPtr(virt: proc &+ 0xD8)
        let cr_posix_ptr = ucred &+ 0x18
        
        if (sb.st_mode & S_ISUID) != 0 {
            try? KRW.w32(virt: proc &+ 0x3C, value: sb.st_uid)        //proc svuid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x8, value: sb.st_uid) //ucred svuid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x0, value: sb.st_uid) //ucred uid set
        }
        if (sb.st_mode & S_ISGID) != 0 {
            try? KRW.w32(virt: proc &+ 0x40, value: sb.st_gid)         //proc svgid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x54, value: sb.st_gid) //ucred svgid set
            try? KRW.w32(virt: cr_posix_ptr &+ 0x10, value: sb.st_gid) //ucred cr_groups set
        }
        var p_flag = try! KRW.rPtr(virt: proc &+ 0x1BC)
        if (p_flag & P_SUGID) != 0 {
            p_flag &= ~P_SUGID
            try? KRW.w32(virt: proc &+ 0x1BC, value: UInt32(p_flag)) //proc p_flag set
        }
    }
    return 0
}

func handleXPC(request: XPCDict, reply: XPCDict) -> UInt64 {
    if let action = request["action"] as? String {
        console = open("/dev/console",O_RDWR)
        defer { close(console) }
        
        log("Got action \(action)")
        switch action {
        case "fix_setuid":
            return fix_setuid(request: request)
        case "csdebug":
            if let pid = request["pid"] as? UInt64 {
                if let proc = try? Proc(pid: pid_t(pid)) {
                    if let flags = proc.cs_flags {
                        
                        proc.cs_flags = (flags & ~0x703b10) | 0x10000024 //0x2400002D
                        
                        guard let pmap = proc.task?.vmMap?.pmap else {
                            return 4
                        }
                        
                        pmap.wx_allowed = 1
                        
                        if let forceDisablePAC = request["forceDisablePAC"] as? UInt64,
                           forceDisablePAC == 1 {
                            /// ATTENTION!!! OFFFSETS ARE HARDCODED FOR iPhone SE 2020 iOS 15.2
                            /// For correct offsets - disassemble iOS kernel
                            /// If these offsets dont work -
                            pmap.jop_disabled = 1                    //0xC8  [+]   0xC4  [+]   0xC0  [-]
                            proc.task?.jop_disabled = 1              //0x348 [+]
                            proc.task?.firstThread?.jop_disabled = 1 //0x15E [+]               0x15F [-]
                            
                            reply["pacDisabled"] = 1 as UInt64
                        }
                        
                        return 0
                    } else {
                        return 3
                    }
                } else {
                    return 2
                }
            } else {
                return 1
            }
            
        case "trustcdhash":
            log("Doing trustcdhash")
            if let type = request["hashtype"] as? UInt64 {
                log("hashtype: \(type)")
                if type == 2 {
                    if let data = request["hashdata"] as? Data {
                        log("hashdata: \(data)")
                        guard data.count >= 20 else {
                            return 3
                        }
                        
                        log("Good length")
                        
                        if TrustCache.currentTrustCache == nil {
                            TrustCache.initialize()
                            if TrustCache.currentTrustCache == nil {
                                TrustCache.currentTrustCache = TrustCache()
                            }
                        }
                        
                        log("I haz initited")
                        
                        guard let tc = TrustCache.currentTrustCache else {
                            return 4
                        }
                        
                        log("I haz current")
                        
                        guard tc.append(hash: data[0..<20]) else {
                            return 5
                        }
                        
                        log("I haz appended")
                        
                        return 0
                    }
                    
                    return 2
                }
                
                return 1
            }
            
        case "fixprot":
            if let pid = request["pid"] as? UInt64 {
                if let start = request["start"] as? XPCArray {
                    if let end = request["end"] as? XPCArray {
                        guard start.count == end.count else {
                            return 99
                        }
                        
                        if start.count == 0 {
                            return 0
                        }
                        
                        var forceExec = false
                        if let f = request["forceExec"] as? UInt64,
                           f != 0 {
                            forceExec = true
                        }
                        if let proc = try? Proc(pid: pid_t(pid)) {
                            guard let links = proc.task?.vmMap?.links else {
                                return 5
                            }
                            
                            let map = links.address
                            var cur = links.next
                            while cur != nil && cur.unsafelyUnwrapped.address != map {
                                guard let eStart = cur.unsafelyUnwrapped.start else {
                                    return 5
                                }
                                
                                guard let eEnd = cur.unsafelyUnwrapped.start else {
                                    return 6
                                }
                                
                                var found = false
                                for i in 0..<start.count {
                                    guard let cStart = start[i] as? UInt64 else {
                                        continue
                                    }
                                    
                                    guard let cEnd = end[i] as? UInt64 else {
                                        continue
                                    }
                                    
                                    if cStart <= eEnd && cEnd >= eStart {
                                        found = true
                                        break
                                    }
                                }
                                
                                if !found {
                                    cur = cur.unsafelyUnwrapped.next
                                    continue
                                }
                                
                                guard let bits = cur.unsafelyUnwrapped.bits else {
                                    return 7
                                }
                                
                                let prot  = (bits >> 7)  & 0x7
                                if forceExec && (prot & UInt64(VM_PROT_WRITE)) == 0 {
                                    cur.unsafelyUnwrapped.bits = bits | (UInt64(VM_PROT_EXECUTE) << 11) | (UInt64(VM_PROT_EXECUTE) << 7)
                                } else {
                                    cur.unsafelyUnwrapped.bits = bits | (UInt64(VM_PROT_EXECUTE) << 11)
                                }
                                
                                cur = cur.unsafelyUnwrapped.next
                            }
                            
                            return 0
                        } else {
                            return 4
                        }
                    } else {
                        return 3
                    }
                } else {
                    return 2
                }
            } else {
                return 1
            }
            
        case "sbtoken":
            if let path = request["path"] as? String {
                let writeI = (request["rw"] as? UInt64) ?? 0
                let write  = writeI != 0
                let action = write ? APP_SANDBOX_READ_WRITE : APP_SANDBOX_READ
                if let token  = sandbox_extension_issue_file(action, path, 0, 0) {
                    defer { free(token) }
                    
                    var sz = malloc_size(token)
                    if sz == 0 {
                        sz = 0x40
                    }
                    
                    reply["token"] = Data(bytes: token, count: sz)
                    return 0
                } else {
                    return 2
                }
            } else {
                return 1
            }
            
        case "fixpermanent":
            if let pid = request["pid"] as? UInt64 {
                if let start = request["start"] as? UInt64 {
                    if let len = request["len"] as? UInt64 {
                        let end = start + len
                        if let proc = try? Proc(pid: pid_t(pid)) {
                            guard let links = proc.task?.vmMap?.links else {
                                return 5
                            }
                            
                            let map = links.address
                            var cur = links.next
                            while cur != nil && cur.unsafelyUnwrapped.address != map {
                                guard let eStart = cur.unsafelyUnwrapped.start else {
                                    return 5
                                }
                                
                                guard let eEnd = cur.unsafelyUnwrapped.start else {
                                    return 6
                                }
                                
                                guard start <= eEnd && end >= eStart else {
                                    cur = cur.unsafelyUnwrapped.next
                                    continue
                                }
                                
                                guard let bits = cur.unsafelyUnwrapped.bits else {
                                    return 7
                                }
                                
                                cur.unsafelyUnwrapped.bits = bits & ~(1 << 19)
                                
                                cur = cur.unsafelyUnwrapped.next
                            }
                            
                            return 0
                        } else {
                            return 4
                        }
                    } else {
                        return 3
                    }
                } else {
                    return 2
                }
            } else {
                return 1
            }
            
        default:
            break
        }
    }
    
    return 0
}

@_cdecl("swift_init")
public func swift_init(_ consoleFD: Int32, _ servicePort: mach_port_t, _ XPCServicePort: UnsafeMutablePointer<mach_port_t>) {
    console = consoleFD
    
    guard KRW.patchfinder != nil else {
        log("KernelPatchfinder.running == nil ?!")
        return
    }
    
    do {
        if servicePort != 0 {
            // Time to get KRW
            let pipe = XPCPipe(port: servicePort)
            guard let rpl = pipe.send(message: ["action": "initPPLBypass"]) as? XPCDict else {
                log("pipe.send[initPPLBypass] failed!")
                return
            }
            
            try initFromStashd(rpl: rpl)
            
            // Create kcall thread
            var kcallTh: mach_port_t = 0
            var kr = thread_create(mach_task_self_, &kcallTh)
            guard kr == KERN_SUCCESS else {
                log("thread_create failed!")
                return
            }
            
            guard let kobj = KRW.kobject(ofPort: kcallTh) else {
                log("KRW.kobject failed!")
                return
            }
            
            log("About to ask stashd to init PAC bypass")
            
            guard let rpl = pipe.send(message: ["action": "initPACBypass", "thread": kobj]) as? XPCDict else {
                log("pipe.send[initPACBypass] failed!")
                return
            }
            
            log("About to KRW.receiveKCall")
            
            try KRW.receiveKCall(thPort: kcallTh)
            
            log("Got PPL and PAC bypass!")
            
            _ = pipe.send(message: ["action": "exit"])
        }
        
        // Start KRW Server
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, XPCServicePort)
        guard kr == KERN_SUCCESS else {
            log("mach_port_allocate failed!")
            return
        }
        
        let xpc = XPCServicePort.pointee
        
        kr = mach_port_insert_right(mach_task_self_, xpc, xpc, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
        guard kr == KERN_SUCCESS else {
            log("mach_port_insert_right failed!")
            return
        }
        
        DispatchQueue(label: "FuFuGuGuXPC").async {
            while true {
                // Don't know if that is necessary
                autoreleasepool {
                    guard let request = XPCPipe.receive(port: xpc) as? XPCDict else {
                        return
                    }
                    
                    guard let reply = request.createReply() else {
                        return
                    }
                    
                    defer { XPCPipe.reply(dict: reply) }
                    
                    reply["status"] = handleXPC(request: request, reply: reply)
                }
            }
        }
        
        log("Fixing launchd...")
        
        let fixups = [
            (orig: "sandbox_check_by_audit_token", replacement: "my_sandbox_check_by_audit_token"),
            (orig: "xpc_dictionary_get_value", replacement: "my_xpc_dictionary_get_value"),
            (orig: "posix_spawn", replacement: "my_posix_spawn"),
            (orig: "posix_spawnp", replacement: "my_posix_spawnp"),
            (orig: "xpc_receive_mach_msg", replacement: "my_xpc_receive_mach_msg")
              /*
                DO NOT INTERPOSE THIS!!!
                IT WILL BREAK AIRPLAY AND POSSIBLY OTHER THINGS!!!!
//             (orig: "kill", replacement: "my_kill"),
              */
        ] as [(orig: String, replacement: String)]
        
        try doFixups(fixups: fixups)
        
        log("Fixed launchd!")
    } catch let e {
        log("[FuFuGuGu] Failed to init: \(e)")
    }
}

fileprivate func convert(_ obj: Any) -> XPCObject? {
    if let s = obj as? String {
        return s
    } else if let s = obj as? UInt64 {
        return s
    } else if let s = obj as? Int64 {
        return s
    } else if let s = obj as? Bool {
        return s
    } else if let s = obj as? [Any] {
        var res: XPCArray = []
        for x in s {
            if let c = convert(x) {
                res.append(c)
            }
        }
        
        return res
    } else if let s = obj as? [String: Any] {
        let res: XPCDict = [:]
        for x in s {
            if let c = convert(x.value) {
                res[x.key] = c
            }
        }
        
        return res
    }
    
    return nil
}

@_cdecl("swift_fix_launch_daemons")
public func swift_fix_launch_daemons(_ rObj: UnsafeMutableRawPointer) {
    let obj = Unmanaged<xpc_object_t>.fromOpaque(rObj).takeUnretainedValue()
    
    for i in (try? FileManager.default.contentsOfDirectory(atPath: "/Library/LaunchDaemons")) ?? [] {
        let path = "/Library/LaunchDaemons/" + i
        if let plistData = try? Data(contentsOf: URL(fileURLWithPath: path)) {
            if let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] {
                if let xpc = convert(plist) {
                    let xpcObj = Unmanaged<xpc_object_t>.fromOpaque(xpc.toOpaqueXPCObject()).takeUnretainedValue()
                    xpc_dictionary_set_value(obj, "/System/Library/LaunchDaemons/" + i, xpcObj)
                }
            }
        }
    }
}
