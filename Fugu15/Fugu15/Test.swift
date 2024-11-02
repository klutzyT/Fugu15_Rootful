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

let pf = KernelPatchfinder.running!

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

func testkrwstuff() throws {
    let port = try getSurfacePort()
    
    KRW.logger("[+] Port: \(port)")
    var kobject = UInt64(0)
    //my wierd attemt to fix app crashes
    for _ in 0..<20{
        guard let virt = try? KRW.ourProc?.task!.getKObject(ofPort: port) else {
            KRW.logger("[-] OurProc is nil -> continue run")
            continue
        }
        kobject = virt
        KRW.logger("[+] Got ourProc of port \(kobject)")
        break
    }
    let surface = try KRW.rPtr(virt: kobject + 0x18/* IOSurfaceSendRight -> IOSurface */)
    
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
