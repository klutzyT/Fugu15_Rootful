//
//  SettingsView.swift
//  Fugu15
//
//  Created by Ghh on 02.01.2025.
//

import SwiftUI
import Foundation
import SwiftXPC
import KRW

let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!


func tweaks() -> Bool {
    if access(documentsDirectory.appendingPathComponent(".tweaks_disabled").path, F_OK) == 0 {
        return false
    } else {
        return true
    }
}

func isjailbroken() -> Bool {
    if access("/Library/.installed_Fugu15_Rootful", F_OK) == 0 {
        KRW.logger("jailbroken")
        return true
    } else {
        return false
    }
}

func prefs_tweak_inject(change: Bool) -> Bool{
    if change {
        try? FileManager.default.removeItem(atPath: documentsDirectory.appendingPathComponent(".tweaks_disabled").path)
        if isjailbroken() {
            renameFile(atPath: "/usr/lib/TweakInject.disabled", toNewName: "TweakInject.dylib")
        }
    } else {
        FileManager.default.createFile(atPath: documentsDirectory.appendingPathComponent(".tweaks_disabled").path, contents: nil)
        if isjailbroken() {
            renameFile(atPath: "/usr/lib/TweakInject.dylib", toNewName: "TweakInject.disabled")
        }
    }
    return change
}

struct SettingsView: View {
    @State private var enable_tweaks: Bool = tweaks()
    @State private var is_jb: Bool = isjailbroken()
    @State private var showAlert: Bool = false

    
    var body: some View {
        VStack {
            Text("Fugu15 Preferences")
                .font(.largeTitle)
                .padding()
            
            
            Toggle(isOn: $enable_tweaks) {
                Text(enable_tweaks ? "Tweaks enabled" : "Tweaks disabled")
            }
            .padding()
            .disabled(isjailbroken())
            .onChange(of: enable_tweaks) { newValue in
                let _ = prefs_tweak_inject(change: enable_tweaks ? true : false)
                if is_jb {
                    showAlert = true
                }
            }.alert(isPresented: $showAlert) {
                Alert(title: Text(enable_tweaks ? "Tweaks enabled" : "Tweaks disabled"), message: Text("To apply setting - reboot userspace"), dismissButton: .default(Text("Reboot Userspace"), action: {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2, execute: {
                            let launchctlPath = "/usr/bin/launchctl"
                            _ = execCmd(args: [launchctlPath, "reboot", "userspace"])
                        })

                }))
            }
        }
        
        .padding()
        
    }
}
struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        SettingsView()
    }
}
