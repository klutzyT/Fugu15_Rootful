//
//  JailbreakView.swift
//  Fugu15
//
//  Created by Linus Henze on 2022-07-29.
//

import SwiftUI
//import Fugu15KernelExploit
import KRW
import iDownload
import SwiftXPC

var jbDone = false

enum JBStatus {
    case notStarted
    case unsupported
    case inProgress
    case failed
    case done
    
    func text() -> String {
        switch self {
        case .notStarted:
            return "Jailbreak"
            
        case .unsupported:
            return "Unsupported"
            
        case .inProgress:
            return "Jailbreaking..."
            
        case .failed:
            return "Error!"
            
        case .done:
            return "Jailbroken"
        }
    }
    
    func color() -> Color {
        switch self {
        case .notStarted:
            return .accentColor
            
        case .unsupported:
            return .accentColor
            
        case .inProgress:
            return .accentColor
            
        case .failed:
            return .red
            
        case .done:
            return .green
        }
    }
}

struct JailbreakView: View {
    @Binding var logText: String
    
    @State var status: JBStatus = .notStarted
    @State var textStatus1      = "Status: Not running"
    @State var textStatus2      = ""
    @State var textStatus3      = ""
    @State var showSuccessMsg   = false
    
    var body: some View {
        VStack {
            Button(status.text(), action: {
                status = .inProgress
                
                DispatchQueue(label: "Fugu15").async {
                    launchExploit()
                }
            })
                .padding()
                .background(status.color())
                .cornerRadius(10)
                .foregroundColor(Color.white)
                .disabled(status != .notStarted)
            
            Text(textStatus1)
                .padding([.top, .leading, .trailing])
                .font(.headline)
            Text(textStatus2)
                .padding([.leading, .trailing])
                .font(.subheadline)
                .opacity(0.5)
            Text(textStatus3)
                .padding([.leading, .trailing])
                .font(.footnote)
                .opacity(0.4)
        }.alert(isPresented: $showSuccessMsg) {
            Alert(title: Text("Success"), message: Text("All exploits succeded and iDownload is now running on port 1337!"), dismissButton: .default(Text("Reboot Userspace"), action: {
                if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 && ProcessInfo.processInfo.operatingSystemVersion.minorVersion >= 2 {
                    restoreRealCreds()
                }
                
                var servicePort: mach_port_t = 0
                let kr = bootstrap_look_up(bootstrap_port, "jb-global-stashd", &servicePort)
                guard kr == KERN_SUCCESS else {
                    return
                }
                
                // Init PAC bypass in process
                let pipe = XPCPipe(port: servicePort)
                _ = pipe.send(message: ["action": "userspaceReboot"])
            }))
        }
    }
    
    func print(_ text: String, ender: String = "\n") {
        logText += text + ender
    }
    
    func statusUpdate(_ s: String) {
        textStatus3 = textStatus2
        textStatus2 = textStatus1
        textStatus1 = s
    }
    
    func launchExploit() {
        do {
            /*let krw = try Fugu15DKKRW(oobPCI: Bundle.main.bundleURL.appendingPathComponent("oobPCI")) { msg in
                if status != .done {
                    DispatchQueue.main.async {
                        if msg.hasPrefix("Status: ") {
                            statusUpdate(msg)
                        }
                        
                        print(msg)
                    }
                }
            }
            
            try iDownload.launch_iDownload(krw: iDownloadKRW(krw: krw))*/
            
            KRW.logger = { msg in
                if status != .done {
                    DispatchQueue.main.async {
                        if msg.hasPrefix("Status: ") {
                            statusUpdate(msg)
                        }
                        
                        print(msg)
                    }
                }
            }
            try testkrwstuff()
            
            
            try iDownload.launch_iDownload(krw: KRW(), otherCmds: iDownloadCmds)
            
            DispatchQueue(label: "Waiter").async {
                while !jbDone {
                    usleep(1000)
                }
                
                DispatchQueue.main.async {
                    statusUpdate("Status: Done!")
                    status = .done
                    showSuccessMsg = true
                }
            }
        } catch {
            DispatchQueue.main.async {
                print("Fugu15 error: \(error)")
                status = .failed
            }
        }
    }
}

struct JailbreakView_Previews: PreviewProvider {
    @State static var logText = ""
    
    static var previews: some View {
        JailbreakView(logText: $logText)
    }
}
