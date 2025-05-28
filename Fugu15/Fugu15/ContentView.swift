//
//  ContentView.swift
//  Fugu15
//
//  Created by Linus Henze.
//

import SwiftUI

#if os(iOS)
import UIKit
#else
import AppKit
#endif

//import Fugu15KernelExploit

struct ContentView: View {
    @State var logText = ""
    @State private var showingRemoveFrame = RemoveFuguInstall.shouldShow()
    
    var body: some View {
        NavigationView {
            VStack {
                Divider()
                
                TabView {
                    JailbreakView(logText: $logText)
                        .tabItem {
                            Label("Jailbreak", systemImage: "lock.open")
                        }
                    
                    LogView(logText: $logText)
                        .tabItem {
                            Label("Log", systemImage: "keyboard.macwindow")
                        }
                    
                    AboutView()
                        .tabItem {
                            Label("About", systemImage: "questionmark.app.dashed")
                        }
                    SettingsView()
                        .tabItem {
                            Label("Settings", systemImage: "gear")
                        }
                }
                    .sheet(isPresented: $showingRemoveFrame) {
                        RemoveFuguInstall(isPresented: $showingRemoveFrame)
                    }
                    .navigationTitle("Fugu15")
                    .navigationBarTitleDisplayMode(.inline)
            }
        }.navigationViewStyle(.stack)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
