//
//  ContentView.swift
//  AmexSniffer
//
//  Created by Eric Richardson on 10/21/25.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var nfcManager = NFCReaderManager()

    var body: some View {
        VStack(spacing: 30) {
            // Header
            VStack(spacing: 10) {
                Image(systemName: "creditcard.fill")
                    .font(.system(size: 80))
                    .foregroundColor(.blue)

                Text("Activate Your Card")
                    .font(.title)
                    .fontWeight(.bold)

                Text("Tap your American Express card to activate")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.top, 40)

//            Spacer()

            // Status indicator
            VStack(spacing: 15) {
                if nfcManager.isReading {
                    ProgressView()
                        .scaleEffect(1.5)
                        .padding()
                }

                Text(nfcManager.statusMessage)
                    .font(.headline)
                    .foregroundColor(nfcManager.errorMessage != nil ? .red : .primary)

                if let error = nfcManager.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
            }
            .frame(minHeight: 20)

            // Card information display
            if let cardNumber = nfcManager.cardNumber {
                VStack(spacing: 10) {
                    Text("Card Number")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Text(cardNumber)
                        .font(.system(.title2, design: .monospaced))
                        .fontWeight(.medium)

                    if let expiration = nfcManager.expirationDate {
                        Text("Expires \(expiration)")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()
                .background(Color.blue.opacity(0.1))
                .cornerRadius(12)
                .padding(.horizontal)
            }

            // Card data display
            if !nfcManager.cardData.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Card Data:")
                            .font(.headline)

                        Text(nfcManager.cardData)
                            .font(.system(.caption, design: .monospaced))
                            .padding()
                            .background(Color.gray.opacity(0.1))
                            .cornerRadius(8)
                    }
                    .padding()
                }
                .frame(maxHeight: 300)
            }

            Spacer()

            // Action button
            Button(action: {
                if nfcManager.isReading {
                    nfcManager.stopScanning()
                } else {
                    nfcManager.beginScanning()
                }
            }) {
                HStack {
                    Image(systemName: nfcManager.isReading ? "stop.circle.fill" : "wave.3.right.circle.fill")
                    Text(nfcManager.isReading ? "Cancel Scan" : "Tap to Activate")
                }
                .font(.headline)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding()
                .background(nfcManager.isReading ? Color.red : Color.blue)
                .cornerRadius(15)
            }
            .padding(.horizontal, 40)
            .padding(.bottom, 40)
        }
    }
}

#Preview {
    ContentView()
}
