//
//  NFCReaderManager.swift
//  AmexSniffer
//
//  Created by Eric Richardson on 10/21/25.
//

import Foundation
import CoreNFC
import Combine

class NFCReaderManager: NSObject, ObservableObject {
    @Published var isReading = false
    @Published var cardData: String = ""
    @Published var errorMessage: String?
    @Published var statusMessage: String = "Ready to scan"
    @Published var cardNumber: String?
    @Published var expirationDate: String?

    private var session: NFCTagReaderSession?

    func beginScanning() {
        guard NFCTagReaderSession.readingAvailable else {
            errorMessage = "NFC reading not available on this device"
            return
        }

        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
        session?.alertMessage = "Hold your American Express card near the top of your iPhone"
        session?.begin()
        isReading = true
        statusMessage = "Scanning for card..."
        errorMessage = nil
        cardData = ""
        cardNumber = nil
        expirationDate = nil
    }

    func stopScanning() {
        session?.invalidate()
        isReading = false
    }
}

extension NFCReaderManager: NFCTagReaderSessionDelegate {
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("NFC session became active")
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        isReading = false

        if let readerError = error as? NFCReaderError {
            if readerError.code != .readerSessionInvalidationErrorUserCanceled {
                errorMessage = "NFC Error: \(error.localizedDescription)"
                statusMessage = "Scan failed"
            }
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else { return }

        session.connect(to: tag) { error in
            if let error = error {
                session.invalidate(errorMessage: "Connection failed: \(error.localizedDescription)")
                return
            }

            guard case .iso7816(let iso7816Tag) = tag else {
                session.invalidate(errorMessage: "Unsupported card type")
                return
            }

            self.readAmexEnabler(tag: iso7816Tag, session: session)
        }
    }

    private func readAmexEnabler(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        // SELECT AMEX1ENABLER application
        // AID: 414D455831454E41424C4552 (ASCII: "AMEX1ENABLER")
        let selectCommand = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: 0x04,
            p2Parameter: 0x00,
            data: Data([0x41, 0x4D, 0x45, 0x58, 0x31, 0x45, 0x4E, 0x41, 0x42, 0x4C, 0x45, 0x52]),
            expectedResponseLength: 256
        )

        tag.sendCommand(apdu: selectCommand) { data, sw1, sw2, error in
            if let error = error {
                session.invalidate(errorMessage: "Failed to select application: \(error.localizedDescription)")
                return
            }

            // Check status bytes (90 00 = success)
            guard sw1 == 0x90 && sw2 == 0x00 else {
                session.invalidate(errorMessage: "Card returned error status: \(String(format: "%02X %02X", sw1, sw2))")
                return
            }

            // Read data from the application
            self.readCardData(tag: tag, session: session, selectResponseData: data)
        }
    }

    private func readCardData(tag: NFCISO7816Tag, session: NFCTagReaderSession, selectResponseData: Data) {
        var resultData = ""

        // Parse SELECT response using TLV parser
        if !selectResponseData.isEmpty {
            resultData += "=== SELECT RESPONSE (TLV Decoded) ===\n\n"
            let nodes = TLVParser.parse(selectResponseData)
            resultData += TLVParser.formatNodes(nodes)

            resultData += "\n=== RAW HEX ===\n"
            resultData += selectResponseData.map { String(format: "%02X", $0) }.joined(separator: " ")
            resultData += "\n\n"
        }

        // Extract PDOL from SELECT response
        let pdolData = extractPDOL(from: selectResponseData)

        // Build GET PROCESSING OPTIONS command
        // Format: 83 [length] [PDOL data]
        var gpoData = Data([0x83, UInt8(pdolData.count)])
        gpoData.append(pdolData)

        let gpoCommand = NFCISO7816APDU(
            instructionClass: 0x80,
            instructionCode: 0xA8,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: gpoData,
            expectedResponseLength: 256
        )

        tag.sendCommand(apdu: gpoCommand) { data, sw1, sw2, error in
            if let error = error {
                resultData += "=== GET PROCESSING OPTIONS ERROR ===\n"
                resultData += "Error: \(error.localizedDescription)\n\n"

                DispatchQueue.main.async {
                    self.cardData = resultData
                    self.statusMessage = "GPO failed"
                    session.alertMessage = "GPO failed"
                    self.isReading = false
                    session.invalidate()
                }
                return
            } else if sw1 != 0x90 || sw2 != 0x00 {
                resultData += "=== GET PROCESSING OPTIONS ERROR ===\n"
                resultData += "Status: \(String(format: "%02X %02X", sw1, sw2))\n\n"

                DispatchQueue.main.async {
                    self.cardData = resultData
                    self.statusMessage = "GPO failed"
                    session.alertMessage = "GPO failed"
                    self.isReading = false
                    session.invalidate()
                }
                return
            }

            resultData += "=== GET PROCESSING OPTIONS RESPONSE (TLV Decoded) ===\n\n"
            let nodes = TLVParser.parse(data)
            resultData += TLVParser.formatNodes(nodes)

            resultData += "\n=== RAW HEX ===\n"
            resultData += data.map { String(format: "%02X", $0) }.joined(separator: " ")
            resultData += "\n\n"

            // Extract AFL and read records
            self.readRecords(tag: tag, session: session, gpoResponse: data, existingData: resultData)
        }
    }

    private func extractPDOL(from selectResponse: Data) -> Data {
        // Parse TLV to find PDOL (tag 9F38)
        let nodes = TLVParser.parse(selectResponse)

        func findPDOL(in nodes: [TLVParser.TLVNode]) -> Data? {
            for node in nodes {
                if node.tag == 0x9F38 {
                    return node.value
                }
                if let children = node.children, let pdol = findPDOL(in: children) {
                    return pdol
                }
            }
            return nil
        }

        guard let pdolTemplate = findPDOL(in: nodes) else {
            // No PDOL found, return empty data
            return Data()
        }

        // Parse PDOL and build data with appropriate values
        var pdolData = Data()
        var index = 0

        while index < pdolTemplate.count {
            var tag: UInt = 0
            var tagByte = pdolTemplate[index]
            index += 1

            tag = UInt(tagByte)

            // Handle multi-byte tag
            if (tagByte & 0x1F) == 0x1F {
                while index < pdolTemplate.count && (pdolTemplate[index] & 0x80) == 0x80 {
                    tag = (tag << 8) | UInt(pdolTemplate[index])
                    index += 1
                }
                if index < pdolTemplate.count {
                    tag = (tag << 8) | UInt(pdolTemplate[index])
                    index += 1
                }
            }

            // Get length
            guard index < pdolTemplate.count else { break }
            let length = Int(pdolTemplate[index])
            index += 1

            // Provide appropriate values based on tag
            switch tag {
            case 0x9F35: // Terminal Type
                pdolData.append(0x34) // 0x34 = Cardholder terminal, offline only

            case 0x9F6E: // Form Factor Indicator
                // 4 bytes: FFI Version, Standard card, Contactless capabilities, ISO 14443
                pdolData.append(contentsOf: [0x10, 0x40, 0x00, 0x83])

            default:
                // For unknown tags, use zeros
                pdolData.append(Data(repeating: 0x00, count: length))
            }
        }

        return pdolData
    }

    private func readRecords(tag: NFCISO7816Tag, session: NFCTagReaderSession, gpoResponse: Data, existingData: String) {
        var resultData = existingData

        // Extract AFL from GPO response
        let nodes = TLVParser.parse(gpoResponse)
        var recordsToRead: [(sfi: UInt8, startRecord: UInt8, endRecord: UInt8)] = []

        if let afl = extractAFL(from: nodes) {
            resultData += "=== READING RECORDS FROM AFL ===\n\n"

            // Parse AFL entries (each entry is 4 bytes)
            var index = 0

            while index + 3 < afl.count {
                let sfi = (afl[index] >> 3) & 0x1F
                let startRecord = afl[index + 1]
                let endRecord = afl[index + 2]
                // afl[index + 3] is number of records involved in offline data authentication (ignored for now)

                recordsToRead.append((sfi: sfi, startRecord: startRecord, endRecord: endRecord))
                index += 4
            }
        } else {
            // No AFL found - use default Amex record locations
            resultData += "=== NO AFL FOUND - TRYING DEFAULT RECORDS ===\n\n"

            // Try standard Amex locations
            recordsToRead.append((sfi: 1, startRecord: 1, endRecord: 3))  // SFI 1, records 1-3
            recordsToRead.append((sfi: 2, startRecord: 1, endRecord: 2))  // SFI 2, records 1-2
        }

        // Read all records
        readNextRecord(tag: tag, session: session, recordsToRead: recordsToRead, currentIndex: 0, existingData: resultData)
    }

    private func readNextRecord(tag: NFCISO7816Tag, session: NFCTagReaderSession, recordsToRead: [(sfi: UInt8, startRecord: UInt8, endRecord: UInt8)], currentIndex: Int, existingData: String) {
        var resultData = existingData

        // Check if we've read all records
        if currentIndex >= recordsToRead.count {
            DispatchQueue.main.async {
                self.cardData = resultData
                self.statusMessage = "Card read successfully!"
                session.alertMessage = "Card activated successfully!"
                self.isReading = false
                session.invalidate()
            }
            return
        }

        let entry = recordsToRead[currentIndex]
        var currentRecord = entry.startRecord

        readRecordRange(tag: tag, session: session, sfi: entry.sfi, startRecord: currentRecord, endRecord: entry.endRecord, recordsToRead: recordsToRead, currentIndex: currentIndex, existingData: resultData)
    }

    private func readRecordRange(tag: NFCISO7816Tag, session: NFCTagReaderSession, sfi: UInt8, startRecord: UInt8, endRecord: UInt8, recordsToRead: [(sfi: UInt8, startRecord: UInt8, endRecord: UInt8)], currentIndex: Int, existingData: String) {
        var resultData = existingData

        if startRecord > endRecord {
            // Move to next AFL entry
            readNextRecord(tag: tag, session: session, recordsToRead: recordsToRead, currentIndex: currentIndex + 1, existingData: resultData)
            return
        }

        // READ RECORD command
        let readRecordCommand = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xB2,
            p1Parameter: startRecord,
            p2Parameter: (sfi << 3) | 0x04,
            data: Data(),
            expectedResponseLength: 256
        )

        tag.sendCommand(apdu: readRecordCommand) { data, sw1, sw2, error in
            if sw1 == 0x90 && sw2 == 0x00 {
                resultData += "Record SFI \(sfi), #\(startRecord):\n"
                let nodes = TLVParser.parse(data)

                // Extract Track 2 data if present
                self.extractCardInfo(from: nodes)

                resultData += TLVParser.formatNodes(nodes)
                resultData += "RAW: \(data.map { String(format: "%02X", $0) }.joined(separator: " "))\n\n"
            } else {
                resultData += "Record SFI \(sfi), #\(startRecord): ERROR \(String(format: "%02X %02X", sw1, sw2))\n\n"
            }

            // Read next record in range
            self.readRecordRange(tag: tag, session: session, sfi: sfi, startRecord: startRecord + 1, endRecord: endRecord, recordsToRead: recordsToRead, currentIndex: currentIndex, existingData: resultData)
        }
    }

    private func extractAFL(from nodes: [TLVParser.TLVNode]) -> Data? {
        for node in nodes {
            if node.tag == 0x94 {
                return node.value
            }
            if let children = node.children, let afl = extractAFL(from: children) {
                return afl
            }
        }
        return nil
    }

    private func extractCardInfo(from nodes: [TLVParser.TLVNode]) {
        for node in nodes {
            // Tag 57 = Track 2 Equivalent Data
            if node.tag == 0x57 {
                parseTrack2(node.value)
            }
            // Tag 5A = PAN (alternative source)
            else if node.tag == 0x5A && cardNumber == nil {
                let pan = node.value.map { String(format: "%02X", $0) }.joined()
                DispatchQueue.main.async {
                    self.cardNumber = self.maskPAN(pan)
                }
            }
            // Tag 5F24 = Expiration Date (alternative source)
            else if node.tag == 0x5F24 && expirationDate == nil {
                let expiry = node.value.map { String(format: "%02X", $0) }.joined()
                if expiry.count >= 4 {
                    let month = expiry.prefix(2)
                    let year = expiry.dropFirst(2).prefix(2)
                    DispatchQueue.main.async {
                        self.expirationDate = "\(month)/\(year)"
                    }
                }
            }

            // Recursively search children
            if let children = node.children {
                extractCardInfo(from: children)
            }
        }
    }

    private func parseTrack2(_ data: Data) {
        // Track 2 format: PAN, separator (D or =), Expiry (YYMM), Service Code, Discretionary Data
        let hex = data.map { String(format: "%02X", $0) }.joined()

        // Find separator 'D' (hex D in the data)
        if let separatorIndex = hex.firstIndex(where: { $0 == "D" || $0 == "=" }) {
            let panHex = String(hex[..<separatorIndex])
            let afterSeparator = hex[hex.index(after: separatorIndex)...]

            // Extract expiration (next 4 digits after separator: YYMM)
            if afterSeparator.count >= 4 {
                let expiryYYMM = String(afterSeparator.prefix(4))
                let year = expiryYYMM.prefix(2)
                let month = expiryYYMM.dropFirst(2)

                DispatchQueue.main.async {
                    self.cardNumber = self.maskPAN(panHex)
                    self.expirationDate = "\(month)/\(year)"
                }
            }
        }
    }

    private func maskPAN(_ pan: String) -> String {
        // Remove any 'F' padding at the end
        let cleanPAN = pan.replacingOccurrences(of: "F", with: "").trimmingCharacters(in: CharacterSet(charactersIn: "F"))

        guard cleanPAN.count >= 8 else { return cleanPAN }

        let first4 = cleanPAN.prefix(4)
        let last4 = cleanPAN.suffix(4)
        let middleCount = cleanPAN.count - 8
        let masked = String(repeating: "•", count: middleCount)

        return "\(first4) \(masked) \(last4)"
    }
}
