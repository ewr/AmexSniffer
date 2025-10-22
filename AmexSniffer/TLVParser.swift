//
//  TLVParser.swift
//  AmexSniffer
//
//  Created by Eric Richardson on 10/21/25.
//

import Foundation

struct TLVParser {
    // Common EMV tag names
    static let tagNames: [UInt: String] = [
        0x4F: "Application Identifier (AID)",
        0x50: "Application Label",
        0x57: "Track 2 Equivalent Data",
        0x5A: "Application Primary Account Number (PAN)",
        0x5F20: "Cardholder Name",
        0x5F24: "Application Expiration Date",
        0x5F25: "Application Effective Date",
        0x5F28: "Issuer Country Code",
        0x5F2D: "Language Preference",
        0x5F30: "Service Code",
        0x5F34: "Application PAN Sequence Number",
        0x61: "Application Template",
        0x6F: "File Control Information (FCI) Template",
        0x70: "Data Template",
        0x77: "Response Message Template Format 2",
        0x80: "Response Message Template Format 1",
        0x82: "Application Interchange Profile",
        0x83: "Command Template",
        0x84: "Dedicated File (DF) Name",
        0x86: "Issuer Script Command",
        0x87: "Application Priority Indicator",
        0x88: "Short File Identifier (SFI)",
        0x89: "Authorization Code",
        0x8A: "Authorization Response Code",
        0x8C: "Card Risk Management Data Object List 1 (CDOL1)",
        0x8D: "Card Risk Management Data Object List 2 (CDOL2)",
        0x8E: "Cardholder Verification Method (CVM) List",
        0x8F: "Certification Authority Public Key Index",
        0x90: "Issuer Public Key Certificate",
        0x91: "Issuer Authentication Data",
        0x92: "Issuer Public Key Remainder",
        0x93: "Signed Static Application Data",
        0x94: "Application File Locator (AFL)",
        0x95: "Terminal Verification Results",
        0x97: "Transaction Certificate Data Object List (TDOL)",
        0x98: "Transaction Certificate (TC) Hash Value",
        0x99: "Transaction Personal Identification Number (PIN) Data",
        0x9A: "Transaction Date",
        0x9B: "Transaction Status Information",
        0x9C: "Transaction Type",
        0x9D: "Directory Definition File (DDF) Name",
        0xA5: "File Control Information (FCI) Proprietary Template",
        0xBF0C: "FCI Issuer Discretionary Data",
        0x9F01: "Acquirer Identifier",
        0x9F02: "Amount, Authorised (Numeric)",
        0x9F03: "Amount, Other (Numeric)",
        0x9F06: "Application Identifier (AID) - terminal",
        0x9F07: "Application Usage Control",
        0x9F08: "Application Version Number",
        0x9F09: "Application Version Number",
        0x9F0D: "Issuer Action Code - Default",
        0x9F0E: "Issuer Action Code - Denial",
        0x9F0F: "Issuer Action Code - Online",
        0x9F10: "Issuer Application Data",
        0x9F11: "Issuer Code Table Index",
        0x9F12: "Application Preferred Name",
        0x9F13: "Last Online Application Transaction Counter (ATC) Register",
        0x9F17: "Personal Identification Number (PIN) Try Counter",
        0x9F1A: "Terminal Country Code",
        0x9F1F: "Track 1 Discretionary Data",
        0x9F26: "Application Cryptogram",
        0x9F27: "Cryptogram Information Data",
        0x9F32: "Issuer Public Key Exponent",
        0x9F33: "Terminal Capabilities",
        0x9F34: "Cardholder Verification Method (CVM) Results",
        0x9F35: "Terminal Type",
        0x9F36: "Application Transaction Counter (ATC)",
        0x9F37: "Unpredictable Number",
        0x9F38: "Processing Options Data Object List (PDOL)",
        0x9F40: "Additional Terminal Capabilities",
        0x9F42: "Application Currency Code",
        0x9F44: "Application Currency Exponent",
        0x9F46: "ICC Public Key Certificate",
        0x9F47: "ICC Public Key Exponent",
        0x9F48: "ICC Public Key Remainder",
        0x9F49: "Dynamic Data Authentication Data Object List (DDOL)",
        0x9F4A: "Static Data Authentication Tag List",
        0x9F4B: "Signed Dynamic Application Data",
        0x9F6E: "Form Factor Indicator (FFI)"
    ]

    struct TLVNode {
        let tag: UInt
        let length: Int
        let value: Data
        let children: [TLVNode]?
        let isConstructed: Bool

        var tagName: String {
            tagNames[tag] ?? String(format: "Unknown Tag %02X", tag)
        }
    }

    static func parse(_ data: Data) -> [TLVNode] {
        var nodes: [TLVNode] = []
        var index = 0

        while index < data.count {
            guard let node = parseNode(data, index: &index) else { break }
            nodes.append(node)
        }

        return nodes
    }

    private static func parseNode(_ data: Data, index: inout Int) -> TLVNode? {
        guard index < data.count else { return nil }

        // Parse tag
        var tagValue: UInt = 0
        var tagByte = data[index]
        index += 1

        tagValue = UInt(tagByte)

        // Multi-byte tag (if bits 1-5 are all set)
        if (tagByte & 0x1F) == 0x1F {
            guard index < data.count else { return nil }
            tagByte = data[index]
            index += 1
            tagValue = (tagValue << 8) | UInt(tagByte)

            // Continue reading tag bytes if needed
            while (tagByte & 0x80) == 0x80 {
                guard index < data.count else { return nil }
                tagByte = data[index]
                index += 1
                tagValue = (tagValue << 8) | UInt(tagByte)
            }
        }

        let isConstructed = (data[index - (tagValue > 0xFF ? 2 : 1)] & 0x20) == 0x20

        // Parse length
        guard index < data.count else { return nil }
        var lengthByte = data[index]
        index += 1

        var length: Int
        if (lengthByte & 0x80) == 0 {
            // Short form
            length = Int(lengthByte)
        } else {
            // Long form
            let numLengthBytes = Int(lengthByte & 0x7F)
            guard index + numLengthBytes <= data.count else { return nil }

            length = 0
            for _ in 0..<numLengthBytes {
                length = (length << 8) | Int(data[index])
                index += 1
            }
        }

        // Parse value
        guard index + length <= data.count else { return nil }
        let value = data[index..<index + length]
        index += length

        // Parse children if constructed
        var children: [TLVNode]? = nil
        if isConstructed {
            var childIndex = 0
            var childNodes: [TLVNode] = []
            let childData = Data(value)

            while childIndex < childData.count {
                if let child = parseNode(childData, index: &childIndex) {
                    childNodes.append(child)
                }
            }

            if !childNodes.isEmpty {
                children = childNodes
            }
        }

        return TLVNode(
            tag: tagValue,
            length: length,
            value: Data(value),
            children: children,
            isConstructed: isConstructed
        )
    }

    static func formatNodes(_ nodes: [TLVNode], indent: Int = 0) -> String {
        var result = ""
        let indentStr = String(repeating: "  ", count: indent)

        for node in nodes {
            let tagStr = String(format: "%02X", node.tag)
            result += "\(indentStr)[\(tagStr)] \(node.tagName)\n"
            result += "\(indentStr)  Length: \(node.length)\n"

            if let children = node.children {
                result += formatNodes(children, indent: indent + 1)
            } else {
                // Format value
                let hexStr = node.value.map { String(format: "%02X", $0) }.joined(separator: " ")
                result += "\(indentStr)  Hex: \(hexStr)\n"

                // Try to decode as ASCII if printable
                if let asciiStr = String(data: node.value, encoding: .ascii),
                   asciiStr.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0.isWhitespace || $0.isPunctuation) }) {
                    result += "\(indentStr)  ASCII: \(asciiStr)\n"
                }

                // Special decodings for certain tags
                if node.tag == 0x5F24 && node.length == 3 {
                    // Application Expiration Date (YYMMDD)
                    let hex = node.value.map { String(format: "%02X", $0) }.joined()
                    result += "\(indentStr)  Date: \(hex.prefix(2))/\(hex.dropFirst(2).prefix(2))/20\(hex.dropFirst(4))\n"
                } else if node.tag == 0x5A {
                    // PAN
                    let hex = node.value.map { String(format: "%02X", $0) }.joined()
                    result += "\(indentStr)  PAN: \(hex)\n"
                } else if node.tag == 0x9F38 {
                    // PDOL - Processing Options Data Object List
                    result += "\(indentStr)  PDOL Decoded:\n"
                    result += parseDOL(node.value, indent: indent + 2)
                } else if node.tag == 0x8C {
                    // CDOL1 - Card Risk Management Data Object List 1
                    result += "\(indentStr)  CDOL1 Decoded:\n"
                    result += parseDOL(node.value, indent: indent + 2)
                } else if node.tag == 0x8D {
                    // CDOL2 - Card Risk Management Data Object List 2
                    result += "\(indentStr)  CDOL2 Decoded:\n"
                    result += parseDOL(node.value, indent: indent + 2)
                }
            }
            result += "\n"
        }

        return result
    }

    static func parseDOL(_ data: Data, indent: Int = 0) -> String {
        var result = ""
        let indentStr = String(repeating: "  ", count: indent)
        var index = 0

        while index < data.count {
            // Parse tag
            var tag: UInt = 0
            var tagByte = data[index]
            index += 1

            tag = UInt(tagByte)

            // Multi-byte tag (if bits 1-5 are all set)
            if (tagByte & 0x1F) == 0x1F {
                guard index < data.count else { break }
                tagByte = data[index]
                index += 1
                tag = (tag << 8) | UInt(tagByte)

                // Continue reading tag bytes if needed
                while (tagByte & 0x80) == 0x80 {
                    guard index < data.count else { break }
                    tagByte = data[index]
                    index += 1
                    tag = (tag << 8) | UInt(tagByte)
                }
            }

            // Parse length
            guard index < data.count else { break }
            let length = Int(data[index])
            index += 1

            let tagName = tagNames[tag] ?? String(format: "Unknown Tag %02X", tag)
            let tagStr = tag > 0xFF ? String(format: "%04X", tag) : String(format: "%02X", tag)

            result += "\(indentStr)Tag [\(tagStr)] \(tagName) - Length: \(length) byte\(length == 1 ? "" : "s")\n"
        }

        return result
    }
}
