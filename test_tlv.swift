import Foundation

// Paste TLVParser code here for testing
let hexString = "6F 27 84 0C 41 4D 45 58 31 45 4E 41 42 4C 45 52 A5 17 50 04 54 41 50 4E 9F 38 06 9F 35 01 9F 6E 04 87 01 03 5F 2D 02 65 6E"

let bytes = hexString.split(separator: " ").compactMap { UInt8($0, radix: 16) }
let data = Data(bytes)

let nodes = TLVParser.parse(data)
print(TLVParser.formatNodes(nodes))
