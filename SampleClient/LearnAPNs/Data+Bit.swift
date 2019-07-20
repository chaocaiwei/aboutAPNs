//
//  Data+Bit.swift
//  SampleCrypto
//
//  Created by myself on 2019/7/2.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

import UIKit

extension UInt8 {
    var hexString : String {
        let str = String(format:"0x%02x",self)
        return str
    }
}

extension Data {
    var bytes : [UInt8] {
        return [UInt8](self)
    }
    var hexString : String {
        var str = ""
        for byte in self.bytes {
            str += byte.hexString
            str += " "
        }
        return str
    }
    
     var description: String {
        return "\(self.hexString)"
    }
    
}

extension Data {
    // Encode `self` with URL escaping considered.
    var base64URLEncoded: String {
        let base64Encoded = base64EncodedString()
        return base64Encoded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension String {
    // Returns the data of `self` (which is a base64 string), with URL related characters decoded.
    var base64URLDecoded: Data? {
        let paddingLength = 4 - count % 4
        // Filling = for %4 padding.
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        let base64EncodedString = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        return Data(base64Encoded: base64EncodedString)
    }
}
