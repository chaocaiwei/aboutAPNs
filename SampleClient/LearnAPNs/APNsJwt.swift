//
//  APNsJwt.swift
//  LearnAPNs
//
//  Created by myself on 2019/7/14.
//  Copyright © 2019 modou. All rights reserved.
//

import UIKit
import CommonCrypto

class APNsJwt {
    
    let p8Path : String
    let keyId  : String
    let teamId : String
    
    
    var tokenValidity :TimeInterval = 50 * 60 // token有效期
    private var tempToken : String?
    var tokenDate : Date?
    
    init(p8Path : String,keyId: String,teamId : String) {
        self.p8Path = p8Path
        self.keyId  = keyId
        self.teamId = teamId
    }
    
    var token : String? {
        if let temToken = self.tempToken,
           let date = self.tokenDate,
            Date().timeIntervalSince1970 - date.timeIntervalSince1970 < tokenValidity {
            return temToken
        }
        self.refreshToken(isForce:false)
        return self.tempToken
    }
    
    var authorization : String? {
        guard let token = self.token else {
            return nil
        }
        return "bearer \(token)"
    }
    private let kJwtTokenKey = "jwtToken"
    private let kJwtTokenDateKey = "jwtTokenDate"
    func refreshToken(isForce:Bool=true){
        if let token = UserDefaults.standard.object(forKey:kJwtTokenKey) as? String,
            let date = UserDefaults.standard.object(forKey:kJwtTokenDateKey) as? Double
            ,!isForce {
            self.tokenDate = Date(timeIntervalSince1970:date)
            self.tempToken = token
        }
        self.tokenDate = Date()
        self.tempToken = self.generateToken(date:self.tokenDate!)
        UserDefaults.standard.set(self.tokenDate?.timeIntervalSince1970, forKey:kJwtTokenDateKey)
        UserDefaults.standard.set(self.tempToken, forKey:kJwtTokenKey)
        UserDefaults.standard.synchronize()
    }
    
    func generateToken(date:Date)->String?{
        
        // head部分
        var head = [String:Any]()
        head["kid"] = kKeyId
        head["alg"] = "ES256"
        let headString = APNsJwt.base64UrlString(json:head)
        
        // claim部分
        var claim = [String:Any]()
        claim["iss"] = kTeamId
        claim["iat"] = date.timeIntervalSince1970
        let claimString = APNsJwt.base64UrlString(json:claim)
        
        // 生成签名前的数据
        let jwtString = headString + "." + claimString
        let data = jwtString.data(using:.utf8)!
        
        // 从.p8获取私钥
        let key : SecKey? = APNsJwt.getPrivKey(p8Path:self.p8Path)
        
        // 用私钥及ECDSA算法进行签名
        let signData =  p256Sign(privKey:key!, data:data)
        // 签名后的数据baseurl编码
        guard let signString = signData?.base64URLEncoded else { return nil }
        
        // 拼接得到最终的token
        return headString + "." + claimString + "." + signString
    }
    
    static func base64UrlString(json:Any)->String{
        let data = try! JSONSerialization.data(withJSONObject:json, options:.sortedKeys)
        let base64Encoded = data.base64EncodedString()
        return base64Encoded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    static func getPrivKey(p8Path:String)->SecKey?{
        let keyData  = try! Data(contentsOf: URL(fileURLWithPath:p8Path))
        guard let keyString = String(data: keyData, encoding: .utf8) else {
            return nil
        }
        let pstr = keyString.components(separatedBy: "\n").filter({!$0.contains("BEGIN") && !$0.contains("END")}).joined()
        let pdata = Data(base64Encoded:pstr,options: .ignoreUnknownCharacters)!
        let asn = try! ASN1DERDecoder.decode(data:pdata)
        let finalSubs = asn.first?.sub?.last?.sub?.last?.sub
        let privData = finalSubs?[1].rawValue
        let pubData  = finalSubs?[3].sub?.first?.rawValue?.drop(while:{$0 == 0x00})
        let allData  = pubData! + privData!
        var error: Unmanaged<CFError>? = nil
        let secKey = SecKeyCreateWithData(allData as CFData,
                                          [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                           kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary,
                                          &error)
        return secKey
    }
    
    private func p256Sign(privKey:SecKey,data:Data) ->Data?{
        
        // SHA256哈希
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_SHA256_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_SHA256(&srcBuf,CC_LONG(data.count),outBuf)
        let digest = Data(UnsafeBufferPointer(start:outBuf, count:outLen))
        
        // 创建签名
        var error: Unmanaged<CFError>? = nil
        guard let signRef = SecKeyCreateSignature(privKey,
                                                  .ecdsaSignatureDigestX962SHA256,
                                                  digest as CFData,
                                                  &error) as Data?
        else {
            print("CreateSignature error \(error?.takeRetainedValue().localizedDescription ?? "")")
            return nil
        }
        
        // ASN1解码 获取其中的r和s
        guard let asn1 = try? ASN1DERDecoder.decode(data:signRef),
        let rData = asn1.first?.sub?[0].rawValue,
        let sData = asn1.first?.sub?[1].rawValue else  { return nil }
        
        return rData + sData
    }
    
}
