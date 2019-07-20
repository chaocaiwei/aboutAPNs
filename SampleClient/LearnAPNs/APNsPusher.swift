//
//  APNsUtil.swift
//  LearnAPNs
//
//  Created by myself on 2019/7/10.
//  Copyright © 2019 modou. All rights reserved.
//

import UIKit

let kTeamId   = "JFW6NYCCQB"
let kKeyId    = "MTB28KC884"

final class APNsPusher : NSObject {
    
    enum Response {
        case success
        case fail(code:Int,msg:String)
    }
    
    enum  CertificateType {
        case develop
        case product
    }
    
    typealias APNsCommonResponse = (Response)->()
    
    lazy var session : URLSession! = {
        let session = URLSession(configuration: URLSessionConfiguration.default, delegate:self, delegateQueue:OperationQueue.main)
        return session
    }()
    
    var certificate : APNsCerticate?
    var jwt : APNsJwt?
    
    static let tokenPusher   = APNsPusher(p8Path:"AuthKey_MTB28KC884.p8", keyId:kKeyId, teamId:kTeamId)
    static let cerPusher     = APNsPusher(p12Path:"learn.p12", pwd:"123456")!
    static let devCerPusher  = APNsPusher(p12Path:"develop.p12", pwd:"123456")!
    
    init?(p12Path:String,pwd:String?=nil) {
        let path = Bundle.main.path(forResource:p12Path, ofType:nil) ?? p12Path
        guard let cer = APNsCerticate(p12Path:path, pwd:pwd) else {
            return nil
        }
        self.certificate = cer
    }
    
    init(p8Path:String,keyId:String,teamId:String){
        let path = Bundle.main.path(forResource:p8Path, ofType:nil) ?? p8Path
        self.jwt  = APNsJwt(p8Path:path, keyId:keyId, teamId:teamId)
    }
    
    func push(token:String,bundleId:String,payload:[String:Any],isSanBox:Bool,completion:@escaping APNsCommonResponse){
        var url : String
        if isSanBox {
            url = "https://api.sandbox.push.apple.com/3/device/\(token)"
        } else {
            url = "https://api.push.apple.com/3/device/\(token)"
        }
        var req = URLRequest(url: URL(string:url)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(bundleId, forHTTPHeaderField:"apns-topic")
        if let auth = self.jwt?.authorization {
            req.setValue(auth, forHTTPHeaderField:"Authorization")
        }
        req.httpBody = try? JSONSerialization.data(withJSONObject:payload, options:.prettyPrinted)
        let task = self.session.dataTask(with:req) { (data,response,error) in
            let statusCode = (response as? HTTPURLResponse)?.statusCode
            var reason : String? = nil
            if let data = data,
                let dict = try? JSONSerialization.jsonObject(with:data, options:.allowFragments) as? [String:Any]{
                reason = dict["reason"] as? String
            }
            if statusCode == 200 {
                completion(.success)
            }else{
                completion(.fail(code:statusCode ?? 400, msg:reason ?? error!.localizedDescription))
            }
        }
        task.resume()
    }
}

extension APNsPusher : URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let space = challenge.protectionSpace
        switch space.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            if let trust = space.serverTrust {
                let credential = URLCredential(trust:trust)
                completionHandler(.useCredential,credential)
            }else{
                completionHandler(.rejectProtectionSpace,nil)
            }
        case NSURLAuthenticationMethodClientCertificate:
            if let credential = self.certificate?.credential {
                completionHandler(.useCredential,credential)
            }else{
                completionHandler(.performDefaultHandling,nil)
            }
        default:
            completionHandler(.performDefaultHandling,nil)
        }
        print("didReceive challenge \(space.authenticationMethod) \(space.host) \(space.port) \(space.serverTrust.debugDescription)")
    }
}
