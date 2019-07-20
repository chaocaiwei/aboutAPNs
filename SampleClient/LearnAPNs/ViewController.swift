//
//  ViewController.swift
//  LearnAPNs
//
//  Created by myself on 2019/7/10.
//  Copyright © 2019 modou. All rights reserved.
//

import UIKit
import SwiftJWT

var targetToken   = "bafed45d10438230c2d926a4d61f036828eee6b52795d57770e80a8a7c5cdfb8"
let bundleId = Bundle.main.infoDictionary!["CFBundleIdentifier"] as! String

class ViewController: UIViewController {

    @IBOutlet weak var titleTextfield: UITextField!
    @IBOutlet weak var bodyTextfield: UITextField!
    @IBOutlet weak var mutableCotentSwitch: UISwitch!
    @IBOutlet weak var developSwitch: UISwitch!
    @IBOutlet weak var lauchLabel: UILabel!
    @IBOutlet weak var pushLable: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        NotificationUtil.shared.startServer()
        NotificationUtil.shared.getDeviceToken { (token) in
            if let token = token {
                targetToken = token
            }
        }
        let del = UIApplication.shared.delegate as! AppDelegate
        self.lauchLabel.text = "lauch=\(del.launchOptions)"
        self.pushLable.text = "push=\(del.responForPush)"
    }
    
    var playload : [String:Any] {
        var aps = [String:Any]()
        var alert = [String:Any]()
        alert["title"] =  self.titleTextfield.text!
        alert["body"]  =  self.bodyTextfield.text!
        aps["alert"] = alert
        aps["sound"] = "default"
        if self.mutableCotentSwitch.isOn {
            aps["mutable-content"] = 1
        }
        return ["aps":aps]
    }
    
    
    @IBAction func developCerPush(_ sender: Any) {
        APNsPusher.devCerPusher.push(token:targetToken, bundleId:bundleId, payload:playload, isSanBox:self.developSwitch.isOn, completion: { (response) in
            switch response {
            case .success:
                print("推送成功")
            case .fail(code:let code, msg:let msg):
                print("推送失败 code=\(code) msg=\(msg)")
            }
        })
    }
    
    @IBAction func productCerPush(_ sender: Any) {
        APNsPusher.cerPusher.push(token:targetToken, bundleId:bundleId, payload:playload, isSanBox:self.developSwitch.isOn, completion: { (response) in
            switch response {
            case .success:
                print("推送成功")
            case .fail(code:let code, msg:let msg):
                print("推送失败 code=\(code) msg=\(msg)")
            }
        })
    }
    
    @IBAction func authKeyPush(_ sender: Any) {
        APNsPusher.tokenPusher.push(token:targetToken, bundleId:bundleId, payload:playload, isSanBox:self.developSwitch.isOn, completion: { (response) in
            switch response {
            case .success:
                print("推送成功")
            case .fail(code:let code, msg:let msg):
                print("推送失败 code=\(code) msg=\(msg)")
            }
        })
    }
    
    @IBAction func stopPush(_ sender: Any) {
        UIApplication.shared.unregisterForRemoteNotifications()
    }
    
    
    @IBAction func reGetDeviceToken(_ sender: Any) {
        NotificationUtil.shared.getDeviceToken { (token) in
            print(token ?? "empty token")
        }
    }
    
    
}

