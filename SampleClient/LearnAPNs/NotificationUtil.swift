//
//  NotificationUtil.swift
//  LearnAPNs
//
//  Created by myself on 2019/7/10.
//  Copyright © 2019 modou. All rights reserved.
//

import UIKit
import UserNotifications


final class NotificationUtil: NSObject {
    
    static let shared = NotificationUtil()
    private override init() {
        super.init()
    }
    
    var deviceToken : String?
    var deviceTokenBlocks = [((String?)->())]()
    
    func startServer(){
        UNUserNotificationCenter.current().delegate = self
        authAndGetDeviceToken()
        print("startServer")
        
    }
    
    func authAndGetDeviceToken(){
        self.auth { (isGrand) in
            if isGrand {
                self.getAndUploadDeviceToken()
            }
        }
    }
    
    private func getAndUploadDeviceToken(){
        getDeviceToken { (token) in
            if let token = token {
                // upload deviceToken here
                
            }
        }
    }
    
    func getDeviceToken(completion:@escaping (String?)->()){
        if let token = self.deviceToken {
            completion(token)
        }else{
            self.deviceTokenBlocks.append(completion)
            (UIApplication.shared.delegate as? AppDelegate)?.getDeviceToken(completion: { (token) in
                if let token = token {
                    self.deviceToken = token
                    print("deviceToken \(token)")
                }
                for block in self.deviceTokenBlocks {
                    block(token)
                }
                self.deviceTokenBlocks.removeAll()
            })
        }
    }
    
    func auth(completion:@escaping (_ isGrand:Bool)->()){
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert,.badge,.sound]) { (isGrand, error) in
            DispatchQueue.main.async {
                if isGrand {
                    completion(true)
                }else{
                    print("用户拒绝了推送权限")
                    completion(false)
                }
            }
        }
    }
    
    func showAlrtToSetting(){
   
        let alert = UIAlertController(title: "温馨提示", message: "您还没有允许推送权限。请在设置中开启相关权限。", preferredStyle:.alert)
        let cancelAction = UIAlertAction(title:"取消" , style:.cancel, handler: nil)
        let setAction = UIAlertAction(title:"去设置" , style:.default, handler: { (_) in
            let url = URL(string: UIApplication.openSettingsURLString)
            UIApplication.shared.open(url!, options:[:], completionHandler:nil)
        })
        alert.addAction(cancelAction)
        alert.addAction(setAction)
        UIApplication.shared.delegate?.window??.rootViewController?.present(alert, animated: true, completion:nil)
    }
    
    func addLocationNotification(){
        let content = UNMutableNotificationContent()
        content.sound = UNNotificationSound.default
        content.body = "this is just a location body"
        let trige = UNTimeIntervalNotificationTrigger(timeInterval:1, repeats:false)
        let req = UNNotificationRequest(identifier:"\(arc4random())", content:content, trigger:trige)
        UNUserNotificationCenter.current().add(req) { (error) in
            
        }
    }
    
}


extension NotificationUtil: UNUserNotificationCenterDelegate {
    
    // 前台收到推送
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        print("receive notification \(notification.request.content.userInfo)")
        completionHandler([.sound,.alert])
    }
    
    // 点击推送进入
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        let userInfo = response.notification.request.content.userInfo
        handleUserResponse(userInfo:userInfo)
        completionHandler()
    }
    
    func handleUserResponse(userInfo:[AnyHashable:Any]){
        
    }
    
    
}
