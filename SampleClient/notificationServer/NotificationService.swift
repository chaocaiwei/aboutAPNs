//
//  NotificationService.swift
//  notificationServer
//
//  Created by myself on 2019/7/17.
//  Copyright © 2019 modou. All rights reserved.
//

import UserNotifications

class NotificationService: UNNotificationServiceExtension {

    var contentHandler: ((UNNotificationContent) -> Void)?
    var bestAttemptContent: UNMutableNotificationContent?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)
        if let bestAttemptContent = bestAttemptContent {
            bestAttemptContent.title = "修改后的标题"
            bestAttemptContent.body = "修改后的body"
            bestAttemptContent.sound = UNNotificationSound(named:UNNotificationSoundName(rawValue: "101.mp3"))
            addLocationNotification()
            contentHandler(bestAttemptContent)
        }
    }
    
    func addLocationNotification(){
        UNUserNotificationCenter.current().requestAuthorization(options:[.sound]) { (isGrand, error) in
            if isGrand {
                let content = UNMutableNotificationContent()
                content.sound = UNNotificationSound.default
                content.body = "this is just a location body"
                content.sound = UNNotificationSound(named:UNNotificationSoundName(rawValue: "101.mp3"))
                let trige = UNTimeIntervalNotificationTrigger(timeInterval:1, repeats:false)
                let req = UNNotificationRequest(identifier:"\(arc4random())", content:content, trigger:trige)
                UNUserNotificationCenter.current().add(req) { (error) in
                    print(error?.localizedDescription)
                }
            }else{
                print(error?.localizedDescription)
            }
        }
        
        
    }
    
    override func serviceExtensionTimeWillExpire() {
        if let contentHandler = contentHandler, let bestAttemptContent =  bestAttemptContent {
            contentHandler(bestAttemptContent)
        }
    }

}
