//
//  AppDelegate.swift
//  LearnAPNs
//
//  Created by myself on 2019/7/10.
//  Copyright © 2019 modou. All rights reserved.
//

import UIKit


@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    var devicceTokenClosure : ((String?)->())?
    var launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    var responForPush : [String:Any]?
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        if let removePushUserInfo = launchOptions?[UIApplication.LaunchOptionsKey.remoteNotification]{
            NotificationUtil.shared.handleUserResponse(userInfo:removePushUserInfo as! [AnyHashable:Any])
        }
        return true
    }
    
    func getDeviceToken(completion:@escaping (String?)->()){
        UIApplication.shared.registerForRemoteNotifications()
        self.devicceTokenClosure = completion
    }
    
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        UMessage.registerDeviceToken(deviceToken);
        let deviceTokenString = deviceToken.reduce("",{$0 + String(format:"%02x",$1)})
        self.devicceTokenClosure?(deviceTokenString)
    }
    
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        self.devicceTokenClosure?(nil)
    }
    
    func applicationWillResignActive(_ application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
    }
    
    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable : Any]) {
        if application.applicationState == .inactive {
            print("点击推送唤起app userInfo=\(userInfo)")
        }else{
            print("前台收到推送 userInfo=\(userInfo)")
        }
    }
    
    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable : Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void){
        if application.applicationState == .inactive {
            self.responForPush = (userInfo as! [String:Any])
            print("点击推送唤起app userInfo=\(userInfo) time=\(Date())")
        }else{
            print("前台收到推送 userInfo=\(userInfo) time=\(Date())")
        }
        completionHandler(.newData)
    }
    
    
    

}

