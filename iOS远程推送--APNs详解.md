# iOS远程推送--APNs详解

iOS远程推送，远远不是配置两个证书，集成个SDK那么简单。

本文会从实践出发，结合苹果的官方文档，带你全面的了解苹果APNs服务。除了基础原理和集成方法外，还将详细介绍了APNs服务接口的调用方式，以及各个推送SDK的基本原理。

## 概述

现在市面上大多数app，都有根据某种条件，服务端主动向用户推送消息的需求。面对这个需求，首先想到的是长链接，如果服务端集成了HTTP/2的话，还可以用Server Push。安卓在处理类似业务时就是这么干的，美其名曰透传消息。

但是我们期望的是，无论是app退后台还是被结束进程，都可以正常收到消息。这就需要用到系统集的推送。而在iOS平台或者说苹果全系统平台，就是伟大的Apple Push Notification service 简称APNs。

## 让客户端具备接收推送能力
### 开启app的推送通知能力
在工程的Capability标签下，打开 Push Notifications 开关

![Capability](capability.png)

我们可以看到，它帮我们做了两个事情。

其一是添加了推送通知的特性，加入到了你的App ID(bundleId)下。和你在开发者账户管理 [Edit your App ID Configuration](https://developer.apple.com/account/resources/identifiers/bundleId)下进行配置是一样的。

![id.tiff](id.tiff)

另外一件事，是生成了相应的.entitlements文件

![enti](enti.png)

### 获取推送权限

获取推送权限的代码很简单：

```swift
UNUserNotificationCenter.current().requestAuthorization(options: [.alert,.badge,.sound]) { (isGrand, error) in
	DispatchQueue.main.async {
	    if isGrand {
	        // 用户允许了推送权限
	    }else{
	        // 用户拒绝了推送权限
	    }
	}
}
```
推送有若干种展现形式，最常用的是横幅(alert)、声音(sound)、标记(badge)。可以在`options`参数中指定。

如果你需要适配iOS10以前的设备，可以用：

```swift
UIApplication.shared.registerUserNotificationSettings(.init(types:[.alert,.badge,.sound], categories:nil))
```

它会在下列方法中回调：

```swift
func application(_ application: UIApplication, didRegister notificationSettings: UIUserNotificationSettings) {
      if notificationSettings.types.isEmpty {
          print("用户拒绝了推送权限")
      }else{
          print("用户允许了推送权限")
      }
  }
```

值得注意的是：

- 获取权限是不用联网的，失败基本上只可能是用户点击了拒绝，或者在设置里关闭了推送权限
- 没必要先获取当前权限状态再申请权限。它内部会根据当前的权限状态，弹出授权提示，或者直接返回成功/失败。
- 回掉函数都是在子线程执行的，必要时需要切换回主线程

### 获取DeviceToken

APNs要向设备推送消息，必须知道设备的ip地址。而移动设备的网络是不停在变化的。苹果设备在每次连接网络的时候，都会和苹果服务器建立长链接，苹果会记录这个连接会话(session)。只要为设备建立一个唯一的唯一标识，与session建立一个关联，就可以实现推送到指定的设备。而这个唯一标识就是DeviceToken。

我们需要通过Apple的长链接，跟APNs进行会话，来生成DeviceToken，并与App的BundleId进行关联。

获取deviceToken很简单，直接调用下列方法

```
UIApplication.shared.registerForRemoteNotifications()
```

然后，deviceToken会在UIApplication的下列代理方法中返回

```
func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let deviceTokenString = deviceToken.reduce("",{$0 + String(format:"%02x",$1)})
}
```

如果获取失败，会触发下列方法

```
func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) 
{}
```

真机基本上都不会触发这个方法，即便是没有网的情况。如果是模拟器会返回错误remote notifications are not supported in the simulator。大多数情况，并不用处理失败的情况。

值得注意的是：

- 获取deviceToken跟app是否申请了推送权限无关，即使是禁用了远程推送，也可以正确获取deviceToken。如果没有申请权限，会以静默推送形式呈现。

> If you do not request and receive authorization for your app's interactions, the system delivers all remote notifications to your app silently.

- 第一次获取deviceToken时必须联网。如果在获取时没有网络，在重新连接网络后会第一时间返回deviceToken。
- 永远不要缓存DeviceToken。每次都调用上面获取方法就可以了。如果已经生成了有效的DeviceToken，系统或有缓存，在 重新安装App、重装系统、或者从备份还原系统时，会重新生成DeviceToken并更新缓存。
- debug环境下是向开发环境的APNs服务器申请DeviceToken，而release环境是向生产环境的APNs服务器申请的。如果环境不匹配，则会出现`Bad deviceToken`错误。
- deviceToken与bundleId存在着关联。如果deviceToken与证书中的bundleId不匹配，会返回`DeviceTokenNotForTopic`

### 上传DeviceToken

我们需要上传DeviceToken给服务器，并且与我们的用户Id相关联。在一些SDK中，在上传deviceToken时，往往还会绑定若干个便签，或者分组。

### 处理前台推送

在前台收到推送时，会触发UNUserNotificationCenterDelegate的下列方法：

```swift
func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    completionHandler([.sound,.alert])
}
```

值得注意的是，前台收到推送，也是可以跟后台收到推送一样，弹出横幅，播放声音并震动的。这要在`completionHandler`中传入相应的`UNNotificationPresentationOptions`就可以了。

如果你需要适配iOS10之前系统，可以实现UIApplicationDelegate的下列方法：

```swift
func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable : Any]) {
    if application.applicationState == .inactive {
        print("点击推送唤起app userInfo=\(userInfo)")
    }else{
        print("前台收到推送 userInfo=\(userInfo)")
    }
}
```

值得注意的是，点击推送横幅唤起app时也会触发相同方法，需要根据应用程序是不是`inactive`状态判断。

### 处理用户的响应

当用户点击我们app的推送通知时，如果app还存活，app会被唤起并触发下列方法。我们往往需要在这里，根据推送信息进行页面跳转等操作。

```swift
func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
    let userInfo = response.notification.request.content.userInfo
    handleUserResponse(userInfo:userInfo)
    completionHandler()
}
```

如果app已经被杀死，那么app会被重新启动，我们需要在app加载完成后处理用户的响应。

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    if let removePushUserInfo = launchOptions?[UIApplication.LaunchOptionsKey.remoteNotification]{
    	// 处理用户收到推送后的响应
   NotificationUtil.shared.handleUserResponse(userInfo:removePushUserInfo as! [AnyHashable:Any])
    }
    return true
}
```

### 处理后台收到推送

后台收到推送时，大多情况下，我们是不用处理的。

需要处理后台推送，一般有下列场景

- 需要统计推送的到达率，则需要无论是前台还是后台都可以监控并上报。
- 需要对推送内容进行更改，或者需要自定义推送的展现形式时。

对于后台推送的处理，我们一般会应用推送插件（App Extension）

#### 推送插件

跟推送有关的App Extension主要有两种`Notification Service Extension`和`Notification Content Extension`

![](notification-extension.png)

##### Notification Service Extension

这种插件，主要用于后台推送的监听，动态修改推送内容等。一种比较常见的业务场景是语音播报，它可以结合本地推送和本地语音包加以实现。

我们可以在Extension的下列方法中，实现对推送内容的修改。

```
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
```

上述方法只有在下列条件同时满足，方能触发调用。

- payload中`mutable-content`为1

- payload中必须包含Alert，并且具备Alert推送权限

更多介绍请参看[Modifying Content in Newly Delivered Notifications](https://developer.apple.com/documentation/usernotifications/modifying_content_in_newly_delivered_notifications)、[UNNotificationServiceExtension](https://developer.apple.com/documentation/usernotifications/unnotificationserviceextension)

##### Notification Content Extension

这类插件可以自定义推送的展现形式，但是实际开发中用的十分少。

在`NotificationViewController`中，可以像普通的UIViewController一样自定义UI。

它生效的必要条件是，payload中的`category`字段，必须和extension的 Info.plist中指定的`UNNotificationExtensionCategory`字段值一致。

它必须在通知中心，左滑点击`查看`推送才可以展现我们自定义的通知界面。

![](alerrt-look-detail.jpeg)

详细介绍，请参看[官方文档](https://developer.apple.com/documentation/usernotificationsui/unnotificationcontentextension)

#### 其他监听方式

下列方法也可以用于监听后台推送

```swift
func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable : Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void){}
```

原则上静默推送才在后台收到推送时唤醒app，并触发上述方法。但实践表明，触发他的必要条件有两个：

- 打开Background Modes 并勾选Remote notification

![image-20190716192501318](backgrand-mode.png)

- payload中包含`content-available`并且值为1

### 静默推送

当我们不请求推送权限，或者用户拒绝或者主动关闭了推送权限，推送还是可以正常到达设备的。但是没有横幅也没有声音，是以静默形式呈现。

必须打开后台模式，并勾选`Remote notification`，我们之前介绍的那些方法才会被触发。

我们在payload中不包含alert、sound、badge，无论app推送权限是否打开，都属于静默推送。

原则上，后台模式的推送应该是静默推送。在iOS13以后，需要在请求头中apns-push-type字段设置为backgroud。而如果不是真正的静默推送，有被APNs丢弃的危险。

## 服务端调用APNs接口

远程推送是服务端主动发起的。无论是自己搭建推送服务，还是选用第三方SDK。最终都是调用APNs的接口。

APNs的接口使用的网络协议是HTTP/2 Over TLS。

为了便于描述，示例代码包含iOS开发者熟悉的swift，和实际服务端使用比较多的java版本。

###与APNs建立安全连接

APNs主要有两种认证方式，一种是`Certificate-Based`（证书认证），另一种是`Token-Based`（Token认证）。其中，我们最为常用的是证书认证方式

#### Certificate-Based Connection

##### 推送证书

推送证书分为两种，一种是推送证书，另一种是生产证书。证书的创建方式很简单，这里就不再赘述了。

![pushcer](pushcer.tiff)

生产证书只能用于iOS开发环境。生产证书也叫通用证书，既能在生产环境使用，也可以用于开发环境。某些SDK可以设置生产证书用于开发环境。绝大多数情况下，配置一个生产证书就够用了。

我们提供给服务器或者第三方SDK的证书，一般有两种格式，一种是.p12，另一种是.pem。p12证书可以很容易从钥匙串导出。

pem证书可以通过下列命令，从p12生成：

```shell
openssl pkcs12 -in push_dis.p12 -out push_dis.pem -nodes
```

##### 建立HTTPS连接

TLS握手建立连接的大致流程是这样的

![cer-connect.png](cer-connect.png)

我们发起TLS连接，APNs返回他的服务端证书，我们提供自己的客户端证书，APNs验证客户端证书成功后，就可以建立安全的信任连接。连接成功后就可以向APNs发送远程推送请求了。

##### swift实现

我们暂且用swift代码来讲述原理。当我们第一次调用APNs的接口时，由于走的HTTPS，会触发`URLSessionDelegate`的`didReceive challenge`代理方法。握手过程大致如下：

```swift
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
  }
```

其中，客户端认证时的`credential`是由p12文件产生的。p12文件中包含了私钥，以及证书信息：

```swift
guard let data = try? Data(contentsOf: URL(fileURLWithPath:p12Path)) else { return nil }

var item = CFArrayCreate(nil, nil, 0,nil)
let options = pwd != nil ? [kSecImportExportPassphrase:pwd!] : [:]
let status = SecPKCS12Import(data as CFData,options as CFDictionary,&item)
if status != noErr {
    return nil
}

guard  let itemArr = item as? [Any],
       let dict = itemArr.first as? [String:Any] else{
    return nil
}
guard let secIdentity = dict[kSecImportItemIdentity as String] else {
    return nil
}
guard let cers = dict[kSecImportItemCertChain as String] as? [SecCertificate] else{
    return nil
} 

self.credential = URLCredential(
                    identity:secIdentity as! SecIdentity,
                                certificates:cers, 			
                                persistence:.permanent)
```

##### Java实现

我们应用java中优秀的事件驱动的异步网络库[Netty](https://github.com/netty/netty)，建立与APNs的安全连接。

我们需要先由p12文件生成私钥和证书，再配置用于建立SSL连接的`SslContext`

```java
final SslContext sslContext(String p12File, String password) throws SSLException, FileNotFoundException {
    // 由p12生成私钥和证书
    final KeyStore.PrivateKeyEntry privateKeyEntry = this.getPrivKeyEntry(p12File, password);
    final X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
    final PrivateKey privateKey = privateKeyEntry.getPrivateKey();

    // 由私钥和证书 生成netty的SslContext
    final SslProvider sslProvider;
    if (OpenSsl.isAvailable()) {
        // Native SSL provider is available; will use native provider.
        sslProvider = SslProvider.OPENSSL_REFCNT;
    } else {
        // Native SSL provider not available; will use JDK SSL provider.
        sslProvider = SslProvider.JDK;
    }
    final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().sslProvider(sslProvider)
            .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE);
    sslContextBuilder.keyManager(privateKey, password, certificate);

    return sslContextBuilder.build();
}
```

如果用的是pem文件，要更为简单一些：

```java
final SslContext sslContext(String pemFilePath) throws SSLException {
    final SslProvider sslProvider;
    if (OpenSsl.isAvailable()) {
        // Native SSL provider is available; will use native provider.
        sslProvider = SslProvider.OPENSSL_REFCNT;
    } else {
        // Native SSL provider not available; will use JDK SSL provider.
        sslProvider = SslProvider.JDK;
    }

    final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().sslProvider(sslProvider)
            .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE);

    final File pemFile = new File(pemFilePath);
    sslContextBuilder.trustManager(pemFile);

    return sslContextBuilder.build();
}
```



####Token-Based Connection

Token认证方式，主要应用了`JSON Web Token` (JWT)技术;

#####推送前的准备信息

如果没有keyId和.p8文件，需要在[这里](https://developer.apple.com/account/resources/authkeys/list)新建一个AuthKey

![getkey](keys.tiff)

创建完成之后记得下载并妥善保管生成的.p8文件，因为它只能下载一次。

`KeyId`直接包含在了文件名中，譬如名为`AuthKey_MTB28KC884.p8`的文件keyId就是MTB28KC884。你也可以点击到对应Key的详情页获取。

`Team Id`可以在Apple Develop -> Account -> Membership中参看。也就是[这里](https://developer.apple.com/account/#/membership/)

![team id](teamId.tiff)

##### 基本原理

###### JWT概述

JWT全称为JSON Web Token，是一个编码后的字符串，比如：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

一个典型的 JWT 由三部分组成，通过点号 . 进行分割。每个部分都是经过 Base64Url 编码的字符串。

- 第一部分 `Header`。Base64Url解码后是json。
- 第二部分 `Payload`(也叫`Claims`) 。解码后是json。
- 第三部分 `签名` 是用密钥对前两部分签名的结果。

######Base64Url编解码

Base64 相信大家都已经很熟悉了，随着网络普及，这套编码有一个很大的“缺点”，就是使用了 +，/ 和 =。这些字符在 URL 里是很不友好的，在作为传输时需要额外做 escaping。Base64Url 就是针对这个问题的改进，具体来说就是：

将 + 替换为 -；
将 / 替换为 _；
将末尾的 = 干掉。

```swift
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
```

######常用的签名方式

在 JWT Header 中，”alg” 是必须指定的值，它表示这个 JWT 的签名方式。常用的签名方式有以下几种

|通用名称|举例|签名算法|简介|
|:-:|:-:|:-:|:-:|
|HSXXX| HS256 |HMAC|运算利用哈希算法，以一个密钥和一个消息为输入，生成一个消息摘要作为输出。|
| RSXXX |RSA512|RSA |RSA签名/认证，XXX为模长（位）|
|ESXXX| ES256 |ECDSA|使用 椭圆曲线数字签名算法 (ECDSA) 进行签名。它也是一种非对称算法。不过它是基于椭圆曲线的。|
| PSXXX | PS256 | RSA |和 RSXXX 类似使用 RSA 算法，但是使用 PSS 作为 padding 进行签名。作为对比，RSXXX 中使用的是 PKCS1-v1_5 的 padding。|

除了 “alg” 以外，我们还会用到 “kid”，它用来表示在验证时所需要的，从 JWK Host 中获取的公钥的 key ID。

#####APNS的JWT结构及签名方式

header部分：

|key|描述|
|:-:|:-:|
| alg|加密算法，APNs只支持ES256 |
| kid |keyId|

Payload(Claims)部分

|key|描述|
|:-:|:-:|
| iss |Team ID|
| iat |时间戳，距离1970年的秒数|

APNs只支持`ES256`，即椭圆曲线数字签名算法（ECDSA）。

> 椭圆曲线数字签名算法（ECDSA）是使用椭圆曲线密码（ECC）对数字签名算法（DSA）的模拟。

在使用ECC进行数字签名的时候，需要构造一条曲线，也可以选择标准曲线，诸如：prime256v1、secp256r1、nistp256、secp256k1等等。

而ES256代表的是，我们选择的是prime256v1标准曲线。

哈希散列函数算法采用SHA256.

关于ECC（ECDSA）的更多知识，请参看[这篇文章](https://www.jianshu.com/p/676a0eb33d31)

#####创建token

我们可以根据keyId、teamId以及时间戳构建head和body。然后分别对他们进行Base64Url，然后用点分隔符拼接得到unsignedJWT，再转成Data得到unsignedData。然后用.p8生成私钥，最后用私钥及ECDSA签名算法对`head + . + body`。

###### Swift实现

大致过程用swift实现如下：


```swift
// head部分
var head = [String:Any]()
head["kid"] = kKeyId
head["alg"] = "ES256"
let headString = APNsJwt.base64UrlString(json:head)

// claim部分
var claim = [String:Any]()
claim["iss"] = kTeamId
claim["iat"] = Date().timeIntervalSince1970
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
let token = headString + "." + claimString + "." + signString
```

###### Java实现

```java
// 生成head、claims两部分json
AuthenticationTokenHeader header = new AuthenticationTokenHeader(keyId);
AuthenticationTokenClaims claims = new AuthenticationTokenClaims(teamId, issuedAt);
final String headerJson = GSON.toJson(header);
final String claimsJson = GSON.toJson(claims);

// base64Url编码后，拼接成签名前字符串
final StringBuilder payloadBuilder = new StringBuilder();   payloadBuilder.append(encodeUnpaddedBase64UrlString(headerJson.getBytes(StandardCharsets.US_ASCII)));
payloadBuilder.append('.');
payloadBuilder.append(encodeUnpaddedBase64UrlString(claimsJson.getBytes(StandardCharsets.US_ASCII)));

// 由p8生成私钥
ECPrivateKey signingKey = loadPrivKey(p8path);

// SHA256withECDSA签名
final Signature signature = Signature.getInstance("SHA256withECDSA");
signature.initSign(signingKey);
signature.update(payloadBuilder.toString().getBytes(StandardCharsets.US_ASCII));
byte[] signatureBytes = signature.sign();

// 签名base64Url编码，并拼接在最后
payloadBuilder.append('.');
payloadBuilder.append(encodeUnpaddedBase64UrlString(signatureBytes));

// 最后得到token
String token = payloadBuilder.toString();
```

其中加载私钥环节是这样的

```java
// 去除头尾标识及回车符
final InputStream inputStream = new FileInputStream(p8path);
final StringBuilder privateKeyBuilder = new StringBuilder();
final BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
boolean haveReadHeader = false;
for (String line; (line = reader.readLine()) != null;) {
    if (!haveReadHeader) {
        if (line.contains("BEGIN PRIVATE KEY")) {
            haveReadHeader = true;
        }
    } else {
        if (line.contains("END PRIVATE KEY")) {
            break;
        } else {
            privateKeyBuilder.append(line);
        }
    }
}
final String base64EncodedPrivateKey = privateKeyBuilder.toString();
reader.close();

// base64解码
final byte[] keyBytes = decodeBase64EncodedString(base64EncodedPrivateKey);

// 转化为ECPrivateKey
final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
final KeyFactory keyFactory = KeyFactory.getInstance("EC");
ECPrivateKey signingKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);
```

#####将token添加到请求头

将`bearer <provider_token>`添加到请求头的authorization字段，其中`provider_token`是上面生成的token。譬如：

```
authorization: bearer eyAia2lkIjogIjhZTDNHM1JSWDciIH0.eyAiaXNzIjogIkM4Nk5WOUpYM0QiLCAiaWF0I
		 jogIjE0NTkxNDM1ODA2NTAiIH0.MEYCIQDzqyahmH1rz1s-LFNkylXEa2lZ_aOCX4daxxTZkVEGzwIhALvkClnx5m5eAT6
		 Lxw7LZtEQcH6JENhJTMArwLf3sXwi
```

#####Token的刷新

出于安全考虑，APNs要求有规律的刷新token。而刷新的周期在20分钟到60分钟之间。APNs会拒绝过期token的所以请求。同样的，如果你更新token太过频繁，也会报错。

也就是说我们的provider server，必须缓存token，并建立定期更新机制。

###请求头字段

请求头主要包含下列字段：

| 头部字段       | 是否必须              | 描述                                                         |
| :------------- | :-------------------- | :----------------------------------------------------------- |
| :method        | 必须                  | POST                                                         |
| :path          | 必须                  | /3/device/<device_token>                                     |
| authorization  | token-based方式下必须 | bearer <provider_token>                                      |
| apns-topic     | 必须                  | BundleId                                                     |
| apns-push-type | iOS13之后必须         | `alert` 或`background`；background是静默推送，alert是普通推送。 |
| apns-id        | 非必须                | 推送通知的唯一标识                                           |

其他请求头字段，详见[Sending Notification Requests to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/sending_notification_requests_to_apns)

### 生成playload

payload是我们请求体，是一个json。它主要包含下列字段

| Key               | 类型                  | 描述                                                         |
| :---------------- | :-------------------- | :----------------------------------------------------------- |
| alert             | Dictionary  or String | 横幅中展现的内容                                             |
| badge             | Number                | 桌面图标展示的小红点数字                                     |
| sound             | String                | 播放的声音                                                   |
| content-available | Number                | 后台推送标识符。值为1时，在后台收到推送可以唤起app进行相关更新，原则上只能静默推送，不能带上alert、sound、badge。 |
| mutable-content   | Number                | 值为1时，Notification Service Extension才能正常工作。        |

关于跟多字段，详见[Generating a Remote Notification](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/generating_a_remote_notification)。

#### Alert

alert一般包含下列字段

| Key     | 类型   | 描述                     |
| ------- | ------ | ------------------------ |
| title   | String | 推送的标题               |
| subtile | String | 解释通知用途的其他信息。 |
| body    | String | 推送的具体内容           |

当alert字段是字符串时，相当于body字段。

alert字段下，还包含一些本地化相关的字段。具体请自行查看[官方文档](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/generating_a_remote_notification)

#### Sound

sound字段的值，是声音文件的文件名。有效的声音文件只能存在两个地方。一个是在`main bundle`下，另一个是在主程序用户目录的 `Library/Sound`下。

关于声音推送的具体介绍，参见[UNNotificationSound](https://developer.apple.com/documentation/usernotifications/unnotificationsound)

### 发送推送请求

完成认证并且生成了payload后，我们就可以发起推送请求了：

#### Swift实现

```swift
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
```

#### Java实现

发送推送请求的大致过程如下：

```java
// 创建请求
String path = "/3/device/" + deviceToken;
HttpScheme scheme = HttpScheme.HTTPS;
AsciiString hostName = new AsciiString("api.sandbox.push.apple.com:443");
HttpVersion version = HttpVersion.valueOf("HTTP/1.1");
ByteBuf body = Unpooled.wrappedBuffer(payload.getBytes(CharsetUtil.UTF_8));
FullHttpRequest request = new DefaultFullHttpRequest(version, new HttpMethod("POST"), path,body);
request.headers().add(HttpHeaderNames.HOST, hostName);
request.headers().add(HttpConversionUtil.ExtensionHeaderNames.SCHEME.text(), scheme.name());
request.headers().add("apns-topic", topic);
if(this.jwt != null){
    request.headers().add(HttpHeaderNames.AUTHORIZATION, "bearer " + this.jwt.token);
}

// 发送请求
Channel channel = initializer.channel;
channel.write(request);
channel.flush();

// 等待返回结果
Result result = initializer.responseHandler.awaite();
System.out.println("sent " + (result.isSuccess ? "成功" : "失败" ) + result.reason);
```

### 处理调用结果

我们需要处理调用APNs接口所返回的结果。apns的返回值，主要有两部分，相应头的响应状态码，响应体中的reason。

| status code | reason                      | 描述                                            |
| ----------- | --------------------------- | ----------------------------------------------- |
| 200         | /                           | 成功                                            |
| 400         | BadDeviceToken              | DeviceToken无效，或者环境错了。                 |
| 400         | BadTopic                    | apns-topic值无效                                |
| 400         | DeviceTokenNotForTopic      | DeviceToken和Topic不匹配                        |
| 400         | MissingDeviceToken          | 没有DeviceToken                                 |
| 400         | MissingTopic                | 请求头缺少apns-topic                            |
| 403         | BadCertificate              | 证书无效                                        |
| 403         | BadCertificateEnvironment   | 证书的环境不对                                  |
| 403         | ExpiredProviderToken        | Token过期了                                     |
| 403         | MissingProviderToken        | 没有提供客户端认证证书，也没有设置authorization |
| 413         | PayloadTooLarge             | payload太大。（不得大于4 KB）                   |
| 429         | TooManyProviderTokenUpdates | Token更新太过频繁（小于20分钟）                 |
| 429         | TooManyRequests             | 同时向同一台设备发送了过多请求                  |

其他状态码，详见[Sending Notification Requests to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/sending_notification_requests_to_apns#2947607)

### 最佳实践

上述事例代码中，我们为了方便描述原理，简化了大量代码。所有连接与请求都是同步的，大大损耗了性能。对于大用户量的广播或者组播，我们需要设法使我们的代码更为高效。

处于性能考虑，我们可以就一下这些方面着手：

- 长链接及多路复用：我们期望在SSL握手成功后，所以请求都通过相同的会话进行，并且保证连接的生命周期经可能长。在必要时有断线重连机制。
- 异步处理APNs的响应：APNs是通过HTTP/2的ServerPush给我们返回请求结果。不用等待前面的请求完成，才能发送新的请求。而我们需要异步监听APNs的响应，再统一处理请求结果。
- 处理`in flight`的请求：`in flight`指的是已经发出去但还没有返回的请求，APNs允许同时存在1,500个左右这样的推送请求，其余的要被阻塞。如果并发量过大，我们需要缓存其余未得以发送的请求。
- 流量控制：虽然我们已经缓存了为发送的请求，但是如果并发量过大，请求队列中为发送的请求过多，会耗费大量内存资源。所以我们必须控制并发量，尤其是在发送广播时。
- 权衡并发数和连接数。我们需要建立线程池及运行循环来控制开启的线程数，来充分发挥CPU的性能。我们可以建立多个连接来充分发挥带宽资源。而往往我们需要一个平衡。

[Pushy](https://github.com/relayrides/pushy/wiki/Best-practices)为我们实现了这些，我们可以直接使用。

建立客户端

```java
ApnsClient cerClient(Boolean isProduct,String p12Path, String p12Pwd) throws SSLException, IOException {
    File file = new File(p12Path);
    String host = isProduct ? ApnsClientBuilder.PRODUCTION_APNS_HOST : ApnsClientBuilder.DEVELOPMENT_APNS_HOST;
    ApnsClientBuilder apnsClientBuiler = new ApnsClientBuilder();
    apnsClientBuiler.setApnsServer(host);
    apnsClientBuiler.setClientCredentials(file, p12Pwd);
    ApnsClient client = apnsClientBuiler.build();
    return client;
}
```

生成的`Client`，应该尽量保证它的生命周期足够长，以提高推送的效率。

新建推送

```java
SimpleApnsPushNotification notification(String deviceToken,String title, String body){
    final ApnsPayloadBuilder payloadBuilder = new ApnsPayloadBuilder();
    payloadBuilder.setAlertTitle(title);
    payloadBuilder.setAlertBody(body);
    payloadBuilder.setSound("default");
    final String payload = payloadBuilder.buildWithDefaultMaximumLength();
    final String token = TokenUtil.sanitizeTokenString(deviceToken);
    SimpleApnsPushNotification pushNotification = new SimpleApnsPushNotification(token, kBundleId, payload);
    return pushNotification;
}
```

异步发送推送请求

```java
private final Semaphore semaphore = new Semaphore(10_000);
    PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>> asyncSent(ApnsPushNotification notification){
  try {
      semaphore.acquire();
      final PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>> sendNotificationFuture =
      client.sendNotification(notification);
      sendNotificationFuture.addListener(future -> semaphore.release());
      return sendNotificationFuture;
  } catch (InterruptedException e1) {
      System.err.println("Failed to  acquire semaphore.");
      e1.printStackTrace();
      return null;
  }
}
```

这个是最底层方法，用于全局流量控制。

可以用下列方法，同步获取推送请求的响应

```java
ApnsResponse getResult(PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>> future){
    try {
        PushNotificationResponse<ApnsPushNotification> pushNotificationResponse = future.get();
        ApnsResponse response = new ApnsResponse(pushNotificationResponse.getPushNotification(), pushNotificationResponse.isAccepted(), pushNotificationResponse.getRejectionReason());
        return response;
    } catch (InterruptedException | ExecutionException e) {
        ApnsResponse response = new ApnsResponse(future.getPushNotification(), false, "sent Interrupted");
        return response;
    }
}
```

向指定设备推送

```java
ApnsResponse sentSingleNotification(String deviceToken,String title,String body){
    ApnsPushNotification notification = notification(deviceToken, title, body);
    return getResult( asyncSent(notification) );
}
```

广播或组播时，需要先从数据库读取一批DeviceToken，然后通过下列方法发送：

```java
List<ApnsResponse> sentNotification(List<String>deviceTokens,String title,String body){
  
 ArrayList<PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>>> futureList = new ArrayList<PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>>>();
     // 异步发送推送请求 
    for (String deviceToken : deviceTokens) {
        ApnsPushNotification notification = notification(deviceToken, title, body);
        futureList.add( asyncSent(notification) );
    }

    // 阻塞直到最后一个请求完成
    ArrayList<ApnsResponse> resultList = new ArrayList<ApnsResponse>();
    for (PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>> future : futureList) {
        ApnsResponse response = getResult(future);
        resultList.add(response);
    }

    return resultList;
}
```

## 推送SDK哪家强

### 主流SDK对比

现在主流的推送SDK主要有这几种：

| 平台 | 支持证书格式 | Token 认证 | 安卓厂商通道 | 历史记录/推送统计      | idfa       |
| ---- | :----------: | :--------: | :----------: | ---------------------- | ---------- |
| 信鸽 |     pem      |   不支持   |     免费     | 只有一定时间内历史记录 | 默认不包含 |
| 友盟 |     p12      |    支持    |     免费     | 历史记录/数据统计      | 默认包含   |
| 极光 |     p12      |    支持    |     收费     | 只有数据统计图表       | 默认包含   |
| 个推 |     p12      |   不支持   |    不支持    | 只有数据统计图表       | 默认包含   |

单论iOS端，从原理上来说，都是调用APNs的接口。基本上各大SDK都是在调用APNs接口之后，就结束，不会缓存消息。那么选用那个其实都是大同小异的。主要是集成方便就可以了。

而就集成来说，都是注册SDK，然后打开授权，然后上传deviceToken，设置若干标签。最后为了统计，还需要在收到推送时、用户点击时上报。

某些SDK推送授权跟点击事件上报放到一个函数，要求传入`launchOptions`。而我们有时候不期望已启动就弹出推送授权认证提示，这样处理起来稍显麻烦。如果SDK中使用了idfa，我们要么集成不包含idfa版本，要么需要在提审时作特殊的设置。友盟还使用的老iOS版本的方法，使用起来略微蹩脚。

而实现上往往要兼顾安卓端。而安卓为了让推送能及时到达，最好是集成厂商通道。那么SDK能免费集成厂商通道，那么自然成为我们的首选。

推送的历史记录能有效帮助我们排查推送发出去后发生的问题。而对于运营来说一些统计信息也是必要的。

## 远程推送的疑难杂症

### 收不到推送问题

推送收不到是最为常见的一种问题。

首先我们可以通过一些调试工具，譬如[Knuff](https://github.com/KnuffApp/Knuff)进行调试。验证客户端代码成面的问题，以及证书的配置问题。

如果使用了SDK，我们可以在它的管理平台发几条消息试试。看看我们集成的有没有问题，或者上传的证书是不是环境设置错了，或者在证书转化格式过程中出现了错误。对于友盟在生成p12时，在钥匙串中对应是不能展开的。

我们可以让后台提供一些验证的接口。如果在SDK的管理后台可以推送到，调接口推不到。可以检查服务在调用第三方接口时是否成功，或者第三方调用APNs是否成功。这个一般可以在接口的响应中可以看到，在一些管理后台也可以看到历史记录。

如果接口都调用成功了，还是收不到。一般是手机上的权限没有打开、有没有联网。或者payload中alert、sound等有没有正确的设置。

### 推送的延迟

首先推送延迟是客观存在的。无论是调用第三方接口，还是调用APNs都会有高峰期，都会有拥堵需要排队的情况。

我们可以监控一下发生延迟情况时，调用第三方接口，或者调用APNs多久才返回。如果返回的都很及时，那么就是APNs处理不过来，或者跟设备协商有所问题。

- [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns)
- [Setting Up a Remote Notification Server](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server)
- [Token-Based Connection](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_token-based_connection_to_apns)
- [Establishing a Certificate-Based Connection to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_certificate-based_connection_to_apns)

- [iOS开发之新版APNs搭建必备知识](https://www.jianshu.com/p/d8dba6c2c07a)
- [基于APNs最新HTTP/2接口实现iOS的高性能消息推送(服务端篇)](http://www.blogjava.net/jb2011/archive/2018/07/30/433310.html)
- [UserNotifications框架详解](https://www.jianshu.com/p/0f0dd782fdd5)
- [iOS的推送服务APNs详解：设计思路、技术原理及缺陷等](http://www.52im.net/thread-345-1-1.html)
- [Establishing a Token-Based Connection to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_token-based_connection_to_apns)
- [与 JOSE 战斗的日子 - 写给 iOS 开发者的密码学入门手册 (实践)](https://onevcat.com/2018/12/jose-3/)
- [与 JOSE 战斗的日子 - 写给 iOS 开发者的密码学入门手册 (基础)](https://onevcat.com/2018/12/jose-1/)
- [Java密码学 非对称加密以及使用secp256k1进行数字签名（ECDSA](https://www.jianshu.com/p/676a0eb33d31)