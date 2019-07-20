package com.ccsobj.apns;


import com.turo.pushy.apns.*;
import com.turo.pushy.apns.auth.ApnsSigningKey;
import com.turo.pushy.apns.util.ApnsPayloadBuilder;
import com.turo.pushy.apns.util.SimpleApnsPushNotification;
import com.turo.pushy.apns.util.TokenUtil;
import com.turo.pushy.apns.util.concurrent.PushNotificationFuture;

import io.netty.util.concurrent.Future;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;

import javax.net.ssl.SSLException;

public class ApnsUtil {

    public class ApnsResponse {
        final ApnsPushNotification notification;
        final Boolean isAccepted;
        final String  reason;
        public ApnsResponse(ApnsPushNotification notification,Boolean isAccepted,String  reason){
            this.notification = notification;
            this.isAccepted = isAccepted;
            this.reason = reason;
        }
    }

    final Boolean kIsProduct = false;
    final Boolean kUserAuthKey = false;

    final String kP12Path = "/Users/myself/Desktop/demo/src/main/resources/learn.p12";
    final String kP12Pwd = "123456";
    final String kP8Path = "/Users/myself/Desktop/demo/src/main/resources/AuthKey_MTB28KC884.p8";
    final String kTeamID = "JFW6NYCCQB";
    final String kKeyId  = "MTB28KC884";
    final String kBundleId = "com.ccsobj.LearnAPNs";
    final String kDeviceToken = "376d43e2181421cbd12f979f3f21efdf11a2a411bad0614524cea338a4994453";

    
    ApnsClient cerClient(Boolean isProduct,String p12Path, String p12Pwd) throws SSLException, IOException {
        File file = new File(p12Path);
        String host = isProduct ? ApnsClientBuilder.PRODUCTION_APNS_HOST : ApnsClientBuilder.DEVELOPMENT_APNS_HOST;
        ApnsClientBuilder apnsClientBuiler = new ApnsClientBuilder();
        apnsClientBuiler.setApnsServer(host);
        apnsClientBuiler.setClientCredentials(file, p12Pwd);
        ApnsClient client = apnsClientBuiler.build();
        return client;
    }

    ApnsClient authKeyClient(Boolean isProduct,String p8Path, String teamID, String keyId)
            throws InvalidKeyException, SSLException, NoSuchAlgorithmException, IOException {
        String host = isProduct ? ApnsClientBuilder.PRODUCTION_APNS_HOST : ApnsClientBuilder.DEVELOPMENT_APNS_HOST;
        final ApnsClient apnsClient = new ApnsClientBuilder()
                .setApnsServer(host)
                .setSigningKey(ApnsSigningKey.loadFromPkcs8File(new File(kP8Path),
                        kTeamID, kKeyId))
                .build();
        return apnsClient;
    }
    
    ApnsClient devCerClient;
    {
        try {
            devCerClient = cerClient(false,kP12Path, kP12Pwd);
        } catch (SSLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    ApnsClient devAuthKeyClient;
    {
        try {
            devAuthKeyClient = authKeyClient(false,kP8Path, kTeamID, kKeyId);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SSLException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    ApnsClient prodCerClient;
    {
        try {
            prodCerClient = cerClient(true,kP12Path, kP12Pwd);
        } catch (SSLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    ApnsClient prodAuthKeyClient;
    {
        try {
            prodAuthKeyClient = authKeyClient(true,kP8Path, kTeamID, kKeyId);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SSLException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    ApnsClient client;
    {
        if (!kIsProduct) {
            if ( kUserAuthKey) {
                client = devAuthKeyClient;
            } else {
                client = devCerClient;
            }
        } else {
            if ( kUserAuthKey) {
                client = prodAuthKeyClient;
            } else {
                client = prodCerClient;
            }
        }
    }

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

    // 推送到指定设备
    ApnsResponse sentSingleNotification(String deviceToken,String title,String body){
        ApnsPushNotification notification = notification(deviceToken, title, body);
        return getResult( asyncSent(notification) );
    }

    // 广播/多播
    List<ApnsResponse> sentNotification(List<String>deviceTokens,String title,String body){

        // 异步发送推送请求
        ArrayList<PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>>> futureList = new ArrayList<PushNotificationFuture<ApnsPushNotification,PushNotificationResponse<ApnsPushNotification>>>();
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

    void silentPush(){
        final ApnsPayloadBuilder payloadBuilder = new ApnsPayloadBuilder();
        payloadBuilder.setContentAvailable(true);
        payloadBuilder.setAlertBody("alert");
        payloadBuilder.setSound("default");
        final String payload = payloadBuilder.buildWithDefaultMaximumLength();
        final String token = TokenUtil.sanitizeTokenString(kDeviceToken);
        SimpleApnsPushNotification pushNotification = new SimpleApnsPushNotification(token, kBundleId, payload);
        System.out.print(getResult(asyncSent(pushNotification)));
    }

    void mutableContentPush(){
        final ApnsPayloadBuilder payloadBuilder = new ApnsPayloadBuilder();
        payloadBuilder.setAlertBody("alert");
        payloadBuilder.setSound("233");
        payloadBuilder.setAlertTitle("title");
        payloadBuilder.addCustomProperty("name", "url");
        payloadBuilder.setMutableContent(true);
        payloadBuilder.setCategoryName("customUI");
        final String payload = payloadBuilder.buildWithDefaultMaximumLength();
        final String token = TokenUtil.sanitizeTokenString(kDeviceToken);
        SimpleApnsPushNotification pushNotification = new SimpleApnsPushNotification(token, kBundleId, payload);
        System.out.print(getResult(asyncSent(pushNotification)));
    }

    void testAuthKeyPush(){
        ApnsPushNotification pushNotification = notification(kDeviceToken,"标题", "这里是用AuthKey推送的内容");
        System.out.print(getResult(asyncSent(pushNotification)));
    }

    void testCerPush(){
        ApnsPushNotification pushNotification = notification(kDeviceToken,"标题", "这里是用证书推送的内容");
        System.out.print(getResult(asyncSent(pushNotification)));
    }


}