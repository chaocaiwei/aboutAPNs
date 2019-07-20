package com.ccsobj.apns;

import com.ccsobj.apns.ApnsUtil.ApnsResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import lombok.extern.log4j.Log4j;

@SpringBootApplication
public class DemoApplication {
	static String kBundleId = "com.ccsobj.LearnAPNs";
	static String kDeviceToken = "376d43e2181421cbd12f979f3f21efdf11a2a411bad0614524cea338a4994453";
	static String kP12Path = "/Users/myself/Desktop/demo/src/main/resources/learn.p12";
	static String kP12Pwd = "123456";
	static String kP8Path = "/Users/myself/Desktop/demo/src/main/resources/AuthKey_MTB28KC884.p8";
    static  String kTeamId  = "JFW6NYCCQB";
	static  String kKeyId   = "MTB28KC884";
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);

		ApnsUtil contr = new ApnsUtil();
		ApnsResponse ret = contr.sentSingleNotification(kDeviceToken, "title","bodysingle");
		System.out.print(ret.isAccepted);
		
		// contr.mutableContentPush();
		// contr.silentPush();
		// contr.testAuthKeyPush();
		// contr.testCerPush();
		// contr.testAuthKeyPush();
		// contr.testAuthKeyPush();

		// String payload = new SampleloadBuilder("title","body 0").build();
		// SampleApnsClient client = new SampleApnsClient(kP12Path,kP12Pwd);
		// client.connect();
		// client.sent(kDeviceToken,kBundleId,payload);

		// String payload1 = new SampleloadBuilder("title","body 1").build();
		// SampleApnsClient keyClient = new SampleApnsClient(kP8Path, kKeyId, kTeamId);
		// keyClient.connect();
		// keyClient.sent(kDeviceToken,kBundleId,payload1);

	}

}
