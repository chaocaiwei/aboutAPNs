package com.ccsobj.apns;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class SampleloadBuilder {
   
    public final Map<String,String> alert;
    public final String sound = "defult";

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    SampleloadBuilder(String title,String body) {
        Map<String,String> map = new HashMap<String,String>();
        map.put("title", title);
        map.put("body", body);
        this.alert = map;
    }

    String build(){
        Map<String,Object> map = new HashMap<String,Object>();
        Map<String,Object> aps = new HashMap<String,Object>();
        aps.put("alert", alert);
        aps.put("sound", sound);
        map.put("aps", aps);
        return GSON.toJson(map);
    }


}