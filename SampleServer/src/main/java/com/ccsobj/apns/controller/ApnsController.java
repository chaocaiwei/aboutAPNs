package com.ccsobj.apns.controller;

import org.springframework.boot.jackson.JsonComponent;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApnsController {
    

    @RequestMapping("/push")
    String push(){
        return "apns push";
    }

}