package com.anjia.unidbgserver.controller;

import com.anjia.unidbgserver.service.FanQieSignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignController {

    @Autowired
    private FanQieSignService signService;

    /**
     * 签名接口
     * @param headers 完整的签名输入字符串（由 Legado 书源构造）
     * @return JSON 格式的签名字典
     */
    @GetMapping("/sign")
    public String sign(@RequestParam("headers") String headers) {
        if (headers == null || headers.isEmpty()) {
            return "{\"error\":\"missing headers\"}";
        }
        return signService.sign(headers);
    }

    @GetMapping("/health")
    public String health() {
        return "OK";
    }
}
