package com.example.unidbgserver.controller;

import com.example.unidbgserver.service.FanQieSignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignController {

    @Autowired
    private FanQieSignService signService;

    @GetMapping("/sign")
    public String sign(@RequestParam("url") String url) {
        // 注意：这里需要根据你的逆向报告构造完整的 headersStr
        // 简化版：只使用 url 作为输入（实际应该包含11个头部）
        // 为了测试，先直接用 url 作为输入
        String headersStr = url; // 请替换为真实的拼接逻辑
        return signService.sign(headersStr);
    }

    @GetMapping("/health")
    public String health() {
        return "OK";
    }
}