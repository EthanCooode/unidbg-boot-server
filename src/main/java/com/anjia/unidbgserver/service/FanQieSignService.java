package com.anjia.unidbgserver.service;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
public class FanQieSignService {

    private AndroidEmulator emulator;
    private Module module;
    // 根据逆向报告，桥梁函数偏移 0x498434
    private final long SUB_498434_OFFSET = 0x498434;

    @PostConstruct
    public void init() throws Exception {
        // 1. 创建 32 位模拟器（如果 .so 是 64 位，改为 .for64Bit()）
        emulator = AndroidEmulatorBuilder.for32Bit().build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23)); // Android 6.0

        // 2. 加载 libsscronet.so
        File soFile = new File("src/main/resources/libsscronet.so");
        if (!soFile.exists()) {
            throw new RuntimeException("libsscronet.so not found in src/main/resources/");
        }
        module = memory.load(soFile);
        System.out.println("[FanQieSign] libsscronet.so loaded at base: 0x" + Long.toHexString(module.base));
    }

    /**
     * 生成签名
     * @param headersStr 完整的签名输入字符串（11个HTTP头部拼接）
     * @return 包含签名的 JSON 字符串
     */
    public String sign(String headersStr) {
        try {
            // 1. 将输入字符串写入模拟器内存
            byte[] inputBytes = headersStr.getBytes(StandardCharsets.UTF_8);
            // 分配内存块，注意：Unidbg 中 malloc 返回 MemoryBlock，需要通过 getPointer() 获取指针
            MemoryBlock inputBlock = emulator.getMemory().malloc(inputBytes.length + 1, false);
            UnidbgPointer inputPtr = inputBlock.getPointer();
            inputPtr.write(0, inputBytes, 0, inputBytes.length);
            // 写入结束符 \0
            inputPtr.setByte(inputBytes.length, (byte) 0);

            // 2. 分配输出缓冲区（512 字节）
            MemoryBlock outputBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outputPtr = outputBlock.getPointer();

            // 3. 调用 sub_498434(a1, a2, a3)
            //    参数1: 请求上下文指针（这里用 inputPtr 模拟）
            //    参数2: 设备信息指针（暂用 0）
            //    参数3: 输出指针
            module.callFunction(emulator, SUB_498434_OFFSET,
                    inputPtr,                 // a1
                    UnidbgPointer.pointer(emulator, 0L), // a2 传 0
                    outputPtr);               // a3

            // 4. 从输出缓冲区读取结果（假设以 \0 结尾的字符串）
            byte[] outBytes = outputPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            // 5. 释放内存块（可选，Unidbg 会在模拟器关闭时自动回收，但显式释放更规范）
            inputBlock.free();
            outputBlock.free();

            // 6. 构造返回结果
            Map<String, Object> result = new HashMap<>();
            result.put("x-gorgon", signature);
            // 如果还有其他签名头，可以继续添加

            // 使用 fastjson 转换为 JSON 字符串
            return com.alibaba.fastjson.JSONObject.toJSONString(result);
        } catch (Exception e) {
            e.printStackTrace();
            return "{}";
        }
    }

    @PreDestroy
    public void destroy() {
        if (emulator != null) {
            emulator.close();
        }
    }
}
