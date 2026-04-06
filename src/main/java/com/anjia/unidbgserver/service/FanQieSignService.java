package com.anjia.unidbgserver.service;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class FanQieSignService {

    private AndroidEmulator emulator;
    private Module module;
    // 根据你的逆向报告，桥梁函数偏移 0x498434
    private final long SUB_498434_OFFSET = 0x498434;

    @PostConstruct
    public void init() throws Exception {
        // 1. 创建模拟器（根据你的 .so 是 32 位还是 64 位，这里是 32 位，若是 64 位改为 for64Bit）
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

        // 可选：如果需要调用 JNI_OnLoad，取消下面注释
        // module.callJNI_OnLoad(emulator);
    }

    /**
     * 生成签名
     * @param headersStr 完整的签名输入字符串（11个HTTP头部拼接，参考逆向报告2.1节）
     * @return 包含签名的 JSON 字符串，例如 {"x-gorgon":"xxxx"}
     */
    public String sign(String headersStr) {
        try {
            // 1. 将输入字符串写入模拟器内存
            byte[] inputBytes = headersStr.getBytes(StandardCharsets.UTF_8);
            UnidbgPointer inputPtr = emulator.getMemory().malloc(inputBytes.length + 1, false);
            inputPtr.write(0, inputBytes, 0, inputBytes.length);
            inputPtr.writeByte(inputBytes.length, (byte) 0); // 末尾加 \0

            // 2. 分配输出缓冲区（假设签名结果长度不超过 512）
            UnidbgPointer outputPtr = emulator.getMemory().malloc(512, false);

            // 3. 调用 sub_498434(a1, a2, a3)
            //    根据逆向报告：a1=请求上下文指针，a2=设备信息指针，a3=输出指针
            //    这里我们传入 inputPtr 作为 a1（模拟请求上下文），outputPtr 作为 a3
            //    a2 暂时传 0，如果后续需要设备信息，可以通过构造结构体传入
            Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                    inputPtr.toPointer(),   // a1
                    UnidbgPointer.pointer(0L), // a2 临时设为 0
                    outputPtr.toPointer());    // a3

            // 4. 从输出缓冲区读取结果（假设结果是 Base64 字符串，以 \0 结尾）
            byte[] outBytes = outputPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            // 5. 构造返回结果（目前只有 x-gorgon，其他头部后续可扩展）
            Map<String, String> result = new HashMap<>();
            result.put("x-gorgon", signature);
            // 如果你知道 x-argus 等其他签名的生成方式，可以在此添加

            return new com.alibaba.fastjson.JSONObject(result).toJSONString();
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