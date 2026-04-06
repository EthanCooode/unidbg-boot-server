package com.example.unidbgserver.service;

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
    private long sub_498434_offset = 0x498434; // 你的逆向报告中的偏移

    @PostConstruct
    public void init() throws Exception {
        // 1. 创建 32 位模拟器（根据你的 .so 是 32 位还是 64 位，这里是 32 位示例）
        emulator = AndroidEmulatorBuilder.for32Bit().build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23)); // Android 6.0

        // 2. 加载 libsscronet.so
        File soFile = new File("src/main/resources/libsscronet.so");
        if (!soFile.exists()) {
            throw new RuntimeException("libsscronet.so not found in resources");
        }
        module = memory.load(soFile);
        System.out.println("[FanQieSign] libsscronet.so loaded at base: " + module.base);

        // 可选：调用 JNI_OnLoad 如果需要
        // module.callJNI_OnLoad(emulator);
    }

    /**
     * 生成签名
     * @param headersStr 签名输入字符串（11个HTTP头拼接，参考你的报告2.1节）
     * @return 包含 x-gorgon 等签名的 JSON 字符串
     */
    public String sign(String headersStr) {
        try {
            // 1. 将输入字符串转换为字节数组并写入模拟器内存
            byte[] inputBytes = headersStr.getBytes(StandardCharsets.UTF_8);
            UnidbgPointer inputPtr = emulator.getMemory().malloc(inputBytes.length + 1, false);
            inputPtr.write(0, inputBytes, 0, inputBytes.length);
            inputPtr.writeByte(inputBytes.length, (byte) 0);

            // 2. 分配输出缓冲区（假设签名结果最大512字节）
            UnidbgPointer outputPtr = emulator.getMemory().malloc(512, false);

            // 3. 调用 sub_498434(a1, a2, a3)
            // 根据逆向报告，参数 a1=请求上下文指针，a2=设备信息指针，a3=输出指针
            // 由于我们没有完整的结构体，这里用 inputPtr 模拟 a1，outputPtr 模拟 a3，a2 传 0
            // 实际调用可能需要更精确的参数，但先跑通流程
            Number ret = module.callFunction(emulator, sub_498434_offset,
                    inputPtr.toPointer(),   // a1
                    UnidbgPointer.pointer(0L), // a2 临时传0
                    outputPtr.toPointer());    // a3

            // 4. 从输出缓冲区读取签名结果（假设结果是 Base64 字符串，以 \0 结尾）
            byte[] outBytes = outputPtr.getByteArray(0, 256);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            // 5. 构造返回的签名字典（目前只有 x-gorgon，其他头需要进一步逆向）
            Map<String, String> result = new HashMap<>();
            result.put("x-gorgon", signature);
            // 如果你有 x-argus 等其他头的生成逻辑，可在此添加

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