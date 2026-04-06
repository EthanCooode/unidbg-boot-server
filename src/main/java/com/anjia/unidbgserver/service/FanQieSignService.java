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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
public class FanQieSignService {

    private AndroidEmulator emulator;
    private Module module;
    private final long SUB_498434_OFFSET = 0x498434;
    private File tempSoFile;
    private volatile boolean initialized = false;

    @PostConstruct
    public void init() {
        try {
            System.out.println("[FanQieSign] Initializing...");

            // 创建 64 位模拟器
            emulator = AndroidEmulatorBuilder.for64Bit().build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            // 从 classpath 加载 libsscronet.so
            InputStream soStream = getClass().getClassLoader().getResourceAsStream("libsscronet.so");
            if (soStream == null) {
                soStream = getClass().getResourceAsStream("/libsscronet.so");
            }
            if (soStream == null) {
                throw new RuntimeException("libsscronet.so not found in classpath");
            }
            tempSoFile = File.createTempFile("libsscronet", ".so");
            tempSoFile.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempSoFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = soStream.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
            soStream.close();
            System.out.println("[FanQieSign] Extracted .so to: " + tempSoFile.getAbsolutePath());

            // 加载 .so 文件
            module = memory.load(tempSoFile);
            System.out.println("[FanQieSign] libsscronet.so loaded at base: 0x" + Long.toHexString(module.base));
            initialized = true;
        } catch (Throwable t) {
            System.err.println("[FanQieSign] Initialization FAILED: " + t.getMessage());
            t.printStackTrace();
            initialized = false;
        }
    }

    public String sign(String headersStr) {
        if (!initialized) {
            return "{\"error\":\"service not initialized\"}";
        }

        MemoryBlock inputBlock = null;
        MemoryBlock deviceBlock = null;
        MemoryBlock outputBlock = null;

        try {
            // 1. 准备输入字符串（a1 参数）
            byte[] inputBytes = headersStr.getBytes(StandardCharsets.UTF_8);
            inputBlock = emulator.getMemory().malloc(inputBytes.length + 1, false);
            UnidbgPointer inputPtr = inputBlock.getPointer();
            inputPtr.write(0, inputBytes, 0, inputBytes.length);
            inputPtr.setByte(inputBytes.length, (byte) 0);

            // 2. 构造设备信息结构体（a2 参数）
            // 根据逆向报告，a2 指向一个包含 "ee.info" 等信息的结构体。
            // 这里简单模拟：分配一块内存，写入一个字符串 "ee.info=test&app_id=1967"
            String deviceInfo = "ee.info=test_device&app_id=1967";
            byte[] deviceBytes = deviceInfo.getBytes(StandardCharsets.UTF_8);
            deviceBlock = emulator.getMemory().malloc(deviceBytes.length + 1, false);
            UnidbgPointer devicePtr = deviceBlock.getPointer();
            devicePtr.write(0, deviceBytes, 0, deviceBytes.length);
            devicePtr.setByte(deviceBytes.length, (byte) 0);
            System.out.println("[FanQieSign] Device info written at: " + devicePtr);

            // 3. 分配输出缓冲区（a3 参数）
            outputBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outputPtr = outputBlock.getPointer();
            System.out.println("[FanQieSign] Output buffer at: " + outputPtr);

            // 4. 调用 sub_498434
            Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                    inputPtr,
                    devicePtr,
                    outputPtr);
            System.out.println("[FanQieSign] sub_498434 returned: " + ret);

            // 5. 读取输出缓冲区内容
            byte[] outBytes = outputPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);
            System.out.println("[FanQieSign] Output length: " + len + ", content: " + signature);

            Map<String, Object> result = new HashMap<>();
            result.put("x-gorgon", signature);
            return com.alibaba.fastjson.JSONObject.toJSONString(result);

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"error\":\"" + e.getMessage() + "\"}";
        } finally {
            if (inputBlock != null) inputBlock.free();
            if (deviceBlock != null) deviceBlock.free();
            if (outputBlock != null) outputBlock.free();
        }
    }

    @PreDestroy
    public void destroy() {
        if (emulator != null) {
            try {
                emulator.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (tempSoFile != null && tempSoFile.exists()) {
            tempSoFile.delete();
        }
    }
}
