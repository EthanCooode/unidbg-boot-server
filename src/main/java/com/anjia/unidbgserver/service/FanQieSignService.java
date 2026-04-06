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
    private File tempSoFile; // 临时文件引用，用于后续清理

    @PostConstruct
    public void init() throws Exception {
        // 1. 创建 32 位模拟器
        emulator = AndroidEmulatorBuilder.for32Bit().build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        // 2. 从 classpath 加载 libsscronet.so 并复制到临时文件
        InputStream soStream = getClass().getClassLoader().getResourceAsStream("libsscronet.so");
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

        // 3. 加载 .so 文件
        module = memory.load(tempSoFile);
        System.out.println("[FanQieSign] libsscronet.so loaded at base: 0x" + Long.toHexString(module.base));
    }

    public String sign(String headersStr) {
        MemoryBlock inputBlock = null;
        MemoryBlock outputBlock = null;
        try {
            byte[] inputBytes = headersStr.getBytes(StandardCharsets.UTF_8);
            inputBlock = emulator.getMemory().malloc(inputBytes.length + 1, false);
            UnidbgPointer inputPtr = inputBlock.getPointer();
            inputPtr.write(0, inputBytes, 0, inputBytes.length);
            inputPtr.setByte(inputBytes.length, (byte) 0);

            outputBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outputPtr = outputBlock.getPointer();

            module.callFunction(emulator, SUB_498434_OFFSET,
                    inputPtr,
                    UnidbgPointer.pointer(emulator, 0L),
                    outputPtr);

            byte[] outBytes = outputPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            Map<String, Object> result = new HashMap<>();
            result.put("x-gorgon", signature);
            return com.alibaba.fastjson.JSONObject.toJSONString(result);
        } catch (Exception e) {
            e.printStackTrace();
            return "{}";
        } finally {
            if (inputBlock != null) inputBlock.free();
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
