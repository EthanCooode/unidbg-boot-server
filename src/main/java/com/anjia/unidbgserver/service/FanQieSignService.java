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
import java.io.IOException;          // <--- 这一行已包含
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
public class FanQieSignService {

    private AndroidEmulator emulator;
    private Module module;
    private final long SUB_498434_OFFSET = 0x498434;

    @PostConstruct
    public void init() throws Exception {
        emulator = AndroidEmulatorBuilder.for32Bit().build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        File soFile = new File("src/main/resources/libsscronet.so");
        if (!soFile.exists()) {
            throw new RuntimeException("libsscronet.so not found in src/main/resources/");
        }
        module = memory.load(soFile);
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
            if (inputBlock != null) {
                try {
                    inputBlock.free();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (outputBlock != null) {
                try {
                    outputBlock.free();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @PreDestroy
    public void destroy() {
        if (emulator != null) {
            emulator.close();
        }
    }
}
