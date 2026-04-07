package com.anjia.unidbgserver.service;

import com.alibaba.fastjson.JSONObject;
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
import java.io.ByteArrayOutputStream;
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
    private byte[] a1Template;
    private byte[] a2Template;

    // 函数偏移
    private final long SUB_498434_OFFSET = 0x498434;
    private final long SUB_467CA0_OFFSET = 0x467CA0;

    // 真机中 libsscronet.so 的基址（用于指针重定位）
    private final long ORIG_BASE = 0x74e0202000L;

    private volatile boolean initialized = false;

    @PostConstruct
    public void init() {
        try {
            System.out.println("[FanQieSign] Initializing...");
            emulator = AndroidEmulatorBuilder.for64Bit().build();
            emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

            // 加载 libsscronet.so
            InputStream soStream = getClass().getClassLoader().getResourceAsStream("libsscronet.so");
            if (soStream == null) soStream = getClass().getResourceAsStream("/libsscronet.so");
            if (soStream == null) throw new RuntimeException("libsscronet.so not found");
            File tempSoFile = File.createTempFile("libsscronet", ".so");
            tempSoFile.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempSoFile)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = soStream.read(buf)) > 0) fos.write(buf, 0, len);
            }
            soStream.close();
            module = emulator.getMemory().load(tempSoFile);
            System.out.println("[FanQieSign] .so base: 0x" + Long.toHexString(module.base));

            // 加载 a1 模板
            InputStream a1Stream = getClass().getClassLoader().getResourceAsStream("a1_template.bin");
            if (a1Stream == null) throw new RuntimeException("a1_template.bin not found");
            a1Template = readAllBytes(a1Stream);
            System.out.println("[FanQieSign] a1 template size: " + a1Template.length);

            // 加载 a2 模板
            InputStream a2Stream = getClass().getClassLoader().getResourceAsStream("a2_template.bin");
            if (a2Stream == null) throw new RuntimeException("a2_template.bin not found");
            a2Template = readAllBytes(a2Stream);
            System.out.println("[FanQieSign] a2 template size: " + a2Template.length);

            initialized = true;
            System.out.println("[FanQieSign] Initialization completed!");
        } catch (Throwable t) {
            t.printStackTrace();
            initialized = false;
        }
    }

    private byte[] readAllBytes(InputStream is) throws java.io.IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    // 重定位指针：将原真机地址转换为 Unidbg 中的地址
    private void rebasePointers(UnidbgPointer ptr, int size) {
        long newBase = module.base;
        int limit = Math.min(size, 0x2000);
        for (int off = 0; off + 8 <= limit; off += 8) {
            long val = ptr.getLong(off);
            if (val >= ORIG_BASE && val < ORIG_BASE + 0x2000000) {
                long newVal = val - ORIG_BASE + newBase;
                ptr.setLong(off, newVal);
                System.out.printf("[Rebase] 0x%04x: 0x%x -> 0x%x\n", off, val, newVal);
            }
        }
    }

    // 创建 std::string 对象
    private UnidbgPointer createStringObject(String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        int len = data.length;
        MemoryBlock block;
        UnidbgPointer ptr;
        if (len <= 22) {
            block = emulator.getMemory().malloc(24, false);
            ptr = block.getPointer();
            ptr.write(0, data, 0, len);
            ptr.setByte(len, (byte) 0);
            ptr.setByte(23, (byte) len);
        } else {
            block = emulator.getMemory().malloc(32, false);
            ptr = block.getPointer();
            MemoryBlock dataBlock = emulator.getMemory().malloc(len + 1, false);
            UnidbgPointer dataPtr = dataBlock.getPointer();
            dataPtr.write(0, data, 0, len);
            dataPtr.setByte(len, (byte) 0);
            ptr.setPointer(0, dataPtr);
            ptr.setLong(8, len);
            ptr.setByte(23, (byte) 0x80);
        }
        return ptr;
    }

    private void addHeader(UnidbgPointer a2Ptr, String key, String value) {
        UnidbgPointer keyObj = createStringObject(key);
        UnidbgPointer valueObj = createStringObject(value);
        module.callFunction(emulator, SUB_467CA0_OFFSET, a2Ptr.peer, keyObj.peer, valueObj.peer, 0L);
        System.out.println("[AddHeader] " + key + ": " + value);
    }

    private void parseAndAddHeaders(UnidbgPointer a2Ptr, String headersStr) {
        if (headersStr == null || headersStr.isEmpty()) return;
        for (String line : headersStr.split("\n")) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                addHeader(a2Ptr, key, value);
            }
        }
    }

    public String sign(String headersStr) {
        if (!initialized) return "{\"error\":\"service not initialized\"}";

        // 1. 从模板复制新的 a1
        MemoryBlock a1Block = emulator.getMemory().malloc(a1Template.length, false);
        UnidbgPointer a1Copy = a1Block.getPointer();
        a1Copy.write(0, a1Template, 0, a1Template.length);
        rebasePointers(a1Copy, a1Template.length);

        // 2. 从模板复制新的 a2
        MemoryBlock a2Block = emulator.getMemory().malloc(a2Template.length, false);
        UnidbgPointer a2Copy = a2Block.getPointer();
        a2Copy.write(0, a2Template, 0, a2Template.length);
        rebasePointers(a2Copy, a2Template.length);

        // 3. 清空头部数组（让 sub_467CA0 重新分配）
        a2Copy.setPointer(0x4D8, UnidbgPointer.pointer(emulator, 0L));
        a2Copy.setPointer(0x4E0, UnidbgPointer.pointer(emulator, 0L));
        a2Copy.setPointer(0x4E8, UnidbgPointer.pointer(emulator, 0L));

        // 4. 添加本次请求的头部
        parseAndAddHeaders(a2Copy, headersStr);

        // 5. 输出缓冲区
        MemoryBlock outBlock = emulator.getMemory().malloc(512, false);
        UnidbgPointer outPtr = outBlock.getPointer();

        // 6. 调用签名函数
        Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                a1Copy.peer, a2Copy.peer, outPtr.peer);
        System.out.println("[sub_498434] returned " + ret);

        // 7. 读取签名结果
        byte[] outBytes = outPtr.getByteArray(0, 512);
        int len = 0;
        while (len < outBytes.length && outBytes[len] != 0) len++;
        String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

        // 8. 释放临时内存
        a1Block.free();
        a2Block.free();
        outBlock.free();

        Map<String, String> result = new HashMap<>();
        result.put("x-gorgon", signature);
        return JSONObject.toJSONString(result);
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
    }
}
