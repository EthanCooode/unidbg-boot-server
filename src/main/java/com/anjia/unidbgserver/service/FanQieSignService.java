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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Service
public class FanQieSignService {

    private AndroidEmulator emulator;
    private Module module;
    private byte[] a1Template;
    private byte[] a2Template;

    private final long SUB_498434_OFFSET = 0x498434;
    private final long SUB_467CA0_OFFSET = 0x467CA0;

    private final long ORIG_BASE = 0x74e0202000L;
    private volatile boolean initialized = false;

    @PostConstruct
    public void init() {
        try {
            System.out.println("[FanQieSign] Initializing...");
            emulator = AndroidEmulatorBuilder.for64Bit().build();
            emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

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

            InputStream a1Stream = getClass().getClassLoader().getResourceAsStream("a1_template.bin");
            if (a1Stream == null) throw new RuntimeException("a1_template.bin not found");
            a1Template = readAllBytes(a1Stream);
            System.out.println("[FanQieSign] a1 template size: " + a1Template.length);
            System.out.println("[FanQieSign] a1 first 16 bytes: " + Arrays.toString(Arrays.copyOf(a1Template, 16)));

            InputStream a2Stream = getClass().getClassLoader().getResourceAsStream("a2_template.bin");
            if (a2Stream == null) throw new RuntimeException("a2_template.bin not found");
            a2Template = readAllBytes(a2Stream);
            System.out.println("[FanQieSign] a2 template size: " + a2Template.length);
            System.out.println("[FanQieSign] a2 first 16 bytes: " + Arrays.toString(Arrays.copyOf(a2Template, 16)));

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

    // 精确重定位已知指针偏移
    private void rebasePointers(UnidbgPointer ptr, int size) {
        long newBase = module.base;
        int[] knownOffsets = {
            0x00, 0x08, 0x20, 0x28, 0x30, 0x58, 0x60, 0x78, 0x80, 0x90, 0xB0,
            0x4D8, 0x4E0, 0x4E8,
            0x1580, 0x15B0
        };
        for (int off : knownOffsets) {
            if (off + 8 > size) continue;
            long val = ptr.getLong(off);
            if (val >= ORIG_BASE && val < ORIG_BASE + 0x2000000) {
                long newVal = val - ORIG_BASE + newBase;
                ptr.setLong(off, newVal);
                System.out.printf("[Rebase] 0x%04x: 0x%x -> 0x%x\n", off, val, newVal);
            }
        }
    }

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

        MemoryBlock a1Block = null;
        MemoryBlock a2Block = null;
        MemoryBlock outBlock = null;
        try {
            a1Block = emulator.getMemory().malloc(a1Template.length, false);
            UnidbgPointer a1Copy = a1Block.getPointer();
            a1Copy.write(0, a1Template, 0, a1Template.length);
            rebasePointers(a1Copy, a1Template.length);

            a2Block = emulator.getMemory().malloc(a2Template.length, false);
            UnidbgPointer a2Copy = a2Block.getPointer();
            a2Copy.write(0, a2Template, 0, a2Template.length);
            rebasePointers(a2Copy, a2Template.length);

            // 注意：不再清空头部数组，保留模板中的初始元数据
            // 直接添加头部，sub_467CA0 会处理
            parseAndAddHeaders(a2Copy, headersStr);

            outBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outPtr = outBlock.getPointer();

            Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                    a1Copy.peer, a2Copy.peer, outPtr.peer);
            System.out.println("[sub_498434] returned " + ret);

            byte[] outBytes = outPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            Map<String, String> result = new HashMap<>();
            result.put("x-gorgon", signature);
            return JSONObject.toJSONString(result);

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"error\":\"" + e.getMessage() + "\"}";
        } finally {
            if (a1Block != null) a1Block.free();
            if (a2Block != null) a2Block.free();
            if (outBlock != null) outBlock.free();
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
    }
}
