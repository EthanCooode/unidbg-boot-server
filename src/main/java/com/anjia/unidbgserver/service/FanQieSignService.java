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
    private UnidbgPointer a1Ptr;
    private UnidbgPointer a2Ptr;
    private UnidbgPointer eeInfoPtr;

    private final long SUB_47223C_OFFSET = 0x47223C;
    private final long SUB_498434_OFFSET = 0x498434;
    private final long SUB_467CA0_OFFSET = 0x467CA0;

    private File tempSoFile;
    private volatile boolean initialized = false;

    private static final long ORIG_BASE = 0x74e0202000L;

    @PostConstruct
    public void init() {
        try {
            System.out.println("[FanQieSign] Initializing...");
            emulator = AndroidEmulatorBuilder.for64Bit().build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            InputStream soStream = getClass().getClassLoader().getResourceAsStream("libsscronet.so");
            if (soStream == null) soStream = getClass().getResourceAsStream("/libsscronet.so");
            if (soStream == null) throw new RuntimeException("libsscronet.so not found");
            tempSoFile = File.createTempFile("libsscronet", ".so");
            tempSoFile.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempSoFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = soStream.read(buffer)) > 0) fos.write(buffer, 0, len);
            }
            soStream.close();
            module = memory.load(tempSoFile);
            System.out.println("[FanQieSign] .so loaded at base: 0x" + Long.toHexString(module.base));

            Number ctxPtrNum = module.callFunction(emulator, SUB_47223C_OFFSET);
            long ctxPtr = ctxPtrNum.longValue();
            a1Ptr = UnidbgPointer.pointer(emulator, ctxPtr);
            System.out.println("[FanQieSign] Global a1 at: 0x" + Long.toHexString(a1Ptr.peer));

            constructA2();

            initialized = true;
            System.out.println("[FanQieSign] Initialization completed!");
        } catch (Throwable t) {
            System.err.println("[FanQieSign] Init FAILED: " + t.getMessage());
            t.printStackTrace();
            initialized = false;
        }
    }

    private long rebasePointer(long origPtr) {
        if (origPtr >= ORIG_BASE && origPtr < ORIG_BASE + 0x2000000) {
            return module.base + (origPtr - ORIG_BASE);
        }
        return origPtr;
    }

    private void constructA2() {
        byte[] eeInfoData = new byte[] {
            (byte)0x2c, (byte)0x49, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xd4, (byte)0x4d, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x74, (byte)0x98, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xcc, (byte)0x98, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xe0, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte)0xbc, (byte)0x4d, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x00, (byte)0x4e, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xc0, (byte)0x98, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xd0, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte)0xc8, (byte)0x4d, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x0c, (byte)0x4e, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x48, (byte)0x99, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x14, (byte)0xb2, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x20, (byte)0xb3, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xd4, (byte)0xbe, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte)0x8c, 0x54, (byte)0x4c, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0x8c, 0x54, (byte)0x4c, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x64, (byte)0xc5, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x40, (byte)0x69, (byte)0x40, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x64, (byte)0xc6, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xa0, (byte)0xc6, (byte)0x60, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xe0, (byte)0xe2, (byte)0x3e, (byte)0xe0, 0x74, 0x00, 0x00, 0x00,
            (byte)0xe0, (byte)0xe2, (byte)0x3e, (byte)0xe0, 0x74, 0x00, 0x00, 0x00
        };

        MemoryBlock eeInfoBlock = emulator.getMemory().malloc(256, false);
        eeInfoPtr = eeInfoBlock.getPointer();
        eeInfoPtr.write(0, eeInfoData, 0, eeInfoData.length);
        System.out.println("[FanQieSign] ee.info at: 0x" + Long.toHexString(eeInfoPtr.peer));

        for (int offset = 0; offset < 256; offset += 8) {
            long val = eeInfoPtr.getLong(offset);
            long newVal = rebasePointer(val);
            if (newVal != val) {
                eeInfoPtr.setLong(offset, newVal);
                System.out.println("[FanQieSign] Rebased pointer at offset 0x" + Integer.toHexString(offset) +
                        ": 0x" + Long.toHexString(val) + " -> 0x" + Long.toHexString(newVal));
            }
        }

        MemoryBlock a2Block = emulator.getMemory().malloc(64, false);
        a2Ptr = a2Block.getPointer();
        a2Ptr.setPointer(0x00, eeInfoPtr);
        a2Ptr.setPointer(0x08, a2Ptr);
        a2Ptr.setLong(0x10, 0L);
        a2Ptr.setLong(0x18, 5L);
        a2Ptr.setLong(0x20, 5L);
        System.out.println("[FanQieSign] a2 constructed at: 0x" + Long.toHexString(a2Ptr.peer));
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

    private void addHeader(String key, String value) {
        UnidbgPointer keyObj = createStringObject(key);
        UnidbgPointer valueObj = createStringObject(value);
        module.callFunction(emulator, SUB_467CA0_OFFSET, a2Ptr.peer, keyObj.peer, valueObj.peer, 0L);
        System.out.println("[FanQieSign] Added header: " + key + "=" + value);
    }

    private void parseAndAddHeaders(String headersStr) {
        if (headersStr == null || headersStr.isEmpty()) return;
        String[] lines = headersStr.split("\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon);
                String value = line.substring(colon + 1);
                addHeader(key, value);
            }
        }
    }

    public String sign(String headersStr) {
        if (!initialized) return "{\"error\":\"service not initialized\"}";
        MemoryBlock outputBlock = null;
        try {
            constructA2();
            parseAndAddHeaders(headersStr);

            outputBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outputPtr = outputBlock.getPointer();

            Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                    a1Ptr.peer, a2Ptr.peer, outputPtr.peer);
            System.out.println("[FanQieSign] sub_498434 returned: " + ret);

            byte[] outBytes = outputPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            Map<String, Object> result = new HashMap<>();
            result.put("x-gorgon", signature);
            return com.alibaba.fastjson.JSONObject.toJSONString(result);
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"error\":\"" + e.getMessage() + "\"}";
        } finally {
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
            try {
                tempSoFile.delete();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
