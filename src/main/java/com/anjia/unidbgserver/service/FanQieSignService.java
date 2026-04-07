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
    private UnidbgPointer a1Ptr;          // 全局配置对象，单例
    private byte[] a2Template;            // 从真机 dump 的 a2 模板（二进制）
    private UnidbgPointer a2TemplatePtr;  // 模板在 Unidbg 中的原始内存指针（仅用于复制）

    // 函数偏移（根据 IDA 分析）
    private final long SUB_47223C_OFFSET = 0x47223C;   // 获取 a1
    private final long SUB_498434_OFFSET = 0x498434;   // 签名主函数
    private final long SUB_467CA0_OFFSET = 0x467CA0;   // 添加 HTTP 头部
    private final long SUB_1F4C68_OFFSET = 0x1F4C68;   // 创建字符串对象

    // 真机中 libsscronet.so 的基址（用于指针重定位）
    private final long ORIG_BASE = 0x74e0202000L;

    private volatile boolean initialized = false;

    @PostConstruct
    public void init() {
        try {
            System.out.println("[FanQieSign] Initializing...");
            // 1. 创建 64 位模拟器
            emulator = AndroidEmulatorBuilder.for64Bit().build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            // 2. 加载 libsscronet.so
            InputStream soStream = getClass().getClassLoader().getResourceAsStream("libsscronet.so");
            if (soStream == null) {
                soStream = getClass().getResourceAsStream("/libsscronet.so");
            }
            if (soStream == null) {
                throw new RuntimeException("libsscronet.so not found");
            }
            File tempSoFile = File.createTempFile("libsscronet", ".so");
            tempSoFile.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempSoFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = soStream.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
            soStream.close();
            module = memory.load(tempSoFile);
            System.out.println("[FanQieSign] .so loaded at base: 0x" + Long.toHexString(module.base));

            // 3. 获取全局配置对象 a1（单例，一次获取终身使用）
            Number ctxPtrNum = module.callFunction(emulator, SUB_47223C_OFFSET);
            long ctxPtr = ctxPtrNum.longValue();
            a1Ptr = UnidbgPointer.pointer(emulator, ctxPtr);
            System.out.println("[FanQieSign] Global a1 at: 0x" + Long.toHexString(a1Ptr.peer));

            // 4. 加载 a2 模板（从资源文件 a2_template.bin）
            InputStream tmplStream = getClass().getClassLoader().getResourceAsStream("a2_template.bin");
            if (tmplStream == null) {
                throw new RuntimeException("a2_template.bin not found in resources");
            }
            a2Template = readAllBytes(tmplStream);  // Java 8 兼容方法
            System.out.println("[FanQieSign] Loaded a2 template, size=" + a2Template.length);

            // 5. 将模板加载到模拟器内存中，作为原始模板（只读，不直接使用）
            MemoryBlock tmplBlock = emulator.getMemory().malloc(a2Template.length, false);
            a2TemplatePtr = tmplBlock.getPointer();
            a2TemplatePtr.write(0, a2Template, 0, a2Template.length);
            // 修正模板中的绝对指针（重定位）
            rebasePointers(a2TemplatePtr);

            initialized = true;
            System.out.println("[FanQieSign] Initialization completed!");
        } catch (Throwable t) {
            System.err.println("[FanQieSign] Init FAILED: " + t.getMessage());
            t.printStackTrace();
            initialized = false;
        }
    }

    // Java 8 兼容的 readAllBytes
    private byte[] readAllBytes(InputStream is) throws java.io.IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int nRead;
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    // 重定位指针：将模板中落在原 SO 地址范围内的 QWORD 替换为 Unidbg 中的新地址
    private void rebasePointers(UnidbgPointer ptr) {
        long newBase = module.base;
        // 只扫描前 0x2000 字节，避免越界（模板大小通常 8192）
        int limit = Math.min(a2Template.length, 0x2000);
        for (int offset = 0; offset + 8 <= limit; offset += 8) {
            long val = ptr.getLong(offset);
            if (val >= ORIG_BASE && val < ORIG_BASE + 0x2000000) { // 假设 SO 大小约 32MB
                long newVal = val - ORIG_BASE + newBase;
                ptr.setLong(offset, newVal);
                System.out.printf("[Rebase] 0x%08x: 0x%x -> 0x%x\n", offset, val, newVal);
            }
        }
    }

    // 创建字符串对象（兼容 Unidbg 的 std::string 格式）
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

    // 添加一个 HTTP 头部到指定的 a2 对象
    private void addHeader(UnidbgPointer a2Ptr, String key, String value) {
        UnidbgPointer keyObj = createStringObject(key);
        UnidbgPointer valueObj = createStringObject(value);
        module.callFunction(emulator, SUB_467CA0_OFFSET, a2Ptr.peer, keyObj.peer, valueObj.peer, 0L);
        System.out.println("[AddHeader] " + key + ": " + value);
    }

    // 解析 headersStr（格式：key:value\nkey:value...）并添加到 a2
    private void parseAndAddHeaders(UnidbgPointer a2Ptr, String headersStr) {
        if (headersStr == null || headersStr.isEmpty()) return;
        String[] lines = headersStr.split("\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                addHeader(a2Ptr, key, value);
            }
        }
    }

    /**
     * 对外签名接口
     * @param headersStr 请求头部字符串，格式 key:value 每行一个
     * @return JSON 包含 x-gorgon 等签名字段
     */
    public String sign(String headersStr) {
        if (!initialized) {
            return "{\"error\":\"service not initialized\"}";
        }

        // 1. 从模板复制一份新的 a2 内存块
        MemoryBlock a2Block = emulator.getMemory().malloc(a2Template.length, false);
        UnidbgPointer a2CopyPtr = a2Block.getPointer();
        a2CopyPtr.write(0, a2TemplatePtr.getByteArray(0, a2Template.length));

        // 2. 重定位新副本中的指针（因为副本是新内存，但指针值需要基于当前 module.base 重新计算）
        rebasePointers(a2CopyPtr);

        // 3. 清空 HTTP 头部数组（可选，如果模板中头部数组非空则需重置）
        //    更简单：直接调用 sub_467CA0 添加头部，它会自动处理重复/扩展。
        //    但为了防止旧数据残留，可以主动将 a2+0x4D8 处的三个指针清零，让 sub_467CA0 重新分配。
        //    根据 IDA 分析，头部数组在 a2+0x4D8 处是一个结构体 { begin, end, capacity }。
        //    我们可以将其全部置零，sub_467CA0 在第一次添加时会自动分配。
        a2CopyPtr.setPointer(0x4D8, UnidbgPointer.pointer(emulator, 0));
        a2CopyPtr.setPointer(0x4E0, UnidbgPointer.pointer(emulator, 0));
        a2CopyPtr.setPointer(0x4E8, UnidbgPointer.pointer(emulator, 0));

        // 4. 添加本次请求的头部
        parseAndAddHeaders(a2CopyPtr, headersStr);

        // 5. 分配输出缓冲区（512 字节足够）
        MemoryBlock outputBlock = emulator.getMemory().malloc(512, false);
        UnidbgPointer outputPtr = outputBlock.getPointer();

        // 6. 调用签名函数
        Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                a1Ptr.peer, a2CopyPtr.peer, outputPtr.peer);
        System.out.println("[sub_498434] returned " + ret);

        // 7. 读取签名结果（以 null 结尾的字符串）
        byte[] outBytes = outputPtr.getByteArray(0, 512);
        int len = 0;
        while (len < outBytes.length && outBytes[len] != 0) len++;
        String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

        // 8. 释放本次请求临时分配的内存（a2 副本和输出缓冲区）
        a2Block.free();
        outputBlock.free();

        // 9. 封装成 JSON 返回（目前只有 x-gorgon，后续可扩展）
        Map<String, String> result = new HashMap<>();
        result.put("x-gorgon", signature);
        // 如果有其他签名头（如 x-ladon, x-argus），sub_498434 的输出可能只有一个值，
        // 但实际 App 中这些头部是在 sub_40C07C 批量设置的。你可以根据后续分析补充。
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
