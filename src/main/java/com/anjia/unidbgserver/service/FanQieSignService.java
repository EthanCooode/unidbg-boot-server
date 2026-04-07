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
import com.alibaba.fastjson.JSON;

@Service
public class FanQieSignService {

    private AndroidEmulator emulator;
    private Module module;
    private UnidbgPointer a1Ptr;          // 全局配置对象，通过 sub_47223C 获取
    private byte[] a2Template;             // 从资源文件加载的 a2 模板（二进制）
    private long origBase = 0x74e0202000L; // dump 时看到的 libsscronet.so 基址（根据你的日志修改）

    // 偏移量（根据你的 IDA 分析）
    private final long SUB_47223C_OFFSET = 0x47223C;
    private final long SUB_498434_OFFSET = 0x498434;
    private final long SUB_467CA0_OFFSET = 0x467CA0;
    private final long SUB_1F4C68_OFFSET = 0x1F4C68;

    private volatile boolean initialized = false;

    @PostConstruct
    public void init() {
        try {
            System.out.println("[FanQieSign] Initializing...");
            // 1. 创建模拟器
            emulator = AndroidEmulatorBuilder.for64Bit().build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            // 2. 加载 libsscronet.so
            InputStream soStream = getClass().getClassLoader().getResourceAsStream("libsscronet.so");
            if (soStream == null) soStream = getClass().getResourceAsStream("/libsscronet.so");
            if (soStream == null) throw new RuntimeException("libsscronet.so not found");
            File tempSoFile = File.createTempFile("libsscronet", ".so");
            tempSoFile.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempSoFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = soStream.read(buffer)) > 0) fos.write(buffer, 0, len);
            }
            soStream.close();
            module = memory.load(tempSoFile);
            System.out.println("[FanQieSign] .so loaded at base: 0x" + Long.toHexString(module.base));

            // 3. 获取全局配置对象 a1
            Number ctxPtrNum = module.callFunction(emulator, SUB_47223C_OFFSET);
            long ctxPtr = ctxPtrNum.longValue();
            a1Ptr = UnidbgPointer.pointer(emulator, ctxPtr);
            System.out.println("[FanQieSign] Global a1 at: 0x" + Long.toHexString(a1Ptr.peer));

            // 4. 加载 a2 模板文件（从 resources 读取）
            InputStream tmplStream = getClass().getClassLoader().getResourceAsStream("a2_template.bin");
            if (tmplStream == null) throw new RuntimeException("a2_template.bin not found in resources");
            a2Template = tmplStream.readAllBytes();
            tmplStream.close();
            System.out.println("[FanQieSign] Loaded a2 template, size=" + a2Template.length + " bytes");

            initialized = true;
            System.out.println("[FanQieSign] Initialization completed!");
        } catch (Throwable t) {
            System.err.println("[FanQieSign] Init FAILED: " + t.getMessage());
            t.printStackTrace();
            initialized = false;
        }
    }

    /**
     * 从模板复制一份新的 a2 内存块，并进行指针重定位
     * @return 新分配的 a2 指针（需要调用者负责释放）
     */
    private UnidbgPointer createA2FromTemplate() {
        // 分配足够的内存
        MemoryBlock block = emulator.getMemory().malloc(a2Template.length, false);
        UnidbgPointer ptr = block.getPointer();
        ptr.write(0, a2Template, 0, a2Template.length);
        // 重定位指针（将模板中的绝对地址转换为当前模块基址）
        rebasePointers(ptr);
        // 注意：这里没有自动释放 block，需要调用者记录并在使用后 free
        // 为了方便，我们返回 ptr 并附带 block 引用？可以另外存储。简化起见，我们相信调用者会自己释放。
        // 实际使用中，可以在 sign 方法中分配，并在方法结束前 free。
        return ptr;
    }

    /**
     * 对 a2 内存块中所有指向原 libsscronet.so 地址的指针进行重定位
     * @param a2Ptr 指向 a2 结构体起始的指针
     */
    private void rebasePointers(UnidbgPointer a2Ptr) {
        long newBase = module.base;
        // 遍历每个 8 字节对齐的位置（0x0 到 0x2000，步长 8）
        for (int offset = 0; offset + 8 <= a2Template.length; offset += 8) {
            long val = a2Ptr.getLong(offset);
            if (val >= origBase && val < origBase + 0x2000000) { // 假设 so 大小不超过 32MB
                long newVal = val - origBase + newBase;
                a2Ptr.setLong(offset, newVal);
                System.out.println("[Rebase] 0x" + Long.toHexString(val) + " -> 0x" + Long.toHexString(newVal));
            }
        }
    }

    /**
     * 创建字符串对象（短字符串优化）
     */
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
        // 注意：这里分配的内存没有释放，在实际使用中建议缓存或使用后释放，但为了简单暂时不管（Unidbg 会在虚拟机退出时释放）
        return ptr;
    }

    /**
     * 向指定的 a2 对象添加一个 HTTP 头部
     * @param a2Ptr 目标 a2 指针
     * @param key 头部名称
     * @param value 头部值
     */
    private void addHeader(UnidbgPointer a2Ptr, String key, String value) {
        UnidbgPointer keyObj = createStringObject(key);
        UnidbgPointer valueObj = createStringObject(value);
        module.callFunction(emulator, SUB_467CA0_OFFSET, a2Ptr.peer, keyObj.peer, valueObj.peer, 0L);
        System.out.println("[FanQieSign] Added header: " + key + "=" + value);
    }

    /**
     * 解析多行头部字符串并添加到 a2
     * @param a2Ptr 目标 a2 指针
     * @param headersStr 格式如 "key1:value1\nkey2:value2\n..."
     */
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
     * 对外暴露的签名接口
     * @param headersStr 需要参与签名的 HTTP 头部字符串（多行）
     * @return JSON 格式的签名结果，如 {"x-gorgon":"..."}
     */
    public String sign(String headersStr) {
        if (!initialized) return "{\"error\":\"service not initialized\"}";
        MemoryBlock a2Block = null;
        MemoryBlock outputBlock = null;
        try {
            // 1. 从模板复制一份新的 a2
            a2Block = emulator.getMemory().malloc(a2Template.length, false);
            UnidbgPointer a2Ptr = a2Block.getPointer();
            a2Ptr.write(0, a2Template, 0, a2Template.length);
            rebasePointers(a2Ptr); // 重定位指针

            // 2. 添加动态头部
            parseAndAddHeaders(a2Ptr, headersStr);

            // 3. 分配输出缓冲区
            outputBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outputPtr = outputBlock.getPointer();

            // 4. 调用签名函数
            Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                    a1Ptr.peer, a2Ptr.peer, outputPtr.peer);
            System.out.println("[FanQieSign] sub_498434 returned: " + ret);

            // 5. 读取签名结果（以 null 结尾的字符串）
            byte[] outBytes = outputPtr.getByteArray(0, 512);
            int len = 0;
            while (len < outBytes.length && outBytes[len] != 0) len++;
            String signature = new String(outBytes, 0, len, StandardCharsets.UTF_8);

            // 6. 构造返回 JSON
            Map<String, String> result = new HashMap<>();
            result.put("x-gorgon", signature);
            // 如果有其他头部（如 x-argus, x-ladon）也可从 a2 中读取，但 sub_498434 只输出 x-gorgon
            // 根据你的需求，可能还需要调用 sub_40C07C 设置其他头部，但这里先只返回 x-gorgon
            return JSON.toJSONString(result);
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"error\":\"" + e.getMessage() + "\"}";
        } finally {
            if (a2Block != null) a2Block.free();
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
    }
}
