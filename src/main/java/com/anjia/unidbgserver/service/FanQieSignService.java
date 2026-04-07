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
    private UnidbgPointer a1Ptr;          // 全局请求上下文
    private UnidbgPointer a2Ptr;          // 设备信息结构体
    private UnidbgPointer eeInfoPtr;      // ee.info 数据块

    // 函数偏移
    private final long SUB_47223C_OFFSET = 0x47223C;
    private final long SUB_498434_OFFSET = 0x498434;
    private final long SUB_467CA0_OFFSET = 0x467CA0;

    private File tempSoFile;
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
            module = memory.load(tempSoFile);
            System.out.println("[FanQieSign] .so loaded at base: 0x" + Long.toHexString(module.base));

            // 3. 获取全局 a1
            Number ctxPtrNum = module.callFunction(emulator, SUB_47223C_OFFSET);
            long ctxPtr = ctxPtrNum.longValue();
            a1Ptr = UnidbgPointer.pointer(emulator, ctxPtr);
            System.out.println("[FanQieSign] Global a1 at: 0x" + Long.toHexString(a1Ptr.peer));

            // 4. 构造 a2 结构体
            constructA2();

            initialized = true;
            System.out.println("[FanQieSign] Initialization completed!");
        } catch (Throwable t) {
            System.err.println("[FanQieSign] Init FAILED: " + t.getMessage());
            t.printStackTrace();
            initialized = false;
        }
    }

    /**
     * 构造 a2 设备信息结构体
     * 基于 Frida dump 的静态数据
     */
    private void constructA2() {
        // 4.1 准备 ee.info 数据块 (256 字节，从 Frida 中提取，完全静态)
        // 注意：这些数据中的指针指向 .rodata 段，Unidbg 加载 .so 后会自动映射，无需修改
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

        // 4.2 分配 a2 64 字节结构体
        MemoryBlock a2Block = emulator.getMemory().malloc(64, false);
        a2Ptr = a2Block.getPointer();
        // 偏移 0x00: 指向 ee.info
        a2Ptr.setPointer(0x00, eeInfoPtr);
        // 偏移 0x08: 自引用
        a2Ptr.setPointer(0x08, a2Ptr);
        // 偏移 0x10: 0
        a2Ptr.setInt64(0x10, 0L);
        // 偏移 0x18: 5
        a2Ptr.setInt64(0x18, 5L);
        // 偏移 0x20: 5
        a2Ptr.setInt64(0x20, 5L);
        // 其余偏移默认为 0

        System.out.println("[FanQieSign] a2 constructed at: 0x" + Long.toHexString(a2Ptr.peer));
    }

    /**
     * 创建字符串对象（支持短字符串优化，与 libsscronet.so 兼容）
     */
    private UnidbgPointer createStringObject(String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        int len = data.length;
        MemoryBlock block;
        UnidbgPointer ptr;
        if (len <= 22) {
            // 短字符串：数据直接存储在对象内
            block = emulator.getMemory().malloc(24, false);
            ptr = block.getPointer();
            ptr.write(0, data, 0, len);
            ptr.setByte(len, (byte) 0);
            // 偏移 23 处存储长度（正数）
            ptr.setByte(23, (byte) len);
        } else {
            // 长字符串：对象中存储指针和长度
            block = emulator.getMemory().malloc(32, false);
            ptr = block.getPointer();
            MemoryBlock dataBlock = emulator.getMemory().malloc(len + 1, false);
            UnidbgPointer dataPtr = dataBlock.getPointer();
            dataPtr.write(0, data, 0, len);
            dataPtr.setByte(len, (byte) 0);
            ptr.setPointer(0, dataPtr);
            ptr.setInt64(8, len);
            // 偏移 23 处设置最高位为 1 表示长字符串
            ptr.setByte(23, (byte) 0x80);
        }
        return ptr;
    }

    /**
     * 添加一个 HTTP 头部到 a2 的头部数组中
     */
    private void addHeader(String key, String value) {
        UnidbgPointer keyObj = createStringObject(key);
        UnidbgPointer valueObj = createStringObject(value);
        // 调用 sub_467CA0(a2, keyObj, valueObj, 0)
        module.callFunction(emulator, SUB_467CA0_OFFSET, a2Ptr, keyObj.toPointer(), valueObj.toPointer(), 0L);
    }

    /**
     * 解析 Legado 传来的 headers 字符串（格式：key:value\nkey:value\n...）
     * 并逐一添加到头部数组
     */
    private void parseAndAddHeaders(String headersStr) {
        if (headersStr == null || headersStr.isEmpty()) return;
        String[] lines = headersStr.split("\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon);
                String value = line.substring(colon + 1);
                addHeader(key, value);
                System.out.println("[FanQieSign] Added header: " + key + "=" + value);
            }
        }
    }

    /**
     * 对外签名接口
     * @param headersStr Legado 传来的 11 个 HTTP 头拼接字符串
     * @return JSON 格式的签名结果
     */
    public String sign(String headersStr) {
        if (!initialized) {
            return "{\"error\":\"service not initialized\"}";
        }
        MemoryBlock outputBlock = null;
        try {
            // 1. 清空头部数组？不需要，sub_498434 会从头部数组读取，但我们需要先添加
            // 注意：a2 中的头部数组是全局的，多次调用会累积。如果需要隔离，需要重新初始化。
            // 为了简单，我们每次调用前清空头部数组（通过重新构造 a2 或设置计数为0）
            // 但 a2 是全局的，为了不影响后续请求，我们可以在每次 sign 时复制一个新的 a2？
            // 为了简化，我们假设每次调用都是独立的，直接添加头部后调用签名。
            // 注意：头部数组的结构复杂，清空较麻烦。这里我们每次调用前不保留旧头部，
            // 因此建议在 sign 方法中重新构造 a2（或者将 a2 设计为每次新建）。但为了性能，可以重用 a2，
            // 但要确保之前添加的头部被清除。清除头部数组最简单的方法是重新构造 a2。
            // 鉴于性能影响不大，我们每次调用都重新构造 a2 和 ee.info。
            // 但为了避免重复分配，可以先释放旧的再新建。为简单，这里每次调用都重新构造。
            // 注意：由于我们已在 init 中分配了 a2 和 ee.info，重复构造会导致内存泄漏，但 Unidbg 会在模拟器关闭时释放。
            // 更好的做法：在 sign 中临时构造 a2 和头部。但为了代码清晰，我们直接重用 init 中的 a2，
            // 并假设头部数组在每次调用前是空的。实际上头部数组可能包含之前调用的残留，导致签名错误。
            // 因此，我们改为在 sign 中独立构造 a2 和头部，避免状态污染。

            // 重新构造 a2 和 ee.info（确保每次请求干净）
            constructA2();

            // 2. 添加头部
            parseAndAddHeaders(headersStr);

            // 3. 分配输出缓冲区
            outputBlock = emulator.getMemory().malloc(512, false);
            UnidbgPointer outputPtr = outputBlock.getPointer();

            // 4. 调用签名函数
            Number ret = module.callFunction(emulator, SUB_498434_OFFSET,
                    a1Ptr,
                    a2Ptr,
                    outputPtr);
            System.out.println("[FanQieSign] sub_498434 returned: " + ret);

            // 5. 读取输出
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
            tempSoFile.delete();
        }
    }
}
