# WMPF 偏移提取 — macOS / ARM64 技术参考

Windows PE 版算法见 [reference.md](reference.md)。

## 目标模块

| 项 | 值 |
|---|---|
| 格式 | Universal Binary（需 `lipo -thin arm64` 提取切片） |
| 路径 | `/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework` |
| Frida 模块名 | `WeChatAppEx Framework` |
| 版本号来源 | `WeChatAppEx.app/Contents/Info.plist` → `CFBundleVersion`（如 `6.25529`） |
| 配置文件 | `frida/config/darwin/addresses.{CFBundleVersion}.json` |

偏移为相对模块基址的 **RVA**，不是 VA。

## 依赖

```bash
pip install capstone
```

不需要 `pefile`。需要系统自带 `lipo`（Xcode Command Line Tools）。

## 函数边界：prologue 扫描

Mach-O 无 Windows `.pdata`。脚本在 `__text` 段扫描 ARM64 函数序言：

- `stp x29, x30, [sp, #-imm]!`（`0xA9xx7BFD` 族）
- `stp x29, x30, [sp], #imm`（`0xA8xx7BFD` 族）

约 38 万函数，扫描约 15 秒。用 `bisect` 在 prologue 列表上定位包含某地址的函数 `[start, end)`。

`__unwind_info` 解析曾因 LLVM 格式复杂而失败，prologue 扫描更可靠。

## 字符串 xref：ADRP + ADD

ARM64 用 `ADRP` + `ADD` 取 PC-relative 地址，而非 x86 `lea [rip+disp]`：

1. 解码 `ADRP` 得目标页地址
2. 紧随其后的 `ADD` 加页内偏移
3. `page + add_imm == str_offset` 即为字符串 xref

## CDPFilterHookOffset 算法

1. 在二进制中搜 ASCII `SendToClientFilter`
2. `scan_adrp_add_xrefs` 得 xref 地址
3. prologue 扫描定位 xref 所在父函数 `[begin, end)`
4. 从 `begin` 起找**第一条 `BL`** 的目标 → `CDPFilterHookOffset`

6.25529 实例：父函数 `0x92f1a64` → 首条 `BL #0x92e76a8`。

## LoadStartHookOffset 算法

1. 扫描所有 `ADRP+ADD` 字符串引用
2. 读取目标字符串，标记函数是否引用：
   - `applet_index_container.cc`
   - `AppletIndexContainer::OnLoadStart(bool`
3. 同时满足两者且 `size < 0x8000` 的函数 → `LoadStartHookOffset = begin`

6.25529 实例：`0x5720430`。

## SceneOffsets 算法

darwin 与 Windows 的 `[0]` 不同：**darwin 为 `56 (0x38)`，Windows 为 `64 (0x40)`**，不可跨平台照搬。

### OnLoadStart 尾部模式

在 OnLoadStart 反汇编中找：

```asm
ldp x8, x9, [x19, #0x38]    ; SceneOffsets[0] = 56
ldr x0, [x8, #0x610]       ; SceneOffsets[1] = 1552
bl  #scene_callee
```

### scene callee 内指针链

跟入 `BL` 目标，找 `cmp ... #0x44d`（scene 1101），反推链：

```asm
ldr x8, [x0, #8]           ; [2] = 8
ldr x9, [x8, #0x5d0]       ; [3] = 1488
ldr x9, [x9, #0x10]        ; [4] = 16
ldr w9, [x9, #0x1c8]       ; [5] = 456
cmp w9, #0x44d
```

6.25529 结果：`[56, 1552, 8, 1488, 16, 456]`。

## capstone 注意

- 立即数可能显示为 `#8` 而非 `#0x8`；解析用 `IMM_RE = re.compile(r"#(?:0x)?([0-9a-f]+)")`
- `BL` 的 `op_str` 可能是 `#0x92e76a8`，需 `lstrip("#")` 后 `int(..., 16)`

## 邻近版本 SceneOffsets 趋势（darwin）

| 版本 | SceneOffsets |
|------|----------------|
| 269136 | [56, 1504, 8, 1440, 16, 456] |
| 6.25529 | [56, 1552, 8, 1488, 16, 456] |

仅作校验参考，**必须以目标 Framework 反汇编为准**。

## 常见陷阱（darwin）

1. **勿在 `~/Library/Containers/com.tencent.xinWeChat` 里找 flue.dll** — Mac 无独立 flue，代码在 App bundle 的 `WeChatAppEx Framework` 内。
2. **Universal Binary 必须先 thin arm64** — 脚本默认用 `lipo -thin arm64`；Apple Silicon 上跑的是 arm64 切片。
3. **版本号文件名用 CFBundleVersion** — 如 `addresses.6.25529.json`，不是 Windows 的整数 `25047`。
4. **SceneOffsets[0] 是 56 不是 64** — 与 Windows hook 链布局不同。

## IDA / Hopper 手工复核

对照 WMPFDebugger 仓库 `ADAPTATION.md`，在 `WeChatAppEx Framework`（arm64）中：

1. 搜 `SendToClientFilter` → 父函数首条 `BL`
2. 搜 `AppletIndexContainer::OnLoadStart(bool` + `applet_index_container.cc` 同函数
3. OnLoadStart 尾部跟 scene `BL`， callee 内找 `cmp #0x44d`
