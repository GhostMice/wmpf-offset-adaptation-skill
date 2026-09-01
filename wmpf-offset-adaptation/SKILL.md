---
name: wmpf-offset-adaptation
description: >-
  Extract WMPF Frida hook offsets (LoadStartHookOffset, CDPFilterHookOffset,
  SceneOffsets) for Nebula/X Debugger addresses.{version}.json. Windows: flue.dll
  PE script. macOS ARM64: WeChatAppEx Framework Mach-O script. Use when version
  config 404, upstream addresses missing, WMPF adaptation, 偏移适配, flue.dll,
  WeChatAppEx Framework, or adding a new WMPF version.
---

# WMPF 偏移适配

为 `frida/config/addresses.{version}.json`（Windows）或 `frida/config/darwin/addresses.{version}.json`（macOS）生成三项偏移。

## 选择平台

| 平台 | 目标模块 | 脚本 | 版本号 |
|------|----------|------|--------|
| **Windows** | `flue.dll` | `scripts/extract_wmpf_offsets.py` | 整数，如 `25047` |
| **macOS ARM64** | `WeChatAppEx Framework` | `scripts/extract_wmpf_offsets_darwin.py` | `CFBundleVersion`，如 `6.25529` |

---

## Windows 快速流程

1. **定位 flue.dll**
   ```
   %APPDATA%\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\{version}\extracted\runtime\flue.dll
   ```
2. **跑自动化脚本**（无需 IDA）：
   ```bash
   python scripts/extract_wmpf_offsets.py --version 25047 --dll "C:\...\flue.dll"
   ```
3. **写入配置**：
   ```bash
   python scripts/extract_wmpf_offsets.py --version 25047 --write --config-dir path/to/frida/config
   ```
4. **验证**：重启调试器 → 等 `script loaded` → 再开小程序 → DevTools 连 `ws://127.0.0.1:62000`

Windows 定位要点：`.pdata` 函数边界 + x86 `E8 call` / `lea [rip+disp]`。详见 [reference.md](reference.md)。

---

## macOS 快速流程

1. **定位 WeChatAppEx Framework**（Universal Binary，脚本自动 `lipo -thin arm64`）：
   ```
   /Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/
   WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework
   ```
2. **跑自动化脚本**（自动读 `Info.plist` 的 `CFBundleVersion`）：
   ```bash
   python scripts/extract_wmpf_offsets_darwin.py -o frida/config/darwin/addresses.6.25529.json
   ```
3. **复制到 WMPFDebugger**：`frida/config/darwin/addresses.{version}.json`
4. **验证**：同上；Frida 模块名为 `Process.findModuleByName("WeChatAppEx Framework")`

macOS 定位要点：prologue 扫描 + `ADRP+ADD` 字符串 xref + 首条 `BL`。详见 [reference-darwin.md](reference-darwin.md)。

**勿在** `~/Library/Containers/com.tencent.xinWeChat` 找 flue.dll — Mac 无独立 flue 模块。

---

## 输出格式

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x........",
    "CDPFilterHookOffset": "0x........",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

值为 **RVA**（相对模块基址），不是 VA。

## 三项偏移含义

| 字段 | hook.js 行为 | Windows 定位 | macOS 定位 |
|------|-------------|-------------|-----------|
| `CDPFilterHookOffset` | `patchCDPFilter` | `SendToClientFilter` → `.pdata` 父函数 → 首条 `E8 call` | 同字符串 → prologue 父函数 → 首条 `BL` |
| `LoadStartHookOffset` | `patchOnLoadStart` | 同时引用 `applet_index_container.cc` 与 `AppletIndexContainer::OnLoadStart(bool` 的 `.pdata` 入口 | 同上字符串条件 + prologue 入口 |
| `SceneOffsets` | `hookOnLoadScene` 六段链 → scene 1101 | OnLoadStart 尾部 `call` → `cmp [reg+0x1C8], 0x44D` | OnLoadStart 尾部 `BL` → callee 内 `cmp #0x44d` |

`SceneOffsets` 语义（与 `hook.js` 一致）：

```
p1  = read(this + [0])
p2  = read(p1 + [1])
p3  = read(p2 + [2])
p4  = read(p3 + [3])
p5  = read(p4 + [4])
scene_addr = p5 + [5]           // 最后一个是字段偏移，不再 readPointer
```

**平台差异**：`SceneOffsets[0]` 在 Windows 通常为 `64 (0x40)`，darwin 为 `56 (0x38)`。

## 方法选择

| 方法 | 何时用 |
|------|--------|
| **自动化脚本**（推荐） | 默认；Windows 用 `.pdata`，macOS 用 prologue 扫描 |
| **IDA / Hopper** | 脚本失败或需人工确认 |
| **手工** | 对照 WMPFDebugger `ADAPTATION.md` |

### IDA MCP（Windows）

- Cursor 配置 `idalib-mcp`（stdio）
- GUI 已打开 `flue.dll` 时 headless `idb_open` 会失败 → 在 IDA 里启动 MCP 插件，或关闭 IDA 后 headless 分析

## 常见陷阱

1. **勿 hook 通用 `OnLoadStart` 日志桩**（`music_player_window.cc` 等）—— 要选 `applet_index_container.cc` 那个。
2. **勿把字符串 helper 当成 CDP** —— CDP 是 SendToClientFilter 父函数的首条 call/BL，不是字符串引用处的 call。
3. **`SceneOffsets` 不能照搬旧版本或跨平台** —— 见下方参考版本。
4. **macOS 版本号来自 CFBundleVersion**，配置文件名如 `addresses.6.25529.json`，不是 Windows 整数版本。

## 参考版本

**Windows 25047**

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x29EF320",
    "CDPFilterHookOffset": "0x3859AE0",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

**macOS 6.25529**

```json
{
    "Version": 6.25529,
    "LoadStartHookOffset": "0x5720430",
    "CDPFilterHookOffset": "0x92e76a8",
    "SceneOffsets": [56, 1552, 8, 1488, 16, 456]
}
```

**macOS 269136**（WMPFDebugger 仓库已有）

```json
{
    "Version": 269136,
    "LoadStartHookOffset": "0x4f744c4",
    "CDPFilterHookOffset": "0x8436b98",
    "SceneOffsets": [56, 1504, 8, 1440, 16, 456]
}
```

## 失败排查

| 现象 | 处理 |
|------|------|
| `上游配置不存在 404` | 本地补 `addresses.{version}.json` |
| 注入无 `script loaded` | 偏移错误；重跑对应平台脚本或 IDA 复核 |
| `unable to intercept` | 地址错；核对函数入口（Windows `.pdata` / macOS prologue） |
| scene 不生效 | 单独重算 `SceneOffsets` |
| macOS 脚本找不到字符串 | 确认 Framework 路径与微信版本；重跑 `lipo -thin arm64` |

## 附加资源

- Windows 算法：[reference.md](reference.md)
- macOS 算法：[reference-darwin.md](reference-darwin.md)
- 安装说明：[README.md](../../README.md)
