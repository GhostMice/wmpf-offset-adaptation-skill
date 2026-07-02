---
name: wmpf-offset-adaptation
description: >-
  Extract WMPF flue.dll Frida hook offsets (LoadStartHookOffset, CDPFilterHookOffset,
  SceneOffsets) for Nebula/X Debugger addresses.{version}.json. Use when the user sees
  version config 404, upstream addresses missing, WMPF adaptation, 偏移适配, flue.dll
  reverse, or asks to add a new WMPF version.
---

# WMPF 偏移适配（flue.dll）

为 `frida/config/addresses.{version}.json` 生成三项偏移。WMPF ≥ 13331 目标模块为 `flue.dll`（ImageBase 通常为 `0x180000000`）。

## 快速流程

1. **定位 flue.dll**
   ```
   %APPDATA%\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\{version}\extracted\runtime\flue.dll
   ```
2. **优先跑自动化脚本**（无需 IDA）：
   ```bash
   python scripts/extract_wmpf_offsets.py --version 25047 --dll "C:\...\flue.dll"
   ```
   脚本位于本 Skill 目录下的 `scripts/`。
3. **写入配置**：
   ```bash
   python scripts/extract_wmpf_offsets.py --version 25047 --write --config-dir path/to/frida/config
   ```
4. **验证**：重启调试器 → 等 `script loaded` → 再开小程序 → DevTools 连 `ws://127.0.0.1:62000`

## 输出格式

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x........",
    "CDPFilterHookOffset": "0x........",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

值为 **RVA**（相对 ImageBase），不是 VA。

## 三项偏移含义

| 字段 | hook.js 行为 | 定位要点 |
|------|-------------|----------|
| `CDPFilterHookOffset` | `patchCDPFilter` 挂在过滤器子函数 | 搜 `SendToClientFilter` → 引用它的 `.pdata` 函数 → **该函数第一条 `E8` call** 的目标 |
| `LoadStartHookOffset` | `patchOnLoadStart` 挂在 `AppletIndexContainer::OnLoadStart` 入口（`rcx`=this，`dl`=bool） | 搜同时引用 `applet_index_container.cc` 与 `AppletIndexContainer::OnLoadStart(bool` 的 `.pdata` 函数入口 |
| `SceneOffsets` | `hookOnLoadScene` 六段指针链后改 scene 为 1101 | 从 OnLoadStart 尾部 `call` 跟入子函数，找 `cmp dword ptr [reg+0x1C8], 0x44D`（1101）反推链 |

`SceneOffsets` 语义（与 `hook.js` 一致）：

```
p1  = read(this + [0])
p2  = read(p1 + [1])          // miniappConfigPtr
p3  = read(p2 + [2])
p4  = read(p3 + [3])
p5  = read(p4 + [4])
scene_addr = p5 + [5]           // 最后一个是字段偏移，不再 readPointer
```

## 方法选择

| 方法 | 何时用 |
|------|--------|
| **脚本 + .pdata**（推荐） | 默认；不依赖 IDA GUI |
| **IDA + idalib-mcp** | 脚本失败或需人工确认；IDA 已开 DLL 时先 **Plugins → MCP** |
| **手工** | 对照 WMPFDebugger 仓库的 `ADAPTATION.md` |

### IDA MCP 注意

- Cursor 配置 `idalib-mcp`（stdio）
- GUI 已打开 `flue.dll` 时 headless `idb_open` 会失败（`.id0` 被锁）→ 在 IDA 里启动 MCP 插件，或关闭 IDA 后 headless 分析
- 激活 idalib：`python "<IDA_DIR>\idalib\python\py-activate-idalib.py" -d "<IDA_DIR>"`

## 常见陷阱

1. **勿 hook 通用 `OnLoadStart` 日志桩**（~0x16C 大小、路径为 `music_player_window.cc` 等）—— 要选 `applet_index_container.cc` 那个。
2. **勿把 `0x441FB00` 一类字符串 helper 当成 CDP** —— CDP 是 SendToClientFilter 父函数的首个 `E8`，不是字符串 `call`。
3. **`SceneOffsets` 不能照搬旧版本** —— 20005 为 `[64,1480,8,1416,16,456]`，25047 为 `[64,1488,8,1424,16,456]`。
4. **plain `OnLoadStart` 字符串有 5+ 处 xref**，多数是非 applet 的 perf 日志包装。

## 参考版本（25047 实测）

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x29EF320",
    "CDPFilterHookOffset": "0x3859AE0",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

## 失败排查

| 现象 | 处理 |
|------|------|
| `上游配置不存在 404` | 本地补 `addresses.{version}.json` |
| 注入无 `script loaded` | 偏移错误；重跑脚本或 IDA 复核 |
| `unable to intercept` | 可能 CET/地址错；核对 `.pdata` 函数入口 |
| scene 不生效 | 单独重算 `SceneOffsets` |

## 附加资源

- 脚本实现细节：[reference.md](reference.md)
- 安装说明：见 [README.md](../../README.md)
