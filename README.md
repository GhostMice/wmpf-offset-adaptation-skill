# wmpf-offset-adaptation

WMPF Frida 偏移自动提取 Skill，适用于 [X Debugger](https://github.com/GhostMice/x-debugger) / [WMPFDebugger](https://github.com/evi0s/WMPFDebugger) 的 `addresses.{version}.json` 适配。

支持两个平台：

| 平台 | 目标模块 | 脚本 |
|------|----------|------|
| **Windows** | `flue.dll`（PE） | `extract_wmpf_offsets.py` |
| **macOS ARM64** | `WeChatAppEx Framework`（Mach-O） | `extract_wmpf_offsets_darwin.py` |

## 安装（Cursor Agent Skill）

任选一种方式：

**个人全局（推荐发布给用户）**

```bash
# 将整个 wmpf-offset-adaptation 文件夹复制到：
# Windows: %USERPROFILE%\.cursor\skills\wmpf-offset-adaptation\
# macOS/Linux: ~/.cursor/skills/wmpf-offset-adaptation/
```

目录结构应为：

```
~/.cursor/skills/wmpf-offset-adaptation/
├── SKILL.md
├── reference.md
├── reference-darwin.md
├── README.md
└── scripts/
    ├── extract_wmpf_offsets.py          # Windows
    └── extract_wmpf_offsets_darwin.py # macOS ARM64
```

**仅当前项目**

```bash
cp -r wmpf-offset-adaptation-skill/wmpf-offset-adaptation .cursor/skills/
```

复制后**重启 Cursor**，Agent 即可根据描述自动选用本 Skill。

## 依赖

**Windows**

```bash
pip install pefile capstone
```

**macOS**

```bash
pip install capstone
```

需要系统 `lipo`（Xcode Command Line Tools）。若 pip 遇 SSL 问题：

```bash
pip install capstone --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

## 快速使用

### Windows（flue.dll）

```bash
# 自动查找本机 WMPF 目录下的 flue.dll
python scripts/extract_wmpf_offsets.py --version 25047

# 指定 DLL 路径
python scripts/extract_wmpf_offsets.py --version 25047 --dll "C:\Users\你\AppData\Roaming\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\25047\extracted\runtime\flue.dll"

# 输出 JSON 到文件
python scripts/extract_wmpf_offsets.py --version 25047 --output addresses.25047.json

# 写入调试器项目的 config 目录
python scripts/extract_wmpf_offsets.py --version 25047 --write --config-dir path/to/frida/config
```

配置放入 `frida/config/addresses.25047.json`。

### macOS ARM64（WeChatAppEx Framework）

```bash
# 自动读取 CFBundleVersion，提取 arm64 切片并输出
python scripts/extract_wmpf_offsets_darwin.py \
  -o frida/config/darwin/addresses.6.25529.json

# 指定版本与 Framework 路径
python scripts/extract_wmpf_offsets_darwin.py \
  --version 6.25529 \
  --framework "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework" \
  -o addresses.6.25529.json
```

配置放入 `frida/config/darwin/addresses.{CFBundleVersion}.json`（WMPFDebugger darwin 布局）。

## 输出示例

**Windows WMPF 25047**

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x29ef320",
    "CDPFilterHookOffset": "0x3859ae0",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

**macOS WMPF 6.25529**

```json
{
    "Version": 6.25529,
    "LoadStartHookOffset": "0x5720430",
    "CDPFilterHookOffset": "0x92e76a8",
    "SceneOffsets": [56, 1552, 8, 1488, 16, 456]
}
```

值为 **RVA**（相对模块基址），不是 VA。darwin 的 `SceneOffsets[0]` 为 `56`，Windows 为 `64`，不可跨平台照搬。

## 验证

1. 将 JSON 复制到调试器对应 config 目录
2. 重启调试器
3. 先启动调试，等待日志出现 `script loaded`
4. 再打开微信小程序
5. 浏览器访问 `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000`

## 文件说明

| 文件 | 说明 |
|------|------|
| `SKILL.md` | Cursor Agent 技能主文件（含 Windows / macOS 流程） |
| `reference.md` | Windows PE / flue.dll 逆向算法 |
| `reference-darwin.md` | macOS ARM64 / WeChatAppEx Framework 逆向算法 |
| `scripts/extract_wmpf_offsets.py` | Windows：基于 PE `.pdata` |
| `scripts/extract_wmpf_offsets_darwin.py` | macOS：prologue 扫描 + ADRP/ADD xref |

## 发布

本文件夹可单独打包为 zip 或推送到独立 Git 仓库；用户只需将内含的 `wmpf-offset-adaptation` 目录放入 `~/.cursor/skills/` 即可。

## License

与 X Debugger / WMPFDebugger 适配流程相同，仅供学习与研究使用。
