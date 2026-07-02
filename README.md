# wmpf-offset-adaptation

WMPF `flue.dll` Frida 偏移自动提取 Skill，适用于 [X Debugger](https://github.com/GhostMice/x-debugger) / [WMPFDebugger](https://github.com/evi0s/WMPFDebugger) 的 `addresses.{version}.json` 适配。

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
├── README.md
└── scripts/
    └── extract_wmpf_offsets.py
```

**仅当前项目**

```bash
cp -r wmpf-offset-adaptation-skill/wmpf-offset-adaptation .cursor/skills/
```

复制后**重启 Cursor**，Agent 即可根据描述自动选用本 Skill。

## 依赖

```bash
pip install pefile capstone
```

## 快速使用

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

## 输出示例（WMPF 25047）

```json
{
    "Version": 25047,
    "LoadStartHookOffset": "0x29ef320",
    "CDPFilterHookOffset": "0x3859ae0",
    "SceneOffsets": [64, 1488, 8, 1424, 16, 456]
}
```

将生成的 `addresses.{version}.json` 放入：

- `x-debugger/frida/config/`
- 或 `frida/config/`（WMPFDebugger 仓库）

## 验证

1. 重启调试器
2. 先启动调试，等待日志出现 `script loaded`
3. 再打开微信小程序
4. 浏览器访问 `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000`

## 文件说明

| 文件 | 说明 |
|------|------|
| `SKILL.md` | Cursor Agent 技能主文件 |
| `reference.md` | 逆向算法与 IDA MCP 参考 |
| `scripts/extract_wmpf_offsets.py` | 基于 PE `.pdata` 的自动化提取脚本 |

## 发布

本文件夹可单独打包为 zip 或推送到独立 Git 仓库；用户只需将内含的 `wmpf-offset-adaptation` 目录放入 `~/.cursor/skills/` 即可。

## License

与 X Debugger / WMPFDebugger 适配流程相同，仅供学习与研究使用。
