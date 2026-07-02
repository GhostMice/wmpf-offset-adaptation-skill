# WMPF 偏移提取 — 技术参考

## 依赖

```bash
pip install pefile capstone
```

## .pdata 解析

x64 Windows DLL 的 `RUNTIME_FUNCTION` 表（`.pdata`）每项 12 字节：`BeginRVA, EndRVA, UnwindRVA`。

用 `BeginRVA <= addr < EndRVA` 判定函数边界，比扫描 `0xCC` 填充可靠得多。

## CDPFilterHookOffset 算法

1. 在文件内搜 ASCII `SendToClientFilter`，得 `str_rva`
2. 在可执行节扫描 `48/4C 8D`（`lea reg, [rip+disp]`），`insn+7+disp == str_rva` 得 `xref_rva`
3. 用 `.pdata` 找包含 `xref_rva` 的函数 `[func_start, func_end)`
4. 从 `func_start` 起扫描，第一条操作码为 `0xE8` 的 `call rel32` → `target_rva = insn+5+rel32`
5. `CDPFilterHookOffset = hex(target_rva)`

25047 实例：xref `0x368CF4A` → 父函数 `0x368CD00` → 首 call `0x3859AE0`。

## LoadStartHookOffset 算法

1. 遍历 `.pdata` 函数（建议过滤 `size < 0x8000`）
2. 对函数体扫描 `lea [rip+disp]`，读取目标字符串
3. 选中同时满足：
   - 含 `applet_index_container.cc`
   - 含 `AppletIndexContainer::OnLoadStart(bool`
4. `LoadStartHookOffset = func_start`

25047 实例：`0x29EF320`（含 Chromium perf 日志序言，入口处 `rcx`/ `edx` 仍正确）。

## SceneOffsets 算法

1. 在 OnLoadStart 函数反汇编中找 `mov rax,[rsi+40h]` 与后续 `call`
2. 典型模式：
   ```asm
   mov rax, [rsi+40h]
   mov rcx, [rax+5D0h]    ; → SceneOffsets[1]，版本间可能变
   ...
   call sub_352C550
   ```
3. 进入 callee，找链：
   ```asm
   mov rax, [rcx+8]
   mov rcx, [rax+590h]
   mov rcx, [rcx+10h]
   cmp dword ptr [rcx+1C8h], 44Dh
   ```
4. 映射为 `[64, 1488, 8, 1424, 16, 456]`（`0x44D = 1101` 为 hook 目标 scene）

## hook.js 指针链对照

```javascript
a1.add(sceneOffsets[0]).readPointer()   // +64
  .add(sceneOffsets[1]).readPointer()   // +1488
  .add(sceneOffsets[2]).readPointer()   // +8
  .add(sceneOffsets[3]).readPointer()   // +1424
  .add(sceneOffsets[4]).readPointer()   // +16
  .add(sceneOffsets[5])                 // +456 field offset
```

## 邻近版本 SceneOffsets 趋势

| 版本 | SceneOffsets |
|------|----------------|
| 19841 | [64, 1408, 8, 1344, 16, 456] |
| 19977 / 20005 | [64, 1480, 8, 1416, 16, 456] |
| 25047 | [64, 1488, 8, 1424, 16, 456] |

仅作校验参考，**必须以目标 DLL 反汇编为准**。

## IDA MCP 工具链

配置 `~/.cursor/mcp.json`：

```json
"idalib-mcp": {
  "command": "C:\\Python\\Python312\\python.exe",
  "args": ["-m", "ida_pro_mcp.idalib_supervisor", "--stdio"]
}
```

常用调用顺序：`idb_open` → `find_regex` / `xrefs_to` → `decompile` → `disasm`

GUI 模式（IDA 内已开 flue.dll）：`idb_open(..., mode="prefer_gui")` + IDA 菜单 **Edit → Plugins → MCP**
