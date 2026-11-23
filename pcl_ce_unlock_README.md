# pcl_ce_unlock.py 使用说明

解除 PCL2 社区版（PCL CE 2.15.1+）在检测到中国大陆环境时锁定的
"Minecraft 本体下载 / 补全 / 整合包安装" 功能。

原理：对 .NET 单文件包内 `PCL.RestrictedFeaturePolicy` 的两个方法做
**等长 IL 补丁**（`Check` → `ldc.i4.1; ret` 恒放行，`get_IsRestricted` →
`ldc.i4.0; ret` 恒"未受限"，方法体 codeSize 收紧为 2）。
不改元数据、不改文件大小、不注入代码。逻辑借鉴
ailixiyaX/PCLDownloadUnlock（MIT），纯 Python 实现，无第三方依赖。

## 前提

- Python 3.8+（无需任何第三方库）
- PCL **完全退出**（包括托盘图标；`错误[busy]` 即说明文件被占用）
- 仅适用于内置该限制的 PCL CE 构建（2.15.1 及之后）。
  官方版 PCL2、其他启动器、无限制的旧版（≤2.15.0）会提示"不适用"。

## 命令

```bat
:: 检测（默认目标为本工作区 MC\PCL2_CE_Release_x64.exe，其他文件请带路径）
python pcl_ce_unlock.py check "D:\games\PCL\PCL2_CE_x64.exe"

:: 打补丁（原地修改，自动备份为 <文件名>.pclfix.bak，写后自动校验，失败自动还原）
python pcl_ce_unlock.py patch "D:\games\PCL\PCL2_CE_x64.exe"

:: 打补丁但输出到副本，不动原文件
python pcl_ce_unlock.py patch "D:\games\PCL\PCL2_CE_x64.exe" --out "D:\games\PCL\PCL2_CE_x64.patched.exe"

:: 还原（用 .pclfix.bak 覆盖回去）
python pcl_ce_unlock.py revert "D:\games\PCL\PCL2_CE_x64.exe"

:: 自定义备份路径
python pcl_ce_unlock.py patch <file> --backup "D:\backups\pcl.orig.exe"
python pcl_ce_unlock.py revert <file> --backup "D:\backups\pcl.orig.exe"
```

## 新下载的 PCLCE 标准流程

1. **退出 PCL**（托盘也要退）。
2. `check` 检测新文件 → 看状态：
   - `未打补丁` + 列出 `Check` / `get_IsRestricted` 两个补丁点 → 继续。
   - `已打补丁` → 无需操作。
   - `不适用`（未找到补丁点）→ 该版本没有此限制（如 2.15.0 及更早），
     或新版本改动了门禁（需等脚本更新）。
3. `patch` 打补丁 → 看到 `校验通过 ✓` 和新的 SHA256 即成功。
4. 启动 PCL → 下载页 → "开始下载" 应不再弹"在你所在的国家或地区不可用"。
   下载源建议选 BMCLAPI 镜像。

## PCL 更新后

每次更新都会用官方文件覆盖 exe，补丁随之消失，
重跑一次 `patch` 即可（脚本会重新定位并补丁）。

## 退出码

| 码 | 含义 |
|----|------|
| 0  | check: 已全部打补丁；patch/revert: 成功 |
| 1  | check: 有补丁点但未打补丁；revert: 找不到备份；文件不存在 |
| 2  | 命令行用法错误 |
| 3  | 不是 .NET 单文件包 |
| 4  | 找不到补丁点（版本不带该限制或门禁已变） |
| 5  | 其他错误（busy 文件被占用 / incompatible / verify 校验失败） |

## 常见问题

- **错误[busy]**：PCL 还在运行，去任务栏托盘和任务管理器彻底退出。
- **杀软报警**：补丁后文件哈希与官方不同属正常，加白名单即可；
  全部修改只有每个方法 2 字节 IL + 头部 codeSize。
- **想反悔**：`revert`，或手动把 `.pclfix.bak` 覆盖回原名。

## 免责

该限制是启动器作者因大陆合规压力加入的，解锁属个人选择、风险自担。
补丁仅解锁本地功能入口，不涉及任何付费内容。
