# 微信数据分析大屏 · 自包含工具包

> **免责声明：** 本项目仅供学习与研究使用。使用者必须遵守所在国家或地区的法律法规，
> 仅处理本人拥有或已获得合法授权的数据，不得用于侵犯他人隐私、非法获取数据或其他违法用途。
> 因不当使用造成的任何后果由使用者自行承担。

作者署名：**云帆-H1088880**

一套只读、离线、跨平台的微信本地数据分析工具：从加密数据库解密，到可视化分析大屏。

## 一分钟启动

前置：Python 3.8+（需联网装一次 `pycryptodome`）、Chrome/Edge/Chromium、以及**你自己的**微信数据和解密密钥。

- **Windows**：双击 `assets/app/启动大屏-Windows.bat`
- **macOS / Linux**：在 `assets/app/` 运行 `bash 启动大屏-Mac-Linux.command`

也可手动：`cd assets/app && python launch.py`（macOS/Linux 用 `python3`）。

启动器会自动装依赖 → 起服务(7890) → 等服务就绪 → 弹全屏大屏。
打开 `http://127.0.0.1:7890/index.html` 可导入密钥、完成解密。

## 说这三句就够了

不需要记任何命令。装完之后，对 Agent 说：

1. **装**：帮我安装这个 skill：https://github.com/H1088880/wechat-data-dashboard
2. **验**（可选但推荐）：跑 `python scripts/preflight.py --imports`，把结果贴给我
3. **开**：帮我打开微信数据分析大屏

卡在"需要密钥"时补一句：**不用管密钥，直接点「⚡ 一键探测 + 解密 + 加载」**——它会复用本机密钥环，缺的从运行中的微信进程内存只读提取，再逐库解密。

想一次说完，就把这整段发给对方：

> 帮我安装这个 skill：https://github.com/H1088880/wechat-data-dashboard
> 装完跑 `python scripts/preflight.py --imports` 自检，通过后重启客户端，再帮我打开微信数据分析大屏。
> 如果卡在"需要密钥"，直接点「⚡ 一键探测 + 解密 + 加载」，不用填密钥。

（更多指令与 Agent 行为对照见 `SKILL.md` 的「一句话指令」「指令映射」两节。）

## 给 AI 使用

对能操作本机文件的 Agent（WorkBuddy / Claude Code / Cursor 等）说：

> 帮我安装并打开这个微信数据分析大屏

它应读取 `SKILL.md` → 检查 Python → 运行 `assets/app/launch.py` → 拉起大屏。

纯云端聊天 AI（无本机文件系统）无法运行本机软件，只能把本包当文档参考。

## 通过 Git 仓库安装（推荐，最接近"发链接即装"）

把本目录作为一个 Git 仓库 push 到你自己的库（GitHub / Gitee / CNB / GitLab 均可）。**仓库根目录就是 Skill 根目录**（含 `SKILL.md`），这样 Agent 看到链接就能直接识别。之后把仓库链接发给对方，让他对能操作本机文件的 Agent 说：

> 帮我安装这个 skill：<你的仓库链接>
> 请 clone 仓库，把根目录（含 SKILL.md）复制到 `~/.workbuddy/skills/wechat-data-dashboard/`，完成后告诉我怎么触发。

这是目前最标准、最省事的分发方式：WorkBuddy / Claude Code 等能操作本机文件的 Agent 原生理解"给仓库链接 → 安装 Skill"。对方不用 Agent 也可以手动一键装：

- macOS / Linux：`git clone <仓库链接> && bash <仓库目录>/install.sh`
- Windows：`git clone <仓库链接>` 后用 PowerShell 运行 `.\install.ps1`

一键脚本会把 Skill 装到 `~/.workbuddy/skills/wechat-data-dashboard/`，重启客户端即可生效。

**仍要如实说明的边界**：Git 链接把"安装 Skill 包"标准化了，但"打开软件"需要对方本机有 ①Python + 浏览器 ②微信数据 ③解密密钥。这些属于隐私，仓库里没有、也无法替对方准备。纯云端聊天 AI（无本机文件系统）即使拿到链接也打不开本机软件——这是物理边界，不是打包方式能绕过的。

## 从资料库/分享链接安装（重要边界）

**资料库链接本身不会自动安装技能**。它只是文件的查看/下载入口，不是技能安装器。收到链接的一方，需要让一个**能读写本机文件的 Agent** 做这几步：

1. 下载 `wechat-data-dashboard.zip` 并解压；
2. 把解压出的 `wechat-data-dashboard/` 文件夹放到本机技能目录：
   - WorkBuddy 用户级：`~/.workbuddy/skills/wechat-data-dashboard/`
   - WorkBuddy 项目级：`<项目目录>/.workbuddy/skills/wechat-data-dashboard/`
   - 其他 Agent：放到它自己识别的 skills 目录；
3. 确认该目录根部有 `SKILL.md`；
4. 对这个 Agent 说"帮我安装并打开微信数据分析大屏"，它会读取 `SKILL.md` → 检查 Python → 运行 `assets/app/launch.py` 拉起大屏。

可以把上面 4 步连同链接一起发给对方，让对方的 Agent 照做——这是目前最接近"给链接就能用"的方式。纯云端聊天 AI（不能访问你的电脑）即使拿到链接也打不开本机软件。

## 装完先自检（一条命令）

```bash
python scripts/preflight.py --imports
```

它核对必需文件、扫出"被 `import` 但没打包"的模块、逐个模块试导入，最后报告第三方依赖状态。
**看到 `结论：✓ 包是完整的` 才继续**；报错会直接点名缺哪个文件。

> 为什么需要这个：本包曾经漏打包 `keycap.py` / `wcdb_ctx.py`（密钥提取的两个核心模块），
> 表现却很迷惑——页面能打开、能探测到 20 个加密库，就是永远停在"但是要密钥"，
> 提示还写成"微信版本/权限限制"。自检能在装完第一时间把这类问题顶出来。

## 目录

```
SKILL.md                 技能入口 / 触发词 / 启动流程
README.md                本文件
assets/app/              完整可运行代码（已脱敏）
  launch.py              一键启动器（跨平台）
  启动大屏-Windows.bat      Windows 双击入口
  启动大屏-Mac-Linux.command Mac/Linux 入口
  server.py 等            服务与核心模块
  keycap.py              密钥捕获入口（按平台分发）
  wcdb_ctx.py            SQLCipher codec 上下文解析 + 密钥校验
  wxkey_extract.py       Windows 进程内存后端
  sample.py              示例库生成（没微信也能先看效果）
  templates/              解密入口页 + 全屏大屏页
references/              架构 / 踩坑 / 平台授权
scripts/                 完整性自检 / 环境探测 / 隐私扫描
```

## 隐私声明

本包不含任何真实数据：无解密库、无密钥、无 token、无账号、无群 ID、无绝对路径。
运行时所需的数据与密钥由使用者在本机自行准备。发布前可运行 `scripts/privacy_scan.py <目录>` 复检。
