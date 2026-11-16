# Henge 0.4 Test 8（4009）——明确启动认证并记录启动结果

4008 的第一份实机报告没有记录到成功启用实验。**后续报告已确认两次启动被接受，并分别在约 6.6 秒、5.6 秒后记录 `signature_policy_blocked`，错误域 `HengeAuthBridge`、错误码 `1010`。** 这证明操作已到达实验启动器；1010 是 Henge 的本地签名策略预检结果，并非 Apple DeviceCheck 原生错误。两次均未进入适配器启动或宿主令牌生成阶段。

旧启动器在签名策略检查后才检查主进程是否仍运行。因此这些日志不能确认关闭窗口后 ChatGPT 是否退出，冷启动速度也不能代替进程证据。本版把这两种观察分别记录，并保留停止实验前的具体失败原因。

**本版修复认证入口和诊断缺口，保留 Test 7 的两条真实 Apple 调用路径。尚未验证 iPad 令牌能被 Chat 接受，不能将此包标为原生 Chat 已修复。**

## 本次改动

- 把 **ChatGPT authentication · Test8** 移到运行中 Mac 的 **ⓘ → Details** 最上方。启动按钮明确为 **Start ChatGPT with iPad authentication**。
- 启动按钮可点击并记录返回结果；会先刷新现有会话的真实运行和前台状态，再请求启用认证。启动失败不再只是一个临时界面错误。
- 每次启动调用都记录尝试数、成功数、失败数、固定返回码与后台处理器是否注册。失败不会覆盖已有授权或伪造成功的 launch。
- Mac 助手升级到 **8**，健康回连报告实际运行版本和认证协议能力。连接协议 4 不再被误当作助手版本。缺字段明确表示未确认。
- 自动报告增加 `authentication_summary` 和有界的界面操作记录。未启动、启动被拒绝、等待助手、加载失败、签名策略阻止和已有认证活动会分别显示。
- 完整验证目标应用后，独立记录其主进程是否仍运行，以及 Hardened Runtime、显式库验证标志和 DYLD／库验证例外的固定布尔结果。不可读标志记为未知，显式库验证标志未设置不代表 Hardened Runtime 的默认库验证已关闭。
- 同一次启动的具体终态错误不会被迟到的 `launch_requested`、助手心跳变化或 Stop 状态覆盖。签名预检失败不会被显示成 Apple 认证错误。
- 删除旧能力探测中容易误导的静态 `guest_forwarding_implemented=false`。宿主 `isSupported=true` 仍只表示宿主 API 支持，不表示已生成令牌或已通过 Chat 认证。

## 使用原来的 Mac 测试

1. 保存 Mac 中的工作并正常关机，用 TrollStore **覆盖更新到 0.4 Test 8 / 4009**，保留 Henge 数据和现有 Mac。
2. 启动原来的 Mac，在终端使用 ABC / U.S. 键盘布局。到 **ⓘ → Details → Sharing → Type Install / Repair Command**，等命令输入完整后在终端按回车。本次更新助手一次；新状态应显示 **Mac helper 8 · Connected**。
3. 在 Mac 内使用 **ChatGPT → Quit ChatGPT／退出 ChatGPT**，或按 **⌘Q**；仅关闭窗口可能保留进程。回到 **ⓘ → Details** 最上方，保持 **iPad DeviceCheck token**，点 **Start ChatGPT with iPad authentication**。让助手启动 ChatGPT；状态到 **Adapter ready** 后进入 Chat 测试一次。
4. 如果显示启动错误、签名策略阻止或等待助手，界面和同一份自动报告会保留原因，无需把普通打开的 ChatGPT 当成已接入认证实验。

原有 **deb BAA signing path** 仍可手动选择。切换前点 Stop 并正常退出 ChatGPT，再重新开始。该路径保留客体原来的 DeviceCheck 支持判断；如果客户端没有调用 BAA，报告不会宣称发生了宿主签名。

**完全退出 ChatGPT 不会改变它的签名策略。** 已遇到 `signature_policy_blocked` 时，两种模式都经过同一个预检；切换模式或重建 Mac 不会据此获得通过。本版会具体记录预检条件，仍不会重签原客户端或放宽该限制。

退出方式仍是 Stop 后正常退出 ChatGPT、按通常方式重开。Henge 进入后台或结束 Mac 会话会撤销授权。不会后台自动启用、自动强退应用或更改客户端签名策略。

## 日志位置

**文件 → 我的 iPad → Henge → HengeDiagnostics → Latest-Henge-diagnostics.txt**

启动动作会立即写入固定字段记录，并触发有节制的自动报告更新。无需关闭 Mac 才能导出。宿主认证事件不依赖耗时的 Mac `log show` 采集；普通日志查询超时仍明确标为不可用，错误计数为 0 不能证明没有错误。

记录模式、阶段、数字错误、耗时、字节数与子进程状态，不记录令牌、签名、签名输入、Cookie 或对话。报告不会自动上传。服务端接受状态保持未验证，需以实际 Chat 成功发送消息为准。

## 验证范围

回归覆盖每次 enable 调用的固定日志、失败不替换授权、旧助手兼容、实际运行版本与探测进程的区分、字段边界、当前 launch 的进度展示，以及 4008 报告状态的误判回归。保留 Test 7 的队列、HTTP、合成原生后端、独立签名子进程、真实 DYLD 自有应用夹具、助手安装与启动、iOS 编译和 TIPA 校验门槛。

这些检查不替代 iPadOS 17 实机上的 Apple 调用、官方客户端加载及 Chat 服务端验证。
