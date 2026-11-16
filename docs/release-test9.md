# Henge 0.4 Test 9（4010）——实际启动认证适配器，并确认 ChatGPT 冷启动

已有 4008 实机报告中的两次实验都停在 `HengeAuthBridge / 1010 / signature_policy_blocked`。这是 Henge 启动器根据静态签名信息提前返回的结果，发生在实际启动 ChatGPT 和请求宿主认证之前；不能把它当成 macOS 已经拒绝加载，更不能当成 Apple 返回的令牌错误。

**本版修改实际启动行为：完整核验原客户端后，只尝试一次由 macOS 自己决定是否允许的加载。启动前会请求 ChatGPT 正常退出，并确认旧主进程已经结束。** 原有静态签名判断保留为预测信息，不再单凭这一预测阻止尝试。

这修复了认证实验的启动阻碍；仍需实机确认适配器能否进入官方客户端、宿主 Apple 调用能否成功，以及 Chat 服务端是否接受结果。本版不宣称原生 Chat 已经恢复。

## 本次改动

- Mac 助手升级到 **9**，认证启动能力为 **2**。界面区分旧助手、能力尚未确认，以及当前助手，避免只看到 Connected 就误以为新启动逻辑已在运行。
- 启动按钮改为 **Quit and start ChatGPT with iPad authentication**。这次明确操作会请求经过验证的 ChatGPT 主应用正常退出；等待实际退出后，才启动本次实验。
- 如果应用拒绝退出、退出超时，或者 Henge 的本次授权被撤销，则停止本次启动。不会通过强制结束进程解决，也不会循环重启。仅关闭窗口不再被当成已退出。
- 保留原应用路径、bundle ID、Team ID、代码签名完整性，以及适配器自身签名的检查。通过检查后，使用原有临时适配器进行一次普通启动，由 macOS 实际执行其权限检查。
- 区分 `launch_started`、`adapter_loaded` 和成功的 `adapter_ready`；启动进程并不等于适配器已经接入。带错误的 ready 回执不能再被当成接入成功。
- 单独记录正常退出被拒绝、退出超时、观察到成功握手前进程结束、适配器已进入但初始化尚未确认，以及未观察到适配器加载。没有握手或进程退出都不会自动被解释为系统签名拒绝。
- 同一次启动的具体失败原因会保留在界面和自动诊断中；迟到的预测信息、停止实验或普通心跳不会把它覆盖成“等待中”。
- 当前启动的关键阶段独立保留，后续反复探测认证能力不会把它们挤出报告。助手重启后也会识别已经尝试过的同一请求，不会再次正常退出和启动 ChatGPT。

没有修改官方 ChatGPT.app 的安装内容或签名，也没有修改 VM 的 SIP／AMFI、磁盘身份或系统认证服务。原来的 Mac 虚拟机可以继续使用。

## 用原来的 Mac 测试一次

1. 保存 Mac 中的工作并正常关机，用 TrollStore 覆盖更新到 **0.4 Test 9 / 4010**，保留 Henge 数据和现有 Mac。
2. 启动原来的 Mac，先打开 **终端**，点击终端输入行并切换到 **ABC / U.S.** 输入布局，再回到 **ⓘ → Details → Sharing** 点 **Type Install / Repair Command**。该按钮向 Mac 当前聚焦的输入框输入命令；等输入完整后回到终端按回车。本次更新助手一次，回连状态应显示 **Mac helper 9 · Connected**。
3. 回到 **ⓘ → Details → ChatGPT authentication · Test9**，先保持 **iPad DeviceCheck token**。完成 ChatGPT 中当前输入后，点 **Quit and start ChatGPT with iPad authentication**，让助手完成正常退出和启动，保持 Henge 在前台。
4. 看到 **Adapter ready** 后，回到 Mac 的 Chat 发送一条测试消息。如果没有到达该状态，不用再手动打开 ChatGPT 来代替这次启动；界面和自动报告会保留停在哪一步。

更新助手是必要的一次操作：只更新 iPad 端、仍运行 Helper 8 时，Mac 里仍是旧的提前拒绝逻辑。

## 两种认证模式的含义

**iPad DeviceCheck token** 调用宿主真实的 `DCDevice`。宿主的 `isSupported=true`、拿到非空令牌，以及 Chat 接受令牌，是三个需要分别验证的结果。Apple 要求生成令牌的应用关联开发者账号，并描述服务端使用这些接口核验来自自己应用的设备令牌；“是真实 Apple 令牌”不能推出它可通用于任意应用和服务端。

**deb BAA signing path** 仍是独立实验入口。提供的 deb 采用的 BAA 签名路径与通用 `DCDevice.generateToken()` 不同，其客体接入点还包括 `akd`；当前 Henge 适配器只进入这次启动的 ChatGPT 主进程。该模式保留客体原有的 DeviceCheck 支持判断，客户端若先因不支持而退出流程，不能把“没有 BAA 请求”解释为已经验证了宿主签名失败。无需为了同一个未加载结果反复切换两种模式。

切换时先点 Stop，再选择模式并点上述退出并启动按钮。停止实验后，正常退出 ChatGPT、按平常方式打开，即结束本次临时适配器运行。Henge 进入后台或结束 Mac 会话同样撤销本次授权。

## 自动日志

**文件 → 我的 iPad → Henge → HengeDiagnostics → Latest-Henge-diagnostics.txt**

只需要这一份自动报告，不需要自行分辨进程或拼接多份日志。报告不会自动上传，也不要求关机后才导出。

日志记录固定阶段、模式、数字错误、耗时和字节数；不保存令牌、签名材料、Cookie 或对话。进程提前结束和没有收到握手只是观察结果，不会被伪装成某个 Apple 错误码。服务端接受状态保持未验证，以实际 Chat 能发送并收到回复为准。

## 验证范围

CI 使用自有、临时签名的 macOS 测试应用和合成认证后端，检查真实 DYLD 启动、关闭窗口后仍运行的进程、正常退出和冷启动、拒绝退出、授权撤销、受限制应用的真实启动结果，以及错误握手判定。保留已有队列、HTTP、独立签名子进程、助手安装、iOS 编译和安装包校验。

这些测试不使用真实 Apple 账号，不生成真实认证材料，也不代表官方客户端或 Chat 服务端已经接受本次接入。

技术依据：[Apple 的 DYLD 环境变量授权说明](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)、[库验证说明](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation)、[正常退出 API](https://developer.apple.com/documentation/appkit/nsrunningapplication/terminate())、[DeviceCheck 概览](https://developer.apple.com/documentation/devicecheck)。
