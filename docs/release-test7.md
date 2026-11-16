# Henge 0.4 Test 7（4008）——实验认证桥

本版按所提供 deb 的宿主签名调用方式加入可关闭的实验认证桥，目标是实际测试 iPad 原生认证结果能否帮助虚拟 macOS 中的 Chat。**这是实验包；发布时没有在用户的 iPad 上验证 Chat 成功创建对话。** 返回令牌或签名与服务端接受认证分别记录，不能将前者当作修复完成。

## 两条实验路径

- **iPad DeviceCheck token：** 在 Henge 主应用上下文真实调用 `DCDevice.isSupported` 和 `generateTokenWithCompletionHandler:`。客体适配器读取真实宿主支持状态，并传递真实结果或原生错误。该结果属于宿主调用上下文，是否适用于官方客户端仍需实际验证。
- **deb BAA signing path：** 参考 deb 的 `DCBAASigner.signatureForData:completion:` / `signaturesForData:completion:`，将原始有界输入转给独立 iPad 签名进程，保留 signature(s) 与 attestation 的可序列化原始结构。签名进程单独带有 deb 使用的权限声明；安装系统是否授予这些权限、iPadOS 17 是否支持该私有接口均须由实机结果确认。BAA 模式的能力探测也在独立签名进程中执行。

私有调用与 Henge 的虚拟机进程隔离，有输入/输出上限和超时回收。主程序不增加签名子进程的 platform/no-sandbox 权限。原生调用仍可能拒绝、超时或返回服务端不接受的材料。BAA 路径保留客体原有 `isSupported` 判断；若客户端在调用 BAA 前已停止，此模式不会伪造支持状态强行继续。

## 使用现有 Mac 测试

1. 保存 Mac 中的工作并正常关机，用 TrollStore **覆盖更新到 0.4 Test 7 / 4008**，保留 Henge 数据。**不需要新建 Mac。**
2. 启动原来的 Mac，在终端切到 ABC / U.S. 键盘布局。到顶部 **ⓘ → Details → Sharing → Type Install / Repair Command**，等命令输入完整后在终端按回车。**本次需要将 Mac 助手更新一次到版本 7**；之后无需每次测试重新安装。
3. 等待助手 **Connected / Installation confirmed**。正常退出 Mac 中的 ChatGPT，保持 Henge 在前台。
4. 在顶部详情找到 **Chat authentication experiment · Test7**，先选择 **iPad DeviceCheck token**，点 **Start authentication test**。助手会尝试启动原来的 ChatGPT.app，成功接入后再进入 Chat、发送一次测试消息。
5. 若失败，点 **Stop authentication test**，正常退出 ChatGPT；再选 **deb BAA signing path** 并重新开始，复现一次即可。两种模式每次都有独立编号，报告能区分结果。

启动器检查 app 路径、bundle、签名及签名是否允许临时加载适配器。若显示 `signature_policy_blocked`，表示这一接入方式被客户端签名策略阻止；报告不会把它计作 iPad 的 DeviceCheck 失败。不会改写或重签官方客户端，也不会修改系统认证进程、SIP、虚拟机身份或磁盘。

**停止方式：** 点 Stop 后正常退出 ChatGPT，再按通常方式打开。适配器只影响实验启动的那次进程；Henge 进入后台或 Mac 会话结束后，宿主授权也会撤销。已发出的 Apple 原生操作可能继续完成，但过期结果会被丢弃。

## 一份日志即可

统一报告自动保存在：

**文件 → 我的 iPad → Henge → HengeDiagnostics → Latest-Henge-diagnostics.txt**

实验阶段、请求编号、模式、实际调用进程、能力/权限存在布尔值、错误域与数字错误码、耗时、输入输出长度及子进程退出状态都进入该报告。客体也保留有大小上限的固定字段事件记录。无需关闭 Mac 才能导出；可在复现后点 **Collect Chat diagnostics** 取得新快照。

不保存令牌、签名、签名输入、attestation 内容、Cookie、对话或原始错误描述，不自动上传报告。`serverAcceptanceVerified` 保持 `false`：只有用户实际成功发送消息，才能确认 Chat 层面可用。

## 发布验证范围

构建门槛包含宿主请求隔离、撤销/超时/迟到结果处理、错误和数据形状校验、敏感材料不进入诊断、独立签名进程回收、合成客户端真实加载适配器、Mac 助手安装与启动回归，以及 TIPA 签名、资源和版本校验。测试只使用合成后端与自有应用，不生成真实账户材料。

这些检查验证代码和测试路径，不替代 iPadOS 17 实机的 Apple 私有接口调用、官方客户端加载和 Chat 服务端认证。此包也不宣称已经修复输入法候选框或所有虚拟机闪退。
