# Henge 0.4 Test 5（4006）

本版修正 Test 4.1 中 Mac 助手未能在后台完成连接、安装器随即回滚的问题。面向 iPadOS 17 / TrollStore，更新现有 Henge，保留原来的 Mac 和磁盘。

**这是 Mac 助手启动流程的修订版，不是已经解决 DeviceCheck 的原生 Chat 修复。** 已有日志里的 `DeviceCheck is not supported` 仍是独立限制。助手连通只表示共享功能和诊断通道可工作，不表示 ChatGPT 已取得设备认证令牌。

## 改动

- 助手以真正的 **Henge Helper.app** 安装到 Mac 用户的 `Applications` 文件夹，有固定应用名称、bundle ID 和本地网络用途说明。通过 macOS Launch Services 打开，替换旧的裸程序 LaunchAgent 启动方式。
- 安装时显示 Mac 连接窗口，后续在菜单栏显示 **Henge**。窗口分别说明当前连接、本地网络授权和登录启动状态；关闭窗口不会退出助手。可通过窗口直接打开相应系统设置。
- 使用 macOS 的 `SMAppService.mainAppService` 注册登录启动。系统要求批准时明确显示等待状态，当前手动启动的应用继续运行。登录项被用户关闭后，普通启动不会反复强制重新注册。
- 健康请求在独立线程立即开始，失败后每两秒重试。网络请求不阻塞主事件循环或权限提示，也不依赖剪贴板初始化。只有实际后台进程的健康回执才能确认连接。
- 取消原先“20 秒”文案与最多 10 次检查之间的矛盾。新安装器进行 60 次有间隔检查；若应用仍在运行但尚未连通，保留应用等待授权，记录 `awaiting_connection`。稍后连通时，应用会自动更新为确认状态，无须重复安装。
- 启动确实失败才恢复旧助手；完整备份在修改前完成，替换途中被终止也保留恢复路径。新增归档的路径和文件类型校验，完整验证 app 签名后才替换。
- 运行状态自动保留在 Mac 的 `~/Library/Logs/Henge/helper-status.json`，只含固定状态、PID 和数字网络错误。Henge 现有统一报告继续保存安装结果、连接状态和启动阶段。

## 更新方法

1. 保存 Mac 中的工作并正常关机，用 TrollStore 覆盖更新到 **0.4 Test 5 / 4006**。不要删除 Henge，不需要新建 Mac。
2. 启动原来的 Mac，打开“终端”，切换到 ABC / U.S. 键盘布局。打开 Henge 顶部 **ⓘ → Details → Sharing → Type Install / Repair Command**，等整条命令输入完毕后，在终端按一次回车。本次需要迁移一次旧助手。
3. 新的 **Henge Helper** 窗口应出现。macOS 询问本地网络访问时，选择允许；如果登录项需要批准，按窗口提示打开系统设置。
4. 以 Mac 窗口的 **Connected to Henge** 和 Henge Details 中的 **Connected / Installation confirmed** 判断实际连通。仅出现“安装完成”或“登录项已添加”不代表连接成功。若正在等待授权，保留窗口，不要再次运行安装命令。

## 验证范围

发布门槛增加真实 macOS 运行测试：实际打开签名后的 app，核对运行进程路径和 PID，验证生产 C 服务的健康连接、诊断通道心跳、安装确认回执，并持续观察至少 12 秒。没有 GUI domain、没有真实心跳或清理失败均不得算通过。

此测试使用 loopback 模拟虚拟机内地址，明确不覆盖用户 macOS 15.6.1 的本地网络授权弹窗。测试模式跳过剪贴板、共享挂载和登录项注册，不能将其声称为这些功能的实机测试。用户 iPad 上的长时间稳定性、中文候选窗及原生 Chat 均仍需各自验证。

Mac 助手使用 ad hoc 测试签名。Apple 提醒，这种签名不能保证跨版本稳定保留系统权限身份；升级后可能需要再次授权。登录启动不等于进程崩溃后自动重启。

统一报告仍位于 **文件 → 我的 iPad → Henge → HengeDiagnostics → Latest-Henge-diagnostics.txt**，运行中的顶部详情面板可分享或保存；不需要为了导出关闭 Mac。诊断不自动上传，不读取对话数据库、Cookie、令牌或钥匙串。

参考：[Apple 本地网络权限说明](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)、[主应用登录启动](https://developer.apple.com/documentation/servicemanagement/smappservice/mainapp)、[代码签名身份说明](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)。
