# Henge 0.4 Test 3（4003）

这是一版面向 iPadOS 17 / TrollStore 的测试包，集中改进 Chat 故障的自动记录、统一诊断和日志保存分享。

## 本版变化

- 自动维护统一的、经过过滤的诊断报告，包含当前及上一次 Henge 启动的日志、版本和内存状态。
- 报告保存在“文件 → 我的 iPad → Henge → HengeDiagnostics”，不再只放在 App 临时目录。
- 替换运行中顶部 ⓘ 详情面板及设置页的导出组件，从当前可见面板呈现系统分享；另有独立的“保存到文件”入口，记录生成、分享和保存的成功、取消或失败结果。
- 新增 Mac 内的 Chat 专用诊断摘要：客户端及系统版本、签名检查状态、DeviceCheck 与请求错误的固定分类；更新 helper 后，Henge 在前台且 Mac 运行时约每两分钟自动请求摘要，并合入同一份报告。
- 记录真实的宿主 DeviceCheck 能力。宿主结果与 macOS 客体结果分别标明，不将二者混为一谈。
- 保留 Test 2 的小映射表面纹理兼容修复。

## 使用

1. 保存 macOS 中的工作并正常关机，在 TrollStore 中更新安装本包；沿用已有虚拟机，无需重新创建。
2. 启动原来的 Mac。Henge 会自动保存宿主报告，无需先点导出，也无需为导出关机。
3. 在 Mac 内打开“终端”并点入输入区，然后到 Henge 的 Details → Sharing，点击 **Type the Update Helper Command**（未安装时是 **Type the Set Up Command**），回到 Mac 按一次回车。只需更新一次；旧版 helper 不具备新增采集功能，Henge 不会擅自提交键盘命令。
4. 在 Mac 内复现一次 Chat 问题，保持 Mac 运行，打开顶部 **ⓘ → Details → Diagnostics**，点击 **Collect Chat diagnostics**（Settings 中也有同一入口）。界面最多等待 Mac 摘要 15 秒，然后生成合并报告并打开系统分享。
5. 如果系统分享仍有问题，使用独立的 **Save diagnostics to Files** 按钮；也可直接到“文件 → 我的 iPad → Henge → HengeDiagnostics”取 **Latest-Henge-diagnostics.txt**。只需这一份，不需要分辨多个日志。

自动报告在启动时保存，运行期间约每两分钟更新，进入后台时按限频规则尝试保存；最多保留 8 次 Henge 启动的报告。突然退出后，下次打开会用已保存的上一轮日志补充合并报告。系统强制结束进程前尚未落盘的内容无法补回，报告会明确区分 Mac 摘要缺失、过期或等待超时。

## 原生 Chat 的修复边界

本版没有把 `DeviceCheck.isSupported` 改成固定成功，没有伪造认证 token，也没有加入未经验证的宿主签名转发。

此前已观察到的 `devicecheck_unsupported_device` 仍是原生 Chat 的独立阻碍。本版不能宣称已恢复原生 Chat 的设备认证。提供的 ChatGPT 网页入口是替代入口，未在用户账号上验证登录和发消息成功。

诊断不会自动上传。Mac 采集器只输出允许字段和错误分类，不保存统一日志原文，不读取对话数据库、Cookie、令牌或钥匙串。

本包通过构建流程编译和包结构验证后发布。iPad Air 5 / iPadOS 17.0 上的分享、Mac helper 和实际 Chat 行为仍需要实机验证；安装包能成功构建不等于原生 Chat 已修复。
