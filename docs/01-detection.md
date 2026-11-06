# 越狱检测

分析版本：9.50.0（脱壳样本）、9.54.0（App Store）。
静态分析使用 Mach-O 解析、ObjC 元数据遍历和 Capstone 反汇编，再结合运行日志确认调用过程。

## DTTJailbreakDetection

第三方 CocoaPod，入口是 `+[DTTJailbreakDetection isJailbroken]`。
9.50.0 中的方法偏移为 `0x4000`，依次执行：

1. 用 `fopen(path, "r")` 检查 `/Applications/Cydia.app`、`/Library/MobileSubstrate/MobileSubstrate.dylib`、`/bin/bash`、`/usr/sbin/sshd`、`/etc/apt`、`/usr/bin/ssh`。
2. 用 `-[NSFileManager fileExistsAtPath:]` 再检查一次。
3. 尝试向 `/private/jailbreak.txt` 写入内容，写入成功则判定越狱，随后删除文件。
4. 用 `-[UIApplication canOpenURL:]` 检查 `cydia://package/com.example.package`。

## JailbreakCheck

App 内的 `JailbreakCheck` 继承自 `NSObject`：

- `+isJailbroken`：调用 `+jailbreakStatusCode`，返回值不为 `nil` 则判定越狱。
- `+jailbreakStatusCode`：将路径检查、文件写入和 URL scheme 检查的结果编码成由 `1`、`0` 组成的字符串。

检测内容与 DTT 基本相同，多了一层结果编码。

## Promon SHIELD

位于 `Frameworks/octopusx.framework`，bundle ID 为 `no.promon.shield`，字符串经过混淆。

| 类 / 方法 | 用途 |
|---|---|
| `PRMShieldEventManager`：`+shared`、`-addObserver:`、`-performSecurityChecks` | 执行检查并向 App 分发结果 |
| `PRMShieldConfig`：`+requestUpdate`、`+getActiveConfigTimestamp` | 更新和读取检测配置 |
| `ShieldCallbackManager`：`+setObserver:` | 注册回调 |
| `PRMViewProtection` / `PRMLayerCleanupHelper` | 截屏和覆盖层检测 |

框架导入了 `fopen`、`opendir`、`readdir`、`readlink`、`getenv`、`dlsym` 等函数。
另外还有 `class_copyMethodList`、`method_getImplementation` 和 `method_exchangeImplementations`，
可用于检查 ObjC 方法实现，因此绕过版本尽量减少方法替换。

## 检测提示

App 中的 `logPromonStatus(_:)` 日志涉及以下状态：

```text
Jailbreak detected
debuggerStatus
hookingFrameworksDetected
libraryInjectionDetected / libraryInjectionPrevented
repackagingStatus
configUpdateReceived
Daily Update / First installation Update
```

提示页类名为 `_TtC17OctopusQuickBuild26PromonNoticeViewController`。
文案键使用 `promon.message.exit.type.%d`，测试中出现了 `type.2`（越狱）和 `type.6`（不支持的装置），按钮键为 `promon.exit.button`。

9.54.0 的启动日志中，提示页通过 modal 弹出后，App 仍继续恢复会话、加载首页。
具体时序见[绕过方案](02-bypass.md)。
