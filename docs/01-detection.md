# 01 · 越狱检测的三层结构

目标：`com.octopuscards.octopus` 9.50.0（脱壳样本）/ 9.54.0（App Store 现网）。
分析手段：Mach-O 解析（chained fixups）+ ObjC 元数据遍历 + Capstone 反汇编 + 运行期验证。

---

## L1 · DTTJailbreakDetection

第三方 CocoaPod，类 `DTTJailbreakDetection`，类方法 `+isJailbroken`。

`+[DTTJailbreakDetection isJailbroken]` @ `0x4000`（9.50.0）的实现顺序：

1. 六次 `fopen(path, "r")`，路径分别是
   `/Applications/Cydia.app`、`/Library/MobileSubstrate/MobileSubstrate.dylib`、
   `/bin/bash`、`/usr/sbin/sshd`、`/etc/apt`、`/usr/bin/ssh`；
2. 六次 `-[NSFileManager fileExistsAtPath:]` 复检；
3. 写文件测试：`[@"." writeToFile:@"/private/jailbreak.txt" atomically:YES
   encoding:NSUTF8StringEncoding error:&err]` —— **写成功即判定越狱**；
4. `removeItemAtPath:error:` 清理；
5. `[NSURL URLWithString:@"cydia://package/com.example.package"]` + `-[UIApplication canOpenURL:]`。

## L2 · 自研 JailbreakCheck

`JailbreakCheck`（父类 `NSObject`）：

- `+isJailbroken` @ `0x100010c1c` = `([JailbreakCheck jailbreakStatusCode] != nil)`
- `+jailbreakStatusCode` @ `0x100010c40` 用一个 `NSMutableString` 逐条追加 `@"1"` / `@"0"`，
  拼成**位串**：路径探测、`/private/jailbreak.txt` 写入测试、`cydia://` 能否打开各占一位。

也就是说：它把 L1 那套探针又实现了一遍，结果编码成字符串。

## L3 · Promon SHIELD

`Frameworks/octopusx.framework`（bundle id `no.promon.shield`，9.6 MB，字符串混淆）。
ObjC 对外暴露：

| 类 / 选择器 | 作用 |
|---|---|
| `PRMShieldEventManager` `+shared` `-addObserver:` `-performSecurityChecks` | 事件分发；App 注册 observer 接收判定 |
| `PRMShieldConfig` `+requestUpdate` `+getActiveConfigTimestamp` | 规则配置的每日更新 |
| `ShieldCallbackManager` `+setObserver:` | 另一条回调注册路径 |
| `PRMViewProtection` / `PRMLayerCleanupHelper` | 截屏 / 覆盖层检测 |

内部导入（说明它自己也在扫）：`_fopen _opendir _readdir _readlink _getenv _dlsym
_pthread_atfork _pipe _class_copyMethodList _method_getImplementation
_method_exchangeImplementations`。

`_class_copyMethodList` + `_method_getImplementation` 意味着它**会枚举方法并比对 IMP**，
所以 swizzle 数量越少越好（这也是后来做"最小版"的原因）。

---

## 判定怎么走到 UI 的

App 侧日志字符串（`logPromonStatus(_:)` 系列）说明了状态包内容：

```
Promon - Jailbreak detected
Promon - debuggerStatus:
Promon - hookingFrameworksDetected
Promon - libraryInjectionDetected / libraryInjectionPrevented
Promon - repackagingStatus:
Promon - configUpdateReceived:
Promon - Daily Update / First installation Update
Promon - getActiveConfigTimestamp: / lastUpdateDay:
```

UI 侧：`_TtC17OctopusQuickBuild26PromonNoticeViewController`
（`viewDidLoad` @ `0x10111de04`、`didTapExit` @ `0x10111dfa0`），
文案键 `promon.message.exit.type.%d`，实测存在 `type.2`（越狱）与 `type.6`（不支持的装置），
按钮键 `promon.exit.button`。

**关键：这个 VC 只是被 present 出来的普通页面，没有任何"挂起业务"的动作。**
下一份文档给出完整时序证据。
