# 绕过方案

## 启动过程

9.54.0 / iOS 16.2 的一次冷启动记录，以 key window 建立为起点：

```text
 0 ms     key window 建立
21 ms     加载启动页文案
46 ms     加载 PromonNoticeViewController.nib
          出现 promon.message.exit.type.6 / type.2
          读取 PromonConfigUpdateTime
1964 ms   读取 AuthenticationManager.session
2015 ms   读取 skippedSplash
约 4 s    加载配置缓存和首页数据
```

提示页出现后，启动流程继续执行。视图切换顺序为：

```text
SplashScreenViewController → PromonNoticeViewController → ProductTourViewController
```

这解释了提示页有时会一闪而过：后续导航替换了它。绕过方案直接拦截 SHIELD 的结果回调和提示页。

## 早期版本

[OctopusJBHook.m](../src/OctopusJBHook.m) 同时处理文件检查、环境变量、ObjC 检测方法、SHIELD 回调和 UI：

- C 函数：`fopen`、`opendir`、`access`、`stat`、`lstat`、`readlink`、`getenv`、`fork`、`ptrace`、`sysctl`、`_dyld_get_image_name`。
- ObjC：DTT 和 `JailbreakCheck` 的检测方法，以及文件检查、写入和 URL scheme 检查。
- SHIELD：observer 注册和 `performSecurityChecks`。
- UI：过滤 `presentViewController:`、`pushViewController:`、`setRootViewController:` 中的检测提示页。

其中将 `fork()` 固定返回 `-1` 会影响 CFNetwork/TLS。后续版本删掉了 `stat`、`lstat`、`access`、`fork`、`ptrace`、`sysctl` 的 hook，`canOpenURL:` 也只处理越狱相关 scheme。

## PromonKiller

[PromonKiller.m](../src/PromonKiller.m) 保留 3 个方法 hook：

| 方法 | 处理 |
|---|---|
| `-[PRMShieldEventManager addObserver:]` | 拦截 observer 注册 |
| `-[ShieldCallbackManager addObserver:]` | 拦截另一处 observer 注册 |
| `-[UIViewController presentViewController:animated:completion:]` | 过滤类名包含 `Promon`、`Jailbreak`、`SecurityNotice` 的页面 |

安装 hook 的逻辑在 constructor 和主队列各执行一次，补上稍后注册的类。
替换前比较当前 IMP，避免重复安装。

9.54.0 连续三次冷启动均保持运行，日志中未出现 `promon.message.exit` 或 `PromonNoticeViewController`。
开启调试日志后，可以看到：

```text
[PromonKiller] hooked -[PRMShieldEventManager addObserver:]
[PromonKiller] hooked -[ShieldCallbackManager addObserver:]
[PromonKiller] hooked -presentViewController:animated:completion:
[PromonKiller] swallowed -addObserver:<AppDelegate: …>
```

## 安装与卸载

使用 ellekit 加载 dylib。TrollFools 修改、重签 App Store 原包后的崩溃记录见[注入崩溃分析](03-crash-analysis.md)。

在 macOS 上构建：

```bash
./scripts/build_mac.sh src/PromonKiller.m libPromonKiller
```

需要日志时，在构建命令末尾加上 `'-DPROMON_KILLER_DEBUG'`。

```bash
export IPHONE_HOST='<设备地址>'
export IPHONE_USER=mobile
export IPHONE_PASS='<SSH 密码>'

python tools/deploy_tweak.py install \
    --dylib build/libPromonKiller.dylib \
    --bundle com.octopuscards.octopus

python tools/deploy_tweak.py remove --name libPromonKiller
```

安装位置：

```text
/var/jb/usr/lib/TweakInject/libPromonKiller.dylib
/var/jb/usr/lib/TweakInject/libPromonKiller.plist
```

plist 的 Filter 指定 `com.octopuscards.octopus`。安装或卸载后重新启动 App，无需 respring。
