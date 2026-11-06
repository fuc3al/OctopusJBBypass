# 02 · 绕过方案与实测

## 设计依据：拦截是异步、非阻塞的

一次冷启动的 syslog 时序（9.54.0 / iOS 16.2）：

```
13:02:43.986  key window 建立
13:02:44.007  app.splash.skip.button 文案
13:02:44.032  PromonNoticeViewController.nib 加载
              promon.message.exit.type.6
              promon.message.exit.type.2      ← "已越狱无法使用"
13:02:44.032  CFPrefs 读 PromonConfigUpdateTime
13:02:45.950  ← 已经在读 AuthenticationManager.session
13:02:46.001  读 skippedSplash
13:02:48+     配置缓存、首页数据 …… 一路跑完
```

**弹窗 44.0 秒建好，启动流水线一秒都没停，45.9 秒就开始恢复会话。**
视图事件序列也印证了它会被替换掉：

```
SplashScreenViewController → PromonNoticeViewController → ProductTourViewController
```

所以有两种绕过策略：

| 策略 | 做法 | 确定性 |
|---|---|---|
| 利用竞态 | 什么都不做，等首页接管 | 差（取决于网络与启动速度） |
| 切断投递 | 让 SHIELD 的判定到不了 App | **确定** |

---

## 方案演进

### v1 全量版 `src/OctopusJBHook.m`

11 个 hook，什么都管：

- `DYLD_INTERPOSE`：`fopen` `opendir` `access` `stat` `lstat` `readlink` `getenv` `fork` `ptrace` `sysctl` `_dyld_get_image_name`
- ObjC：`+[DTTJailbreakDetection isJailbroken]`、`+[JailbreakCheck isJailbroken]`、
  `+[JailbreakCheck jailbreakStatusCode]`、`NSFileManager` 的 `fileExistsAtPath:`(x2)、
  `NSString writeToFile:…`、`UIApplication canOpenURL:`
- SHIELD：`PRMShieldEventManager` / `ShieldCallbackManager` 的 `addObserver:`、`performSecurityChecks`、`setObserver:`
- UI 兜底：`presentViewController:` / `pushViewController:` / `setRootViewController:` 过滤 `Promon*`

问题：`fork()=-1` 会打断 CFNetwork/TLS；`stat`/`lstat`/`access` 对这三层检测毫无用处，纯增加 ABT 风险。

### v2 精简全量版

删掉 `stat`/`lstat`/`access`/`fork`/`ptrace`/`sysctl`（App、DTT、SHIELD 都不导入这些），
`canOpenURL:` 改成只否掉越狱 scheme（其余放行原函数），保留
`fopen`/`opendir`/`readlink`/`getenv` + `_dyld_get_image_name`。

### v3 最小版 `src/PromonKiller.m`（推荐）

只切 3 个方法：

| Hook | 作用 |
|---|---|
| `-[PRMShieldEventManager addObserver:]` | 判定送不到 App 的 Swift 层 |
| `-[ShieldCallbackManager addObserver:]` | 另一条注册路径 |
| `-[UIViewController presentViewController:animated:completion:]` | 类名含 `Promon`/`Jailbreak`/`SecurityNotice` 的直接丢弃 |

不碰文件、不碰环境变量、不改检测器返回值 —— 暴露给 SHIELD 的 IMP 扫描面从 11 个降到 3 个。

**3/3 冷启动实测：**

```
run1 alive=1
run2 alive=1
run3 alive=1
promon.message.exit / PromonNoticeViewController 出现次数: 0
```

日志：

```
[PromonKiller] loaded pid=…
[PromonKiller] hooked -[PRMShieldEventManager addObserver:]
[PromonKiller] hooked -[ShieldCallbackManager addObserver:]
[PromonKiller] hooked -presentViewController:animated:completion:
[PromonKiller] swallowed -addObserver:<AppDelegate: 0x…>
```

---

## 投递方式：ellekit，不是 TrollFools

这一点踩过坑，单独记在 `docs/03-crash-analysis.md`：

| 方式 | 是否改 App 二进制 | 是否重签 | 结果 |
|---|---|---|---|
| TrollFools 注入 | 是 | 是 | **启动即崩**（FairPlay 失效） |
| ellekit 注入 | 否 | 否 | 正常，签名校验 17490/17490 页全对 |

---

## 安装 / 卸载

```bash
export IPHONE_HOST=… IPHONE_USER=mobile IPHONE_PASS=…
python tools/deploy_tweak.py install --dylib build/libPromonKiller.dylib \
       --bundle com.octopuscards.octopus
python tools/deploy_tweak.py remove --name libPromonKiller
```

落到设备上的文件：

```
/var/jb/usr/lib/TweakInject/libPromonKiller.dylib    root:wheel 755
/var/jb/usr/lib/TweakInject/libPromonKiller.plist    Filter → com.octopuscards.octopus
```

不需要 respring：Substrate 兼容的 filter 在每次 exec 时按需加载。
