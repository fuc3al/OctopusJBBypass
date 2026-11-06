# OctopusJBBypass

八达通 iOS App 的越狱检测分析、绕过 tweak 和相关工具。

测试环境：iPhone SE3 / iOS 16.2 / Dopamine rootless。
分析版本：9.50.0（脱壳样本）、9.54.0（App Store）。Bundle ID：`com.octopuscards.octopus`。

## 实现

App 使用了三套越狱检测：`DTTJailbreakDetection`、`JailbreakCheck` 和 Promon SHIELD（`octopusx.framework`）。
SHIELD 异步返回检测结果，App 再弹出 `PromonNoticeViewController`。测试中弹窗出现后，启动流程仍会继续。

`PromonKiller.m` hook 两个 observer 注册方法，阻止检测结果传给 App，同时过滤检测提示页的弹出。
9.54.0 连续三次冷启动均保持运行，未出现越狱提示。

## 目录

```text
src/      tweak 源码
tools/    设备操作和二进制分析脚本
scripts/  macOS 构建脚本
docs/     分析记录
```

| 源码 | 用途 |
|---|---|
| [PromonKiller.m](src/PromonKiller.m) | 绕过版本，修改 3 个 ObjC 方法 |
| [OctopusJBHook.m](src/OctopusJBHook.m) | 早期版本，包含文件、环境、检测方法和 UI hook |
| [PromonNetProbe.m](src/PromonNetProbe.m) | 记录请求 URL、body 和关键词匹配结果 |
| [PromonCryptoScan.m](src/PromonCryptoScan.m) | 基于 `__DATA,__interpose` 的加密调用观测，测试中未在 ellekit 注入下生效 |
| [SymbolRebind.m](src/SymbolRebind.m) | 符号槽重绑定，记录加密调用、keychain 和网络请求 |

## 使用

构建需要 macOS、Xcode 和 iOS SDK，安装脚本依赖 Python 3 和 `paramiko`。设备需开启 SSH，并使用 ellekit 注入。

```bash
./scripts/build_mac.sh src/PromonKiller.m libPromonKiller

export IPHONE_HOST='<设备地址>'
export IPHONE_USER=mobile
export IPHONE_PASS='<SSH 密码>'

python tools/deploy_tweak.py install \
    --dylib build/libPromonKiller.dylib \
    --bundle com.octopuscards.octopus
```

安装后重新启动 App。卸载：

```bash
python tools/deploy_tweak.py remove --name libPromonKiller
```

需要调试日志时，构建时加上 `-DPROMON_KILLER_DEBUG`，再重新安装：

```bash
./scripts/build_mac.sh src/PromonKiller.m libPromonKiller '-DPROMON_KILLER_DEBUG'
```

通过 SSH 在设备上查看日志：

```bash
/usr/bin/log stream --predicate 'eventMessage CONTAINS "[PromonKiller]"' --level debug
```

出现 `swallowed -addObserver:` 表示 observer 注册已被拦截。

## 注入说明

App Store 原包仍有 FairPlay 加密。测试中经 TrollFools 修改、重签后启动崩溃，因此这里使用 ellekit 在运行时加载 tweak。

`__DATA,__interpose` 在这次 ellekit 注入测试中没有生效。C 函数 hook 改用符号槽重绑定，见 [SymbolRebind.m](src/SymbolRebind.m)。

## 分析记录

- [越狱检测](docs/01-detection.md)
- [绕过方案](docs/02-bypass.md)
- [注入崩溃分析](docs/03-crash-analysis.md)
- [encryptedInfo 与网络观测](docs/04-encryption.md)
- [分析工具](docs/05-tooling.md)
