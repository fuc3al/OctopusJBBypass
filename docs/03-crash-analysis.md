# 注入崩溃分析

## 崩溃现象

TrollFools 注入 App Store 原包后，App 在启动阶段崩溃：

- `usedImages` 只有 2–3 个镜像。
- 异常为 `EXC_BAD_ACCESS / SIGSEGV`，子类型为 `KERN_PROTECTION_FAILURE`。
- 栈中有 511 帧 `_malloc_zone_malloc_instrumented_or_legacy` 递归，触及栈保护页。

9.50/9.52 的较早崩溃记录则是 `EXC_BREAKPOINT / SIGTRAP`，栈中出现 `libswiftCore.dylib` 的 `_assertionFailure`，已加载 17–21 个镜像。两类崩溃发生的阶段不同。

## FairPlay 与重签

App Store 原包的加密信息为：

```text
LC_ENCRYPTION_INFO_64
cryptoff=163840  cryptsize=4096  cryptid=1
```

TrollFools 注入会修改 Mach-O 并重新签名。修改后 App 在 dyld 的 `map_images` 阶段崩溃，tweak 的 constructor 尚未执行。
同样的注入方式用于 `cryptid=0` 的 9.50.0 脱壳包时，可以正常启动。这些现象指向重签后的 FairPlay 解密问题。

因此，App Store 原包使用 ellekit 在运行时加载 tweak。

## 检查二进制是否改动

[verify_ipa_signature.py](../tools/verify_ipa_signature.py) 按 CodeDirectory 中的摘要逐页检查代码：

```bash
python tools/verify_ipa_signature.py <可执行文件>
```

测试样本的结果为：

```text
hash       : sha1  page=4096  slots=17490  codeLimit=71637936
page check : 17490/17490 pages match
```

这表示受检查的代码页与 CodeDirectory 中的摘要一致。脚本还会列出 `LC_LOAD_DYLIB`，标记 `/var/jb`、Substrate、TrollFools、Frida 等路径。

## interpose 未生效

本次测试中，启动时通过 `LC_LOAD_DYLIB` 加载的 interpose 可以生效，ellekit 运行时加载的 `__DATA,__interpose` 则未命中。ObjC 方法替换不受这个问题影响。

改用 [SymbolRebind.m](../src/SymbolRebind.m) 的符号槽重绑定后，`getenv` 出现调用记录：

```text
patched getenv in systemhook.dylib (__auth_got)
patched getenv in octopusx (__got)
patched getenv in libdispatch.dylib (__auth_got)
getenv hit: DYLD_VERSIONED_LIBRARY_PATH
```

## 崩溃报告

排查时先看加载镜像、异常类型和出错线程的栈：

| 字段 | 本次记录中的表现 |
|---|---|
| `usedImages` | 仅加载少量镜像，崩溃发生在启动早期 |
| `exception.type` | `EXC_BREAKPOINT / SIGTRAP` 配合 Swift assertion 栈，定位主动断言退出 |
| `faultingThread` | 大量重复栈帧并触及栈保护页，定位递归导致的栈溢出 |

批量整理报告：

```bash
python tools/dev_crashlog.py --sig <报告目录> --match <App名称>
```
