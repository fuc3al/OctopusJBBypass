# 03 · 崩溃分析：为什么 TrollFools 注入会闪退

## 现象

注入后 App 一启动就退出，崩溃报告里 `usedImages` **只有 2–3 个镜像**，栈是 511 帧的
`_malloc_zone_malloc_instrumented_or_legacy` 递归，异常类型 `EXC_BAD_ACCESS / SIGSEGV`，
`subtype: KERN_PROTECTION_FAILURE`（栈保护页）。

而**历史崩溃**（注入之前、9.50/9.52 版本）签名完全不同：

```
EXC_BREAKPOINT / SIGTRAP
libswiftCore.dylib _assertionFailure(_:_:file:line:flags:)   ← App 自己的 fatalError
usedImages = 17~21
```

也就是说：App 本来就有"检测到就 fatalError"的硬退路径，而注入后的那种崩溃是**另一回事**。

## 根因

设备上那份是 App Store 原包：

```
LC_ENCRYPTION_INFO_64  cryptoff=163840  cryptsize=4096  cryptid=1   ← 仍是 FairPlay 加密
```

TrollFools 注入必须改 Mach-O 并**重新签名**。Apple 的签名一旦被替换，
内核就不会再为这个二进制做 FairPlay 解密 → dyld 在 `map_images` 阶段直接死掉，
我们的 `constructor` 根本没机会执行（所以崩溃报告里从来没有我们的镜像）。

对照组：自己脱壳的 9.50.0 IPA 是 `cryptid=0`，注入 + 重签后可以正常跑。

## 怎么证明"App 现在是纯净的"

`tools/verify_ipa_signature.py` 直接拿 CodeDirectory 的哈希逐页重算：

```
$ python tools/verify_ipa_signature.py <可执行文件>

identifier      : com.example.app
team            : XXXXXXXXXX
cd version      : 0x20500   flags=0x0   platform=0
hash            : sha1  page=4096  slots=17490  codeLimit=71637936
page check      : 17490/17490 pages match
               => every code page matches Apple's signature: BINARY IS UNMODIFIED
```

页数全对 = 二进制与 Apple 签发时逐字节一致；只要加过一条 `LC_LOAD_DYLIB`，对应页必然 MISMATCH。

同一脚本还会打印 `LC_LOAD_DYLIB` 清单并标出异常路径（`/var/jb`、Substrate、TrollFools、frida 等）：

```
LC_LOAD_DYLIB   : 150 entries
  unusual paths : none
  jailbreak libs: none
```

## 另一个坑：注入方式决定能否 hook

| 注入方式 | 镜像何时加载 | `__DATA,__interpose` | ObjC hook |
|---|---|---|---|
| `LC_LOAD_DYLIB`（启动期） | 启动时 | ✅ 生效 | ✅ |
| ellekit `dlopen`（运行期） | 启动后 | ❌ **被 dyld 忽略** | ✅ |

实测自检（`src/SymbolRebind.m` 里对 `getenv` 做重绑定并只打印前两次调用）：

```
[SymRebind] loaded pid=34959
[SymRebind] ready
getenv 自检 = 0        ← interpose 一次都没触发
```

对照组换成符号槽重绑定后立刻有命中：

```
patched getenv in systemhook.dylib (__auth_got)
patched getenv in octopusx (__got)
patched getenv in libdispatch.dylib (__auth_got)
armed (getenv=7 aes=3 aesupd=1 rsa=3)
getenv hit: DYLD_VERSIONED_LIBRARY_PATH
```

## 崩溃报告怎么读

三个字段足够定位"是不是我的锅"：

| 字段 | 含义 |
|---|---|
| `usedImages` 数量 | 只有个位数 → 死在 dyld 早期，与注入的代码无关 |
| `exception.type` | `EXC_BREAKPOINT/SIGTRAP` + `swift_unexpectedError` → App 自己 fatalError |
| `faultingThread` 栈顶 | 511 帧同类递归 + 栈保护页 → 栈溢出（通常是无限递归） |

`tools/dev_crashlog.py --sig DIR AppName` 会把这几项直接打成一行，方便横向对比。
