# 05 · 工具与方法：怎么做这类分析

## 静态侧

脱壳样本（`cryptid=0`）之后做三件事：

1. **Mach-O 解析**：自己写 chained-fixups 解码，得到 section 表、导入符号、`__objc_classrefs` 绑定。
   （App Store 包符号表完整；第三方脱壳工具有时会抹掉 `LC_SYMTAB` 的字符串表，
   这时要靠 chained fixups 里的 bind 名还原导入表。）
2. **ObjC 元数据遍历**：`__objc_classlist` → `class_ro_t`（+24 是类名，+32 是方法列表），
   注意 **relative / small method list**：`entsizeAndFlags` 最高位为 1 时 entsize=12，
   三个 int32 都是相对偏移（nameOffset → selref 槽、typesOffset、impOffset）。
   踩过这个坑的人不少：按大列表解析会得到一堆垃圾方法名。
3. **交叉引用**：ADRP+ADD/LDR 扫描找字面量与 selref / classref 槽的引用，
   再用 Capstone 反汇编窗口，把 `__stubs` / `__objc_stubs` 的调用点还原成符号名。

## 动态侧

| 目的 | 手段 |
|---|---|
| 看时序、看谁在什么时候做了什么 | `pymobiledevice3 syslog live --udid …` 或设备上 `/usr/bin/log stream` |
| 看请求与 body | hook `NSURLSession -dataTaskWithRequest:completionHandler:` / `-uploadTaskWithRequest:fromData:` |
| 看加密入参 | 符号槽重绑定 `CCCrypt` / `SecKeyCreateEncryptedData` … |
| 看 keychain | 进程内 `SecItemCopyMatching`（只能看 App 自己那组） |
| 强制重新登录 | 摘掉 App Group 偏好里的 `AuthenticationManager.session*`，再 `killall cfprefsd` |
| 拉崩溃报告 | `tools/dev_crashlog.py --pull` |

> `log` 是 zsh 的内建命令，直接敲会被 shell 吃掉，要用 **`/usr/bin/log`**。

## 钩子选型（这段是踩坑总结）

| 需求 | 手段 | 适用 |
|---|---|---|
| 改 ObjC 方法 | `method_setImplementation` | 任何注入方式 |
| 拦 C 函数（启动期镜像内） | `DYLD_INTERPOSE` | `LC_LOAD_DYLIB` 注入 |
| 拦 C 函数（运行期 dlopen 注入） | **符号槽重绑定** | ellekit / 任何后加载场景 |
| 拦非导出 / 纯 Swift 函数 | inline hook（不改，成本高） | 最后手段 |

### 符号槽重绑定最小实现

遍历 `_dyld_image_count()`，对每个镜像取 slide，扫描 `__DATA*` 段里
`S_NON_LAZY_SYMBOL_POINTERS` / `S_LAZY_SYMBOL_POINTERS` 的 section，
把等于 `dlsym(RTLD_DEFAULT, name)` 的槽改成自己的函数：

```c
void **slots = (void **)(uintptr_t)(s->addr + (uintptr_t)slide);   // ← slide 千万别忘
if (slots[j] == target) {
    mprotect(page, getpagesize(), PROT_READ | PROT_WRITE);
    slots[j] = replacement;
}
```

两个必须注意的点：

- **ASLR slide**：`s->addr` 是链接期地址，直接用会读到未映射内存（第一版就这么崩的）。
- **延迟绑定**：`S_LAZY_SYMBOL_POINTERS` 的槽在首次调用前存的是 stub 地址，
  不等于是目标的真实地址，会漏补；所以除了启动时补一遍，还要**定时重补**几轮
  （`src/SymbolRebind.m` 里是每秒一次 × 25 轮）。

### 自检

任何 hook 框架写完，先用一个**必然会被调用**的函数验证机制：

```c
static const char *my_getenv(const char *name) {
    static int n = 0;
    if (n++ < 2) NSLog(@"[probe] getenv hit: %s", name);
    return orig_getenv(name);
}
```

`getenv` 在启动阶段会被打几百次，看到命中就说明整套机制通了；
看不到就说明 interpose/重绑定压根没生效，先别怀疑业务路径。

## 观测代码的写法约定

- 每个 hook 都 `@try/@catch` 包住日志逻辑，**绝不让观测代码把目标进程搞崩**。
- 日志前缀统一（`[PromonKiller]` / `[SymRebind]` / `[NetProbe]`），方便 `log stream --predicate` 过滤。
- 观测 dylib 与绕过 dylib 分开：观测版带 `-DEBUG` 宏，正式版不 `NSLog`。
- 不要在一个 App 上同时装两个 tweak —— 实测 ellekit 在这种情况下**一个都不注入**。

## 目录对照

```
src/OctopusJBHook.m     v1/v2 全量绕过（含 interpose 版文件钩子，作参考）
src/PromonKiller.m      最小绕过（生产用）
src/PromonNetProbe.m    ObjC 网络观测
src/PromonCryptoScan.m  interpose 版加密观测（在 ellekit 下无效，作反面对照）
src/SymbolRebind.m      符号槽重绑定 + 自检 + AES/RSA/keychain 观测 + 网络日志
```
