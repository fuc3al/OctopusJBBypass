# 分析工具

## 静态分析

主要处理 Mach-O、ObjC 元数据和调用点：

1. 解析 chained fixups，读取 section、导入符号和 `__objc_classrefs` 绑定。样本缺少 `LC_SYMTAB` 字符串表时，可从 fixups 的 bind 名称补充导入信息。
2. 从 `__objc_classlist` 遍历到 `class_ro_t`，读取类名和方法列表。64 位布局中，类名和方法列表分别位于 `+24`、`+32`。
3. 处理 relative / small method list。`entsizeAndFlags` 最高位为 1 时，每项为三个 int32 相对偏移，不能按普通方法列表解析。
4. 查找 ADRP+ADD/LDR 对字面量、selref、classref 的引用，用 Capstone 反汇编调用点，并关联 `__stubs`、`__objc_stubs` 中的符号。

## 运行观测

| 内容 | 方法 |
|---|---|
| 启动时序 | `pymobiledevice3 syslog live --udid <UDID>` 或设备上的 `/usr/bin/log stream` |
| 请求 URL 和 body | hook `NSURLSession` 的请求方法 |
| C 层加密调用 | 重绑定 `CCCrypt`、`SecKeyCreateEncryptedData` 等符号 |
| keychain 条目 | 进程内调用 `SecItemCopyMatching` |
| 崩溃报告 | `python tools/dev_crashlog.py --pull <目录>` |

设备上查看日志时使用完整路径 `/usr/bin/log`，避免与 shell 内建命令重名。

## Hook 方式

| 目标 | 项目中使用的方式 |
|---|---|
| ObjC 方法 | `method_setImplementation` |
| 启动时加载镜像中的 C 函数 | `DYLD_INTERPOSE` |
| ellekit 运行时加载后的 C 函数 | 符号槽重绑定 |
| 非导出 Swift 函数 | 尚未实现 |

### 符号槽重绑定

[SymbolRebind.m](../src/SymbolRebind.m) 遍历已加载镜像，扫描 `__DATA*` 段中的 `S_NON_LAZY_SYMBOL_POINTERS` 和 `S_LAZY_SYMBOL_POINTERS`。
找到指向目标函数的槽后，将其替换为 hook 函数：

```c
void **slots = (void **)(uintptr_t)(s->addr + (uintptr_t)slide);
if (slots[j] == target) {
    mprotect(page, getpagesize(), PROT_READ | PROT_WRITE);
    slots[j] = replacement;
}
```

这里有两个需要处理的细节：

- `s->addr` 是链接时地址，访问前需要加上 ASLR slide。
- 延迟绑定的槽在首次调用前可能仍指向 stub。当前实现每秒重新扫描一次，共 25 轮。

### 检查是否命中

使用启动时会调用的 `getenv` 检查重绑定，并限制日志数量：

```c
static const char *my_getenv(const char *name) {
    static int n = 0;
    if (n++ < 2) NSLog(@"[probe] getenv hit: %s", name);
    return orig_getenv(name);
}
```

若 `getenv` 已命中而加密函数没有调用记录，再检查目标是否经过对应的加密入口。

`PromonKiller.m` 的日志由 `PROMON_KILLER_DEBUG` 控制；其他观测源码需查看各自的日志宏。

## 工具索引

| 文件 | 用途 |
|---|---|
| [devssh.py](../tools/devssh.py) | SSH 命令和 SFTP 文件传输，使用 `IPHONE_HOST`、`IPHONE_USER`、`IPHONE_PASS` |
| [deploy_tweak.py](../tools/deploy_tweak.py) | 安装、卸载 tweak，启动 App 和清理会话偏好 |
| [dev_crashlog.py](../tools/dev_crashlog.py) | 拉取和整理崩溃报告，设备选择使用 `IPHONE_SERIAL` |
| [verify_ipa_signature.py](../tools/verify_ipa_signature.py) | 检查 CodeDirectory 摘要和加载库路径 |
| [inject_dylib.py](../tools/inject_dylib.py) | 向 Mach-O 添加 `LC_LOAD_DYLIB` |
| [patch_binary.py](../tools/patch_binary.py) | 修改检测方法的返回值 |
| [verify_hooks.js](../tools/verify_hooks.js) | 通过 Frida 检查 hook 结果 |
