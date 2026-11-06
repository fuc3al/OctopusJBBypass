# octopus-jb-reversing

一个 iOS App（香港八達通 / Octopus，`com.octopuscards.octopus`）**越狱检测机制的逆向记录**，
以及围绕它做的一系列绕过与观测工具。

所有实验都在**自己持有的设备**上完成：iPhone SE3（`iPhone14,6`）/ iOS 16.2 / Dopamine rootless。
仓库里**不含**任何 App 二进制、IPA、崩溃日志、账号数据或设备标识 —— 只有我们自己的代码和结论。

---

## 结论速览

| 问题 | 结论 | 依据 |
|---|---|---|
| 越狱检测有几层 | **三层**：`DTTJailbreakDetection` + 自研 `JailbreakCheck` + Promon SHIELD(`octopusx.framework`) | ObjC 元数据全量遍历 + 运行期确认 |
| 拦截是怎么实现的 | SHIELD 异步判定 → `PromonNoticeViewController`（nib + `promon.message.exit.type.N`）**present 出来**，无 `exit()`、无二次校验 | 启动时序日志 + 视图事件序列 |
| 为什么"弹一下就能进去" | 拦截页是普通 modal，被启动流程的导航替换带走；判定到达时间与首页就绪时间存在竞态 | 13:02 实测时序 |
| 会不会把越狱状态上报 | **没有专用上报通道**。A/B 对照下"检测成立"时零新增请求 | 请求集合 diff + 全量关键词扫描 |
| 唯一外泄点 | Firebase Analytics 会把 `PromonNoticeViewController` 当 `screen_view` 上报 | 抓到明文 `_vs` 事件 JSON |
| `encryptedInfo` 是什么 | 两段式信封加密：`appKey`=RSA-2048 包 AES key，`appData`=IV+AES-CBC 密文 | 677 B multipart body 完整解出 |
| 能否离线解密 | **不能**。AES 密钥运行时生成、用服务端公钥包走；AES 由纯 Swift 的 CryptoSwift 实现 | 导入表 + `nm` |
| 有没有证书固定 | 有。App keychain 里有 37 KB 的 `oepay://certPinKeystore` | 进程内 keychain 枚举 |

---

## 目录

```
src/      tweak 源码（arm64 + arm64e，clang 直接编译，无需 Theos）
tools/    设备操作与二进制分析脚本（配置全走环境变量）
scripts/  macOS 侧通用构建脚本
docs/     分析记录：检测层 / 绕过 / 崩溃 / 加密 / 工具方法
```

### src

| 文件 | 作用 |
|---|---|
| `OctopusJBHook.m` | 全量版：11 个 hook（文件/环境/进程 + ObjC + SHIELD + UI） |
| `PromonKiller.m` | **最小版**：只切 3 个方法，稳定绕过（推荐） |
| `PromonNetProbe.m` | 网络观测探针：打印请求 URL/body，扫关键词 |
| `PromonCryptoScan.m` | 加密观测探针（基于 `__DATA,__interpose`，**在 ellekit 下无效**，留作对照） |
| `SymbolRebind.m` | **符号槽重绑定**实现：`getenv` 自检 + AES/RSA/keychain 观测 + 网络日志 |

### tools

| 文件 | 作用 |
|---|---|
| `devssh.py` | SSH/SFTP 驱动（env: `IPHONE_HOST/USER/PASS`） |
| `deploy_tweak.py` | 把 dylib 装成 ellekit tweak / 强制登出 / 拉活 App |
| `dev_crashlog.py` | 拉取崩溃报告并归纳签名（env: `IPHONE_SERIAL`） |
| `verify_ipa_signature.py` | **逐页校验 CodeDirectory**，判断二进制是否被改过 |
| `inject_dylib.py` | 纯 Python 往 Mach-O 头部空余插 `LC_LOAD_DYLIB` |
| `patch_binary.py` | 静态补丁：把检测方法首指令改成 `mov w0,#0; ret` |
| `verify_hooks.js` | Frida 侧验证脚本 |

---

## 五分钟上手

```bash
# 1) 构建（macOS + Xcode）
./scripts/build_mac.sh src/PromonKiller.m libPromonKiller   # 产出 build/libPromonKiller.dylib

# 2) 装到设备（ellekit 注入，不动 App 签名）
export IPHONE_HOST=… IPHONE_USER=mobile IPHONE_PASS=…
python tools/deploy_tweak.py install \
    --dylib build/libPromonKiller.dylib --bundle com.octopuscards.octopus

# 3) 看效果
ssh mobile@$IPHONE_HOST
/usr/bin/log stream --predicate 'eventMessage CONTAINS "[PromonKiller]"' --level debug
```

验证绕过是否生效，看两个信号：

```
[PromonKiller] swallowed -addObserver:<AppDelegate: …>
promon.message.exit / PromonNoticeViewController  → 期望 0 次
```

---

## 三条最容易踩的坑

1. **不要用 TrollFools 注入 App Store 的加密二进制。**
   它会改 Mach-O 并重签，`cryptid=1` 的二进制换签名后 FairPlay 不再解密，启动即崩
   （崩溃报告里只有 2–3 个镜像）。用 ellekit 的进程级注入，App 签名和二进制都不动。

2. **在 ellekit 下 `__DATA,__interpose` 是死的。**
   ellekit 运行期 `dlopen` 注入，dyld 不会为后加载镜像处理 interpose 表。
   实测 `getenv` 自检 0 命中即为证。要 hook C 函数请改**符号槽重绑定**（见 `src/SymbolRebind.m`）。

3. **SHIELD 的类可能晚于 constructor 注册。**
   安装逻辑要幂等 + 多时机重试（constructor / 主队列 / `didFinishLaunching`），
   并且用 `method_getImplementation` 比对，避免把"自己的 hook"当原函数存下来导致无限递归。

---

## 边界

- 这是**客户端**层面的研究。检测方是本地 RASP，绕过只影响本机 UI 与本地判定。
- `encryptedInfo` 的内容无法离线还原（服务端私钥 + 运行时随机 AES key），
  仓库里只给出**结构**与**为什么解不了**，不含任何实际解密结果。
- 仓库不提供 App 二进制、密钥、证书或可直接复用的签名材料。
