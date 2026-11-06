# 04 · `encryptedInfo` 的结构，以及为什么解不开

## 抓到了什么

`POST /ow_owallet_ws/rest/authenticate/encryptedInfo`，`multipart/form-data`，**677 B**。
把完整 body 落盘后解开（hex → bytes）：

```
--alamofire.boundary.xxxxxxxx
Content-Disposition: form-data; name="appData"; filename="appData"
Content-Type: application/octet-stream

<二进制：16 B IV + AES-CBC 密文>

--alamofire.boundary.xxxxxxxx
Content-Disposition: form-data; name="appKey"; filename="appKey"
Content-Type: application/octet-stream

<二进制：约 256 B，RSA-2048 密文>
```

**两段式信封加密**：

| 字段 | 内容 |
|---|---|
| `appKey` | 运行时随机生成的 AES 密钥，用服务端 RSA 公钥（OAEP）包裹 |
| `appData` | 那把一次性密钥做的 AES-CBC 加密，前 16 B 是 IV |

要还原明文 = 用服务端**私钥**解 `appKey` → 拿 AES key → 解 `appData`。
两边都不在我们手上，所以**离线解密在密码学上不成立**，不是工具问题。

## 为什么所有 C 层钩子都是 0 命中

先看这份 App 到底导入了什么（App Store 原包符号表完整，1616 条 chained imports）：

```
CryptoSwift        1 条
   _$s11CryptoSwift3AESCAA6CipherAAWP        ← 只有 AES: Cipher 的 witness table

CCCrypt            0 条
SecKeyEncrypt      0 条
SecKeyCreate…      0 条
CryptoKit          0 条

JOSESwift          6 条  (JWS / Payload / Verifier —— 验签用)
SwiftyRSA          3 条  (PublicKey 协议一致性 / Error —— 只用公钥)
```

也就是说加密调用长这样：

```swift
let cipher: any Cipher = AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
try cipher.encrypt(bytes)          // 协议方法，走 witness table 动态派发
```

不走 `Data.encrypt(cipher:)`（未导入），也不走任何 CommonCrypto 符号。
`CryptoSwift` 的 AES 是**纯 Swift 实现**，所以：

| 尝试的钩子 | 结果 |
|---|---|
| `CCCrypt`（3 个镜像） | 0 |
| `CCCryptorCreate` / `CCCryptorUpdate` | 0 |
| `SecKeyCreateEncryptedData`（3 个镜像） | 0 |
| `SecKeyEncrypt` | 0 |
| `getenv`（对照组，验证机制本身） | **有命中** |

对照组证明符号重绑定是好的 —— 0 命中是因为**这条路径根本不经过 C 符号**。

## 继续下去需要什么

唯一可行的是 **inline hook**：

1. 从 `AES: Cipher` 的 witness table 里解出 `encrypt` 的内部实现地址（未导出）；
2. 写 ABI 完全一致的替身（Swift 协议方法：`self` 在 x20、`[UInt8]` 间接返回、`throws` 用 swifterror）；
3. 在 arm64 上做指令重定位（`adrp/add`、`ldr literal` 都要修）。

成本高且脆弱，本项目**不实现**。

## 一个间接但有力的结论

`encryptedInfo` 的 677 B 在四种状态下长度**完全一致**：

| 场景 | 长度 |
|---|---|
| 抑制生效，检测不成立 | 677 |
| 检测成立并弹窗 | 677 |
| 强制登出后重新登录 | 677 |
| 再次登录 | 677 |

长度恒定 + 每次登录只生成一次（缓存复用）→ 它是**设备静态信息**，
不随越狱判定变化。结合"检测成立时零新增请求"的 A/B 对照，可以确认：
**这条加密通道里没有越狱状态字段。**

## 顺带发现：证书固定

在 App 进程内用 `SecItemCopyMatching` 枚举它自己的 keychain：

```
svc=oepay://certPinKeystore  acct=certPinKeystore  len=37609   ← 37 KB 的 pinning keystore
svc=com.firebase.FIRInstallations.installations  len=450
svc=BranchKeychainService  acct=BranchKeychainFirstBuild/FirstInstall/Temp  len=223 ×3
svc=com.octopuscards.octopus  acct=_pfo  len=1
```

pinning 是开着的 —— 抓包代理没有意义，"进程内、加密前"截取才是可行路径。
