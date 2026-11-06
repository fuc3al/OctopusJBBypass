# encryptedInfo 与网络观测

## 请求结构

接口为 `POST /ow_owallet_ws/rest/authenticate/encryptedInfo`，使用 `multipart/form-data`。
记录中的请求体为 677 B，包含 `appData` 和 `appKey`：

```text
--alamofire.boundary.xxxxxxxx
Content-Disposition: form-data; name="appData"; filename="appData"
Content-Type: application/octet-stream

<16 B IV + AES-CBC 密文>

--alamofire.boundary.xxxxxxxx
Content-Disposition: form-data; name="appKey"; filename="appKey"
Content-Type: application/octet-stream

<约 256 B RSA-2048 密文>
```

请求采用信封加密：

| 字段 | 内容 |
|---|---|
| `appKey` | 运行时生成的 AES 密钥，经服务端 RSA 公钥加密 |
| `appData` | 使用该 AES 密钥加密的数据，前 16 B 为 IV |

离线还原需要对应的 AES 密钥，或用于解开 `appKey` 的 RSA 私钥。目前只拿到了请求密文，未取得明文。

## 加密调用

App 的导入表中包含 `CryptoSwift.AES: Cipher` 的 witness table，没有直接导入 `CCCrypt`、`SecKeyEncrypt` 或 `SecKeyCreateEncryptedData`。
另外还有 JOSESwift 的验签相关符号和 SwiftyRSA 的公钥相关符号。

AES 调用推测通过 `Cipher` 协议派发，形式类似：

```swift
let cipher: any Cipher = AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
try cipher.encrypt(bytes)
```

CryptoSwift 的 AES 使用 Swift 实现。本次符号槽重绑定的结果为：

| 函数 | 结果 |
|---|---|
| `CCCrypt` | 未命中 |
| `CCCryptorCreate` / `CCCryptorUpdate` | 未命中 |
| `SecKeyCreateEncryptedData` / `SecKeyEncrypt` | 未命中 |
| `getenv` | 有调用记录，用于检查重绑定是否生效 |

目前没有从这些 C 函数入口截取到加密参数。继续分析需要沿 `AES: Cipher` 的 witness table 定位 Swift 实现，并处理对应 ABI；这部分尚未实现。

## 越狱状态与请求变化

以下四种状态下，记录到的 `encryptedInfo` 请求体均为 677 B：

- 绕过生效，未出现检测提示。
- 检测提示已弹出。
- 强制登出后重新登录。
- 再次登录。

检测提示出现前后的请求对比中，也没有观察到新增的专用上报请求。
这些记录能说明请求数量和长度没有变化，密文里的字段仍未确定。

另一个已观察到的上报来自 Firebase Analytics：`PromonNoticeViewController` 会作为 `screen_view` 记录，对应 `_vs` 事件。

## 证书固定相关条目

App 的 keychain 中存在 `oepay://certPinKeystore`，大小约 37 KB。当前工具通过进程内 hook 记录请求和加密调用。
