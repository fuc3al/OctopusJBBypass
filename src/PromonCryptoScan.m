// PromonCryptoScan.m (v2) — 捕获 encryptedInfo 的加密前明文。
//
// v1 在 constructor 里遍历全部 ObjC 类（class_copyMethodList），把 App 卡死在
// dyld 初始化阶段。v2 去掉枚举，只保留三个高收益钩子：
//   1) +[NSJSONSerialization dataWithJSONObject:options:error:]  → 加密前的 JSON 明文
//   2) CCCrypt()                                                  → AES 明文/密文
//   3) SecKeyCreateEncryptedData() / SecKeyEncrypt()               → RSA 明文
//
// 2/3 依赖 DYLD_INTERPOSE；ellekit 走 launchd 的 DYLD_INSERT_LIBRARIES，
// 属于启动期镜像，interpose 生效。若日志里看不到 [C] 行，就说明走的是 dlopen 注入，
// 那 1) 仍然能拿到明文。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

#define CS(fmt, ...) NSLog(@"[CryptScan] " fmt, ##__VA_ARGS__)

struct cs_interpose_pair { const void *replacement; const void *replacee; };

#define CS_INTERPOSE(_repl, _orig)                                                    \
    __attribute__((used, section("__DATA,__interpose"), visibility("hidden")))        \
    const struct cs_interpose_pair _interpose_##_orig = {                              \
        (const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_orig,      \
    };


// ------------------------------------------------- 0) interpose 自检
extern const struct cs_interpose_pair _interpose_getenv;
static const char *cs_getenv(const char *name) {
    static int logged = 0;
    if (logged < 3) { logged++; CS(@"[getenv] %s", name ? name : "(null)"); }
    return ((const char *(*)(const char *))_interpose_getenv.replacee)(name);
}
CS_INTERPOSE(cs_getenv, getenv)

// ------------------------------------------------------------ 1) JSON 明文

static NSData *(*cs_json)(id, SEL, id, NSJSONWritingOptions, NSError **);

static BOOL CSHasDeviceFields(NSString *s) {
    NSString *low = s.lowercaseString;
    static NSArray *kw;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        kw = @[@"device", @"jail", @"model", @"uuid", @"vendor", @"idfv", @"idfa",
               @"osversion", @"os_version", @"sdk", @"tamper", @"integrity",
               @"encrypt", @"appversion", @"resversion", @"locale", @"platform"];
    });
    NSInteger hits = 0;
    for (NSString *k in kw) if ([low containsString:k]) hits++;
    return hits >= 2;
}

static NSData *cs_jsonHook(id self, SEL _cmd, id obj, NSJSONWritingOptions opt, NSError **err) {
    NSData *out = cs_json(self, _cmd, obj, opt, err);
    @try {
        if (out.length > 0 && out.length < 8000) {
            NSString *s = [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
            if (s) {
                CS(@"JSON(%luB): %@", (unsigned long)out.length,
                   s.length > 1500 ? [s substringToIndex:1500] : s);
            }
        }
    } @catch (NSException *e) {}
    return out;
}

// ------------------------------------------------------- 2) AES / 3) RSA

// (macro moved to top)

extern const struct cs_interpose_pair _interpose_CCCrypt;
extern const struct cs_interpose_pair _interpose_SecKeyCreateEncryptedData;

static CCCryptorStatus cs_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                                  const void *key, size_t keyLength, const void *iv,
                                  const void *dataIn, size_t dataInLength,
                                  void *dataOut, size_t dataOutAvailable,
                                  size_t *dataOutMoved) {
    CCCryptorStatus st = ((CCCryptorStatus (*)(CCOperation, CCAlgorithm, CCOptions,
                                               const void *, size_t, const void *,
                                               const void *, size_t, void *, size_t, size_t *))
                          _interpose_CCCrypt.replacee)(op, alg, options, key, keyLength, iv,
                                                       dataIn, dataInLength, dataOut,
                                                       dataOutAvailable, dataOutMoved);
    @try {
        if (op == kCCEncrypt && dataIn && dataInLength > 8 && dataInLength < 8192) {
            NSData *in = [NSData dataWithBytes:dataIn length:dataInLength];
            NSString *s = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding];
            CS(@"[AES] alg=%u keyLen=%zu inLen=%zu out=%d plain=%@",
               (unsigned)alg, keyLength, dataInLength, (int)st,
               s ? (s.length > 1200 ? [s substringToIndex:1200] : s)
                 : [NSString stringWithFormat:@"<bin %luB>", (unsigned long)dataInLength]);
        }
    } @catch (NSException *e) {}
    return st;
}
CS_INTERPOSE(cs_CCCrypt, CCCrypt)

static SecKeyRef cs_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                              CFDataRef plaintext, CFErrorRef *error) {
    @try {
        NSData *p = (__bridge NSData *)plaintext;
        if (p.length && p.length < 8192) {
            NSString *s = [[NSString alloc] initWithData:p encoding:NSUTF8StringEncoding];
            CS(@"[RSA] plainLen=%lu plain=%@", (unsigned long)p.length,
               s ? [s stringByReplacingOccurrencesOfString:@"\n" withString:@" "] : @"<bin>");
        }
    } @catch (NSException *e) {}
    return ((SecKeyRef (*)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *))
            _interpose_SecKeyCreateEncryptedData.replacee)(key, algorithm, plaintext, error);
}
CS_INTERPOSE(cs_SecKeyCreateEncryptedData, SecKeyCreateEncryptedData)


// ------------------------------------------- 2b) 流式 CommonCrypto + SecKeyEncrypt

extern const struct cs_interpose_pair _interpose_CCCryptorCreate;
extern const struct cs_interpose_pair _interpose_CCCryptorUpdate;
extern const struct cs_interpose_pair _interpose_SecKeyEncrypt;

static CCCryptorStatus cs_CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
                                          const void *key, size_t keyLength, const void *iv,
                                          CCCryptorRef *cryptorRef) {
    CS(@"[AES-init] op=%u alg=%u keyLen=%zu iv=%s", (unsigned)op, (unsigned)alg, keyLength,
       iv ? @"yes" : @"no");
    return ((CCCryptorStatus (*)(CCOperation, CCAlgorithm, CCOptions, const void *,
                                 size_t, const void *, CCCryptorRef *))
            _interpose_CCCryptorCreate.replacee)(op, alg, options, key, keyLength, iv, cryptorRef);
}
CS_INTERPOSE(cs_CCCryptorCreate, CCCryptorCreate)

static CCCryptorStatus cs_CCCryptorUpdate(CCCryptorRef ref, const void *dataIn, size_t dataInLength,
                                          void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    @try {
        if (dataIn && dataInLength > 8 && dataInLength < 8192) {
            NSData *in = [NSData dataWithBytes:dataIn length:dataInLength];
            NSString *t = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding];
            if (!t) t = [[NSString alloc] initWithData:in encoding:NSISOLatin1StringEncoding];
            CS(@"[AES-upd] len=%zu plain=%@", dataInLength,
               t ? (t.length > 800 ? [t substringToIndex:800] : t)
                 : [NSString stringWithFormat:@"<bin %luB>", (unsigned long)dataInLength]);
        }
    } @catch (NSException *e) {}
    return ((CCCryptorStatus (*)(CCCryptorRef, const void *, size_t, void *, size_t, size_t *))
            _interpose_CCCryptorUpdate.replacee)(ref, dataIn, dataInLength, dataOut,
                                                 dataOutAvailable, dataOutMoved);
}
CS_INTERPOSE(cs_CCCryptorUpdate, CCCryptorUpdate)

static OSStatus cs_SecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText,
                                 size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen) {
    @try {
        if (plainText && plainTextLen && plainTextLen < 8192) {
            NSData *in = [NSData dataWithBytes:plainText length:plainTextLen];
            NSString *t = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding];
            CS(@"[RSA2] len=%zu plain=%@", plainTextLen, t ? t : @"<bin>");
        }
    } @catch (NSException *e) {}
    return ((OSStatus (*)(SecKeyRef, SecPadding, const uint8_t *, size_t, uint8_t *, size_t *))
            _interpose_SecKeyEncrypt.replacee)(key, padding, plainText, plainTextLen,
                                               cipherText, cipherTextLen);
}
CS_INTERPOSE(cs_SecKeyEncrypt, SecKeyEncrypt)


// ------------------------------------------------ 4) 请求体抓取（确认 JWE 结构）
static id (*cs_dt)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static id cs_dataTaskHandlerHook(id self, SEL _cmd, NSURLRequest *req,
                                 void (^h)(NSData *, NSURLResponse *, NSError *)) {
    @try {
        NSURL *u = req.URL;
        NSData *b = req.HTTPBody;
        CS(@"REQ %@ %@ len=%lu ct=%@", req.HTTPMethod ?: @"?",
           u.absoluteString ?: @"?", (unsigned long)b.length,
           [req valueForHTTPHeaderField:@"Content-Type"] ?: @"-");
        if (b.length && b.length < 4000) {
            NSString *t = [[NSString alloc] initWithData:b encoding:NSUTF8StringEncoding];
            if (t) CS(@"   body: %@", [t stringByReplacingOccurrencesOfString:@"\n" withString:@" "]);
            else {
                NSMutableString *hx = [NSMutableString string];
                const uint8_t *p2 = b.bytes;
                for (NSUInteger i = 0; i < MIN(b.length, (NSUInteger)400); i++)
                    [hx appendFormat:@"%02x", p2[i]];
                CS(@"   body-hex: %@", hx);
            }
        }
    } @catch (NSException *e) {}
    return cs_dt(self, _cmd, req, h);
}

static id (*cs_up)(id, SEL, NSURLRequest *, NSData *);
static id cs_uploadHook(id self, SEL _cmd, NSURLRequest *req, NSData *data) {
    @try {
        NSData *b = data.length ? data : req.HTTPBody;
        CS(@"UPLOAD %@ len=%lu ct=%@", req.URL.absoluteString ?: @"?",
           (unsigned long)b.length, [req valueForHTTPHeaderField:@"Content-Type"] ?: @"-");
        if (b.length && b.length < 4000) {
            NSString *t = [[NSString alloc] initWithData:b encoding:NSUTF8StringEncoding];
            if (t) {
                CS(@"   body: %@", [t stringByReplacingOccurrencesOfString:@"\n" withString:@" "]);
            } else {
                NSMutableString *hx = [NSMutableString string];
                const uint8_t *q = b.bytes;
                for (NSUInteger i = 0; i < MIN(b.length, (NSUInteger)900); i++)
                    [hx appendFormat:@"%02x", q[i]];
                CS(@"   body-hex: %@", hx);
            }
        }
    } @catch (NSException *e) {}
    return cs_up(self, _cmd, req, data);
}

static void CSInstallNetHooks(void) {
    Class s = objc_getClass("NSURLSession"); if (!s) return;
    Method m = class_getInstanceMethod(s, @selector(dataTaskWithRequest:completionHandler:));
    if (m) { cs_dt = (void *)method_getImplementation(m);
             method_setImplementation(m, (IMP)cs_dataTaskHandlerHook); }
    m = class_getInstanceMethod(s, @selector(uploadTaskWithRequest:fromData:));
    if (m) { cs_up = (void *)method_getImplementation(m);
             method_setImplementation(m, (IMP)cs_uploadHook); }
}

__attribute__((constructor))
static void PromonCryptoScanInit(void) {
    @autoreleasepool {
        CS(@"loaded pid=%d", getpid());
        Class js = objc_getClass("NSJSONSerialization");
        Method m = js ? class_getClassMethod(js, @selector(dataWithJSONObject:options:error:)) : NULL;
        if (m) {
            cs_json = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)cs_jsonHook);
            CS(@"json hook on");
        }
        CSInstallNetHooks();
        CS(@"ready");
    }
}
