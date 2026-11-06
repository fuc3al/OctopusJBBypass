// SymbolRebind.m — 运行期符号重绑定（fishhook 思路），替代失效的 DYLD_INTERPOSE。
//
// 背景：ellekit 用 dlopen 在启动后注入，dyld 不会为后加载镜像处理 __DATA,__interpose，
// 实测 getenv 自检 0 命中。所以改为直接改各镜像 __got / __la_symbol_ptr 里的函数指针。
//
// 先做两件事：
//   1) 自检：重绑定 getenv，看是否命中 —— 验证机制可用
//   2) 抓明文：CCCrypt / CCCryptorCreate / CCCryptorUpdate / SecKeyCreateEncryptedData

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/vm_page_size.h>
#import <mach/vm_map.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#include <dlfcn.h>

#define SR(fmt, ...) NSLog(@"[SymRebind] " fmt, ##__VA_ARGS__)

typedef struct { const char *name; void *replacement; void *original; int patched; } sr_entry;

// ---------------------------------------------------------------- 重绑定核心

static int sr_patch_slot(void **slot, void *replacement) {
    void *old = *slot;
    if (old == replacement) return 0;
    void *page = (void *)((uintptr_t)slot & ~(uintptr_t)(getpagesize() - 1));
    if (mprotect(page, getpagesize(), PROT_READ | PROT_WRITE) != 0 &&
        mprotect(page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }
    *slot = replacement;
    return 1;
}

static void sr_rebind(sr_entry *e) {
    void *target = dlsym(RTLD_DEFAULT, e->name);
    if (!target) { SR(@"target %s not found", e->name); return; }
    e->original = target;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        const char *img = _dyld_get_image_name(i);
        const uint8_t *p = (const uint8_t *)(hdr + 1);
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (strncmp(seg->segname, "__DATA", 6) == 0) {
                    const struct section_64 *s = (const struct section_64 *)(seg + 1);
                    for (uint32_t k = 0; k < seg->nsects; k++, s++) {
                        uint32_t t = s->flags & SECTION_TYPE;
                        if (t != S_NON_LAZY_SYMBOL_POINTERS && t != S_LAZY_SYMBOL_POINTERS) continue;
                        void **slots = (void **)(uintptr_t)(s->addr + (uintptr_t)slide);
                        size_t count = s->size / sizeof(void *);
                        for (size_t j = 0; j < count; j++) {
                            if (slots[j] == target) {
                                if (sr_patch_slot(&slots[j], e->replacement) > 0) {
                                    e->patched++;
                                    SR(@"patched %s in %s (%s)", e->name,
                                       img ? strrchr(img, '/') ? strrchr(img, '/') + 1 : img : "?",
                                       s->sectname);
                                }
                            }
                        }
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    if (!e->patched) SR(@"no slot for %s", e->name);
}

// ------------------------------------------------------------- 1) getenv 自检

static const char *(*sr_getenv_orig)(const char *);
static const char *sr_getenv(const char *name) {
    static int logged = 0;
    if (logged < 2) { logged++; SR(@"getenv hit: %s", name ? name : "(null)"); }
    return sr_getenv_orig(name);
}

// --------------------------------------------------------------- 2) 加密钩子

static CCCryptorStatus (*sr_CCCrypt_orig)(CCOperation, CCAlgorithm, CCOptions, const void *,
                                          size_t, const void *, const void *, size_t,
                                          void *, size_t, size_t *);
static CCCryptorStatus sr_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                  const void *key, size_t keyLen, const void *iv,
                                  const void *in, size_t inLen,
                                  void *out, size_t outAvail, size_t *outMoved) {
    @try {
        if (op == kCCEncrypt && in && inLen > 8 && inLen < 8192) {
            NSData *d = [NSData dataWithBytes:in length:inLen];
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (!s) s = [[NSString alloc] initWithData:d encoding:NSISOLatin1StringEncoding];
            SR(@"[AES] alg=%u keyLen=%zu in=%zu plain=%@", (unsigned)alg, keyLen, inLen,
               s ? (s.length > 900 ? [s substringToIndex:900] : s) : @"<bin>");
        }
    } @catch (NSException *e) {}
    return sr_CCCrypt_orig(op, alg, opts, key, keyLen, iv, in, inLen, out, outAvail, outMoved);
}

static CCCryptorStatus (*sr_CCUpdate_orig)(CCCryptorRef, const void *, size_t, void *, size_t, size_t *);
static CCCryptorStatus sr_CCUpdate(CCCryptorRef ref, const void *in, size_t inLen,
                                   void *out, size_t outAvail, size_t *outMoved) {
    @try {
        if (in && inLen > 8 && inLen < 8192) {
            NSData *d = [NSData dataWithBytes:in length:inLen];
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (!s) s = [[NSString alloc] initWithData:d encoding:NSISOLatin1StringEncoding];
            SR(@"[AES-upd] in=%zu plain=%@", inLen,
               s ? (s.length > 900 ? [s substringToIndex:900] : s) : @"<bin>");
        }
    } @catch (NSException *e) {}
    return sr_CCUpdate_orig(ref, in, inLen, out, outAvail, outMoved);
}

static SecKeyRef (*sr_SKEnc_orig)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static SecKeyRef sr_SKEnc(SecKeyRef key, SecKeyAlgorithm alg, CFDataRef plain, CFErrorRef *err) {
    @try {
        NSData *d = (__bridge NSData *)plain;
        if (d.length && d.length < 8192) {
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            SR(@"[RSA] alg=%@ plainLen=%lu plain=%@", (__bridge NSString *)alg,
               (unsigned long)d.length, s ? s : @"<bin>");
        }
    } @catch (NSException *e) {}
    return sr_SKEnc_orig(key, alg, plain, err);
}


// ------------------------------------------------------------ 3) 请求体日志
static id (*sr_dt)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static id sr_dataTaskHook(id self, SEL _cmd, NSURLRequest *req,
                          void (^h)(NSData *, NSURLResponse *, NSError *)) {
    @try {
        NSData *b = req.HTTPBody;
        SR(@"REQ %@ %@ len=%lu ct=%@", req.HTTPMethod ?: @"?",
           req.URL.absoluteString ?: @"?", (unsigned long)b.length,
           [req valueForHTTPHeaderField:@"Content-Type"] ?: @"-");
        if (b.length && b.length < 4000) {
            NSString *t = [[NSString alloc] initWithData:b encoding:NSUTF8StringEncoding];
            if (t) {
                SR(@"   body: %@", [t stringByReplacingOccurrencesOfString:@"\n" withString:@" "]);
            } else {
                NSMutableString *hx = [NSMutableString string];
                const uint8_t *q = b.bytes;
                for (NSUInteger i = 0; i < MIN(b.length, (NSUInteger)800); i++)
                    [hx appendFormat:@"%02x", q[i]];
                SR(@"   body-hex: %@", hx);
            }
        }
    } @catch (NSException *e) {}
    return sr_dt(self, _cmd, req, h);
}

static id (*sr_up)(id, SEL, NSURLRequest *, NSData *);
static id sr_uploadHook(id self, SEL _cmd, NSURLRequest *req, NSData *data) {
    @try {
        NSData *b = data.length ? data : req.HTTPBody;
        SR(@"UPLOAD %@ len=%lu ct=%@", req.URL.absoluteString ?: @"?",
           (unsigned long)b.length, [req valueForHTTPHeaderField:@"Content-Type"] ?: @"-");
        if (b.length && b.length < 4000) {
            NSString *t = [[NSString alloc] initWithData:b encoding:NSUTF8StringEncoding];
            if (t) {
                SR(@"   body: %@", [t stringByReplacingOccurrencesOfString:@"\n" withString:@" "]);
            } else {
                NSMutableString *hx = [NSMutableString string];
                const uint8_t *q = b.bytes;
                for (NSUInteger i = 0; i < MIN(b.length, (NSUInteger)800); i++)
                    [hx appendFormat:@"%02x", q[i]];
                SR(@"   body-hex: %@", hx);
            }
        }
    } @catch (NSException *e) {}
    return sr_up(self, _cmd, req, data);
}

static void SRInstallNetHooks(void) {
    Class s = objc_getClass("NSURLSession"); if (!s) return;
    Method m = class_getInstanceMethod(s, @selector(dataTaskWithRequest:completionHandler:));
    if (m) { sr_dt = (void *)method_getImplementation(m);
             method_setImplementation(m, (IMP)sr_dataTaskHook); }
    m = class_getInstanceMethod(s, @selector(uploadTaskWithRequest:fromData:));
    if (m) { sr_up = (void *)method_getImplementation(m);
             method_setImplementation(m, (IMP)sr_uploadHook); }
    SR(@"net hooks on");
}


// --------------------------------------------------------- 4) keychain 盘点
static void SRDumpKeychain(void) {
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                        (__bridge id)kSecReturnAttributes: @YES,
                        (__bridge id)kSecReturnData: @YES};
    CFTypeRef res = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
    if (st != errSecSuccess || !res) { SR(@"kc status=%d", (int)st); return; }
    NSArray *items = (__bridge_transfer NSArray *)res;
    SR(@"kc items=%lu", (unsigned long)items.count);
    for (NSDictionary *it in items) {
        NSString *svc = it[(__bridge id)kSecAttrService] ?: @"(nil)";
        NSString *acct = it[(__bridge id)kSecAttrAccount] ?: @"(nil)";
        NSData *data = it[(__bridge id)kSecValueData];
        SR(@"  svc=%@ acct=%@ len=%lu", svc, acct, (unsigned long)data.length);
        if (data.length && data.length < 900) {
            NSString *t = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            SR(@"     val=%@", t ? [t stringByReplacingOccurrencesOfString:@"\n" withString:@" "] : @"<bin>");
        }
    }
}


static OSStatus (*sr_SKEncOld_orig)(SecKeyRef, SecPadding, const uint8_t *, size_t, uint8_t *, size_t *);
static OSStatus sr_SKEncOld(SecKeyRef key, SecPadding pad, const uint8_t *pt, size_t ptLen,
                            uint8_t *ct, size_t *ctLen) {
    @try {
        if (pt && ptLen && ptLen < 4096) {
            NSData *d = [NSData dataWithBytes:pt length:ptLen];
            NSString *t = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (!t) t = [[NSString alloc] initWithData:d encoding:NSISOLatin1StringEncoding];
            SR(@"[RSA-old] len=%zu plain=%@", ptLen, t ?: @"<bin>");
        }
    } @catch (NSException *e) {}
    return sr_SKEncOld_orig(key, pad, pt, ptLen, ct, ctLen);
}

static CCCryptorStatus (*sr_CCCreate_orig)(CCOperation, CCAlgorithm, CCOptions, const void *,
                                           size_t, const void *, CCCryptorRef *);
static CCCryptorStatus sr_CCCreate(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                   const void *key, size_t keyLen, const void *iv,
                                   CCCryptorRef *ref) {
    SR(@"[AES-init] op=%u alg=%u keyLen=%zu iv=%d", (unsigned)op, (unsigned)alg, keyLen, iv != NULL);
    return sr_CCCreate_orig(op, alg, opts, key, keyLen, iv, ref);
}

__attribute__((constructor))
static void SymbolRebindInit(void) {
    @autoreleasepool {
        SR(@"loaded pid=%d", getpid());
        static sr_entry entries[] = {
            {"getenv",                    (void *)sr_getenv,     NULL, 0},
            {"CCCrypt",                   (void *)sr_CCCrypt,    NULL, 0},
            {"CCCryptorUpdate",           (void *)sr_CCUpdate,   NULL, 0},
            {"SecKeyCreateEncryptedData", (void *)sr_SKEnc,      NULL, 0},
            {"SecKeyEncrypt",             (void *)sr_SKEncOld,   NULL, 0},
            {"CCCryptorCreate",           (void *)sr_CCCreate,   NULL, 0},
            {"CCCryptorCreateWithMode",   (void *)sr_CCCreate,   NULL, 0},
        };
        for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
            sr_rebind(&entries[i]);
        }
        sr_getenv_orig     = (const char *(*)(const char *))entries[0].original;
        sr_CCCrypt_orig    = (CCCryptorStatus (*)(CCOperation, CCAlgorithm, CCOptions,
                                                  const void *, size_t, const void *,
                                                  const void *, size_t, void *, size_t,
                                                  size_t *))entries[1].original;
        sr_CCUpdate_orig   = (CCCryptorStatus (*)(CCCryptorRef, const void *, size_t,
                                                  void *, size_t, size_t *))entries[2].original;
        sr_SKEnc_orig      = (SecKeyRef (*)(SecKeyRef, SecKeyAlgorithm, CFDataRef,
                                            CFErrorRef *))entries[3].original;
        sr_SKEncOld_orig   = (OSStatus (*)(SecKeyRef, SecPadding, const uint8_t *, size_t,
                                           uint8_t *, size_t *))entries[4].original;
        sr_CCCreate_orig   = (CCCryptorStatus (*)(CCOperation, CCAlgorithm, CCOptions,
                                                  const void *, size_t, const void *,
                                                  CCCryptorRef *))entries[5].original;
        SRInstallNetHooks();
        SRDumpKeychain();
        __block int rounds = 0;
        dispatch_queue_t q = dispatch_get_global_queue(0, 0);
        dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
        dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, 1ull*NSEC_PER_SEC),
                                  1ull*NSEC_PER_SEC, NSEC_PER_SEC/2);
        dispatch_source_set_event_handler(t, ^{
            if (rounds++ > 25) { dispatch_source_cancel(t); return; }
            for (size_t i = 0; i < sizeof(entries)/sizeof(entries[0]); i++) sr_rebind(&entries[i]);
        });
        dispatch_resume(t);
        SR(@"armed (getenv=%d aes=%d aesupd=%d rsa=%d)",
           entries[0].patched, entries[1].patched, entries[2].patched, entries[3].patched);
    }
}
