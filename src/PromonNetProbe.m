// PromonNetProbe.m (v3) — 只观察，不绕过。
// v3 相比 v2：
//   * 对 googleapis / octopus 域名，dump 前 1.5 KB body（含 protobuf 用 hex）
//   * 在【完整 body】里做关键词扫描（jailbreak / promon / shield / security / jail），
//     命中就把命中位置附近的内容也打出来 —— 这是判断"结论有没有随请求出去"的关键
//   * 额外 hook -[NSMutableURLRequest setHTTPBody:] 与 -setHTTPBodyStream:，
//     捕捉 Alamofire 之类先建 request 再赋 body 的路径

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

#define NP(fmt, ...) NSLog(@"[NetProbe] " fmt, ##__VA_ARGS__)

static NSArray<NSString *> *NPKeywords(void) {
    static NSArray *kw;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        kw = @[@"jailbreak", @"jailbroken", @"promon", @"shield", @"cydia",
               @"substrate", @"ellekit", @"rootless", @"tamper", @"integrity",
               @"isJail", @"security"];
    });
    return kw;
}

static NSString *NPPrintable(NSData *d, NSUInteger max) {
    NSUInteger n = MIN(d.length, max);
    NSData *head = [d subdataWithRange:NSMakeRange(0, n)];
    NSString *s = [[NSString alloc] initWithData:head encoding:NSUTF8StringEncoding];
    if (s) return [s stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    NSMutableString *hex = [NSMutableString string];
    const uint8_t *b = head.bytes;
    for (NSUInteger i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", b[i]];
        if (i == 63) { [hex appendString:@"…"]; break; }
    }
    return hex;
}

// 在完整 body 中找关键词，命中就打印最多 3 段前后文
static void NPScanKeywords(NSData *body, NSString *host) {
    if (body.length < 4) return;
    NSString *latin = [[NSString alloc] initWithData:body encoding:NSISOLatin1StringEncoding];
    if (!latin) return;
    NSString *lower = latin.lowercaseString;
    NSInteger hits = 0;
    for (NSString *kw in NPKeywords()) {
        NSRange search = NSMakeRange(0, lower.length);
        while (hits < 6) {
            NSRange r = [lower rangeOfString:kw options:0 range:search];
            if (r.location == NSNotFound) break;
            NSInteger from = MAX(0, (NSInteger)r.location - 60);
            NSInteger len = MIN((NSInteger)latin.length - from, (NSInteger)140);
            NSString *ctx = [latin substringWithRange:NSMakeRange(from, len)];
            NP(@"   HIT[%@] host=%@ ctx=%@", kw, host,
               [ctx stringByReplacingOccurrencesOfString:@"\n" withString:@" "]);
            hits++;
            NSInteger next = (NSInteger)(r.location + r.length);
            search = NSMakeRange(next, lower.length - next);
        }
    }
    if (hits == 0) NP(@"   no keyword in %lu B body", (unsigned long)body.length);
}

static void NPLogRequest(NSURLRequest *req, NSString *phase, NSData *extra) {
    @try {
        NSURL *u = req.URL;
        NSString *host = u.host ?: @"?";
        NSData *body = req.HTTPBody ?: extra;
        NP(@"%@ %@ %@ len=%lu ct=%@", phase, req.HTTPMethod ?: @"?",
           u.absoluteString ?: @"?", (unsigned long)body.length,
           [req valueForHTTPHeaderField:@"Content-Type"] ?: @"-");
        NSDictionary *hdrs = req.allHTTPHeaderFields;
        if (hdrs.count) {
            NSMutableString *h = [NSMutableString string];
            for (NSString *k in hdrs) {
                if ([k.lowercaseString containsString:@"auth"] ||
                    [k.lowercaseString containsString:@"token"] ||
                    [k.lowercaseString containsString:@"device"] ||
                    [k.lowercaseString containsString:@"app"]) {
                    [h appendFormat:@"%@=%@; ", k, hdrs[k]];
                }
            }
            if (h.length) NP(@"   hdrs: %@", h);
        }
        if (body.length) {
            BOOL interesting = [host containsString:@"googleapis"] ||
                               [host containsString:@"octopus"] ||
                               [host containsString:@"firebase"];
            if (interesting) {
                NP(@"   head: %@", NPPrintable(body, 1500));
                NPScanKeywords(body, host);
            }
        }
    } @catch (NSException *e) {
        NP(@"log failed: %@", e.reason);
    }
}

// ------------------------------------------------------------ session hooks

static id (*np_dataTaskHandler)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static id np_dataTaskHandlerHook(id self, SEL _cmd, NSURLRequest *req,
                                 void (^h)(NSData *, NSURLResponse *, NSError *)) {
    NPLogRequest(req, @"REQ", nil);
    return np_dataTaskHandler(self, _cmd, req, h);
}

static id (*np_dataTask)(id, SEL, NSURLRequest *);
static id np_dataTaskHook(id self, SEL _cmd, NSURLRequest *req) {
    NPLogRequest(req, @"REQ2", nil);
    return np_dataTask(self, _cmd, req);
}

static id (*np_upload)(id, SEL, NSURLRequest *, NSData *);
static id np_uploadHook(id self, SEL _cmd, NSURLRequest *req, NSData *data) {
    NPLogRequest(req, @"UPLOAD", data);
    if (data.length) NPScanKeywords(data, req.URL.host ?: @"?");
    return np_upload(self, _cmd, req, data);
}

// ------------------------------------------- 捕捉后赋 body 的 request 构造

static void (*np_setBody)(id, SEL, NSData *);
static void np_setBodyHook(id self, SEL _cmd, NSData *body) {
    if (body.length > 32) {
        NSURL *u = [self URL];
        NSString *host = u.host ?: @"?";
        NP(@"BODY-SET %@%@ len=%lu", host, u.path ?: @"", (unsigned long)body.length);
        NPScanKeywords(body, host);
    }
    np_setBody(self, _cmd, body);
}

static void NPProbeClass(NSString *name, NSArray<NSString *> *sels) {
    Class c = NSClassFromString(name);
    if (!c) { NP(@"%@ absent", name); return; }
    for (NSString *s in sels) {
        SEL sel = NSSelectorFromString(s);
        Method im = class_getInstanceMethod(c, sel);
        Method cm = class_getClassMethod(c, sel);
        if (im || cm) NP(@"%@ %@ %@", name, im ? @"-" : @"+", s);
    }
}

#ifdef PROMON_PROBE_SUPPRESS
// ---- 抑制（与探针合体，避免多 tweak 注入冲突）----
static void (*pp_present)(id, SEL, UIViewController *, BOOL, void (^)(void));
static void pp_presentHook(id self, SEL _cmd, UIViewController *vc, BOOL animated,
                           void (^completion)(void)) {
    NSString *n = vc ? NSStringFromClass([vc class]) : @"(nil)";
    if ([n containsString:@"Promon"] || [n containsString:@"Jailbreak"]) {
        NP(@"[SUPPRESS] dropped %@", n);
        if (completion) completion();
        return;
    }
    pp_present(self, _cmd, vc, animated, completion);
}
static void pp_addObserver(id self, SEL _cmd, id observer) {
    NP(@"[SUPPRESS] swallowed -addObserver:%@", observer);
}
static BOOL NPSuppressWanted(void) {
    return access("/var/mobile/ocjb.off", F_OK) != 0;
}
static void NPInstallSuppression(void) {
    for (NSString *cls in @[@"PRMShieldEventManager", @"ShieldCallbackManager"]) {
        Class c = objc_getClass(cls.UTF8String);
        if (!c) continue;
        Method m = class_getInstanceMethod(c, @selector(addObserver:));
        if (m && method_getImplementation(m) != (IMP)pp_addObserver)
            method_setImplementation(m, (IMP)pp_addObserver);
    }
    Class vcc = objc_getClass("UIViewController");
    Method pm = vcc ? class_getInstanceMethod(vcc, @selector(presentViewController:animated:completion:)) : NULL;
    if (pm && method_getImplementation(pm) != (IMP)pp_presentHook) {
        pp_present = (void *)method_getImplementation(pm);
        method_setImplementation(pm, (IMP)pp_presentHook);
    }
}
#endif

__attribute__((constructor))
static void PromonNetProbeInit(void) {
    @autoreleasepool {
        NP(@"loaded pid=%d", getpid());

        Class s = objc_getClass("NSURLSession");
        if (s) {
            Method m;
            m = class_getInstanceMethod(s, @selector(dataTaskWithRequest:completionHandler:));
            if (m) { np_dataTaskHandler = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)np_dataTaskHandlerHook); }
            m = class_getInstanceMethod(s, @selector(dataTaskWithRequest:));
            if (m) { np_dataTask = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)np_dataTaskHook); }
            m = class_getInstanceMethod(s, @selector(uploadTaskWithRequest:fromData:));
            if (m) { np_upload = (void *)method_getImplementation(m);
                     method_setImplementation(m, (IMP)np_uploadHook); }
        }
        Class mr = objc_getClass("NSMutableURLRequest");
        Method bm = mr ? class_getInstanceMethod(mr, @selector(setHTTPBody:)) : NULL;
        if (bm) { np_setBody = (void *)method_getImplementation(bm);
                  method_setImplementation(bm, (IMP)np_setBodyHook); }

        NPProbeClass(@"PRMShieldConfig", @[@"requestUpdate", @"requestUpdate:",
                                           @"getActiveConfigTimestamp", @"configUpdate",
                                           @"updateConfig", @"shared"]);
        NPProbeClass(@"ShieldConfig", @[@"requestUpdate", @"getActiveConfigTimestamp"]);
        NPProbeClass(@"PRMShieldEventManager", @[@"performSecurityChecks", @"shared"]);
#ifdef PROMON_PROBE_SUPPRESS
        if (NPSuppressWanted()) {
            NPInstallSuppression();
            NP(@"suppression active");
        } else {
            NP(@"suppression OFF (flag file present)");
        }
#endif
        NP(@"probe armed");
    }
}
