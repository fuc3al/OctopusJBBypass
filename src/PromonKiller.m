// PromonKiller.m — 极简版：只利用"拦截提示是异步、非阻塞的纯 UI"这一特性。
//
// 不做任何文件 / 环境变量 / dyld 拦截，不碰 DTT、JailbreakCheck 的返回值，
// 只在两个必经入口上做一次性短路：
//   1) -[PRMShieldEventManager addObserver:] / -[ShieldCallbackManager addObserver:]
//      → shield 的判定结果送不到 App 的 Swift 层，连"要不要弹"的决策都不会发生
//   2) -[UIViewController presentViewController:animated:completion:]
//      → 万一还有别的路径构造了拦截页，也弹不出来
//
// 为什么这样就够：实测（9.54.0 / iOS 16.2）拦截页只是被 present 出来的普通 VC，
// App 的启动流水线从不等它；present 一旦被吃掉，警告不存在，功能照常。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#ifdef PROMON_KILLER_DEBUG
#  define PKLog(fmt, ...) NSLog(@"[PromonKiller] " fmt, ##__VA_ARGS__)
#else
#  define PKLog(fmt, ...) do {} while (0)
#endif

static BOOL PKIsBlockVC(id vc) {
    if (!vc) return NO;
    NSString *n = NSStringFromClass([vc class]);
    return [n containsString:@"Promon"] ||
           [n containsString:@"Jailbreak"] ||
           [n containsString:@"SecurityNotice"];
}

// ---------------------------------------------------------------- present 拦截

static void (*pk_presentVC)(id, SEL, UIViewController *, BOOL, void (^)(void));

static void pk_present(id self, SEL _cmd, UIViewController *vc, BOOL animated,
                       void (^completion)(void)) {
    if (PKIsBlockVC(vc)) {
        PKLog(@"dropped presentation of %@", NSStringFromClass([vc class]));
        if (completion) completion();
        return;
    }
    pk_presentVC(self, _cmd, vc, animated, completion);
}

// ------------------------------------------------------- shield observer 拦截

static void pk_addObserver(id self, SEL _cmd, id observer) {
    PKLog(@"swallowed -addObserver:%@", observer);
}

static BOOL PKInstall(void) {
    BOOL any = NO;
    for (NSString *cls in @[@"PRMShieldEventManager", @"ShieldCallbackManager"]) {
        Class c = objc_getClass(cls.UTF8String);
        if (!c) { PKLog(@"class %@ absent", cls); continue; }
        Method m = class_getInstanceMethod(c, @selector(addObserver:));
        if (m && method_getImplementation(m) != (IMP)pk_addObserver) {
            method_setImplementation(m, (IMP)pk_addObserver);
            any = YES;
            PKLog(@"hooked -[%@ addObserver:]", cls);
        }
    }
    Class vcc = objc_getClass("UIViewController");
    Method pm = vcc ? class_getInstanceMethod(vcc, @selector(presentViewController:animated:completion:)) : NULL;
    if (pm && method_getImplementation(pm) != (IMP)pk_present) {
        pk_presentVC = (void *)method_getImplementation(pm);
        method_setImplementation(pm, (IMP)pk_present);
        any = YES;
        PKLog(@"hooked -presentViewController:animated:completion:");
    }
    return any;
}

__attribute__((constructor))
static void PromonKillerInit(void) {
    @autoreleasepool {
        PKLog(@"loaded pid=%d", getpid());
        PKInstall();
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool { PKInstall(); }
        });
    }
}
