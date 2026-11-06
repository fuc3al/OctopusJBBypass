//
//  OctopusJBHook.m
//  八達通 (com.octopuscards.octopus) 9.50.0 — jailbreak-detection bypass dylib
//
//  Loaded into the app process via LC_LOAD_DYLIB (@executable_path/Frameworks/).
//  Neutralises the three independent layers found in the shipped binary:
//
//    L1  DTTJailbreakDetection.framework            +[DTTJailbreakDetection isJailbroken]
//    L2  OctopusQuickBuild  class "JailbreakCheck"  +isJailbroken / +jailbreakStatusCode
//    L3  Promon SHIELD      octopusx.framework      PRMShieldEventManager / ShieldCallbackManager
//        + the "PromonNoticeViewController" block screen
//
//  Layered defence:
//    (a) the filesystem looks clean            -> fopen/opendir/access/stat/lstat/readlink/NSFileManager
//    (b) dyld injection looks absent           -> getenv(DYLD_*), _dyld_get_image_name
//    (c) fork/ptrace/sysctl probes look clean  -> SHIELD debugger+jailbreak heuristics
//    (d) both ObjC detectors return "clean"    -> DTT + JailbreakCheck
//    (e) SHIELD never reaches the app          -> addObserver:/performSecurityChecks swallowed
//    (f) the block screen can never appear     -> present/push/setRootViewController filtered
//
//  Build: see README.md   (Theos: `make package` | clang: one-liner in README)
//  Debug: add -DOCTO_JB_DEBUG to print every intercepted probe to NSLog.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <strings.h>
#import <unistd.h>
#import <dirent.h>
#import <fcntl.h>
#import <errno.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>

#if __has_include(<sys/proc.h>)
#  include <sys/proc.h>
#endif

#ifdef OCTO_JB_DEBUG
#  define JBLog(fmt, ...) NSLog(@"[OctopusJB] " fmt, ##__VA_ARGS__)
#else
#  define JBLog(fmt, ...) do {} while (0)
#endif

// ---------------------------------------------------------------------------
// 0.  DYLD interposing helper
// ---------------------------------------------------------------------------

struct jb_interpose_pair {
    const void *replacement;
    const void *replacee;
};

#define DYLD_INTERPOSE(_replacement, _replacee)                                        \
    __attribute__((used, section("__DATA,__interpose"), visibility("hidden")))          \
    const struct jb_interpose_pair _interpose_##_replacee = {                           \
        (const void *)(unsigned long)&_replacement,                                     \
        (const void *)(unsigned long)&_replacee,                                        \
    };

// Forward declarations so the interposers below can read .replacee.
extern const struct jb_interpose_pair _interpose_fopen;
extern const struct jb_interpose_pair _interpose_opendir;
extern const struct jb_interpose_pair _interpose_access;
extern const struct jb_interpose_pair _interpose_stat;
extern const struct jb_interpose_pair _interpose_lstat;
extern const struct jb_interpose_pair _interpose_readlink;
extern const struct jb_interpose_pair _interpose_getenv;
extern const struct jb_interpose_pair _interpose_fork;
extern const struct jb_interpose_pair _interpose_ptrace;
extern const struct jb_interpose_pair _interpose_sysctl;
extern const struct jb_interpose_pair _interpose__dyld_get_image_name;

typedef FILE    *(*fopen_t)(const char *, const char *);
typedef DIR     *(*opendir_t)(const char *);
typedef ssize_t  (*readlink_t)(const char *, char *, size_t);
typedef char    *(*getenv_t)(const char *);

static fopen_t    orig_fopen;
static opendir_t  orig_opendir;
static readlink_t orig_readlink;
static getenv_t   orig_getenv;

// ---------------------------------------------------------------------------
// 1.  Surface that must look clean
// ---------------------------------------------------------------------------

// Exact strings recovered from Octopus 9.50.0 + the usual jailbreak surface.
static const char *kHiddenPrefixes[] = {
    // ---- exact probes found in this build ----
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/usr/bin/ssh",
    "/private/jailbreak.txt",
    // ---- rootful surface ----
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Cydia Installer.app",
    "/Applications/blackra1n.app",
    "/private/var/lib/apt",
    "/var/lib/apt",
    "/private/var/lib/dpkg",
    "/var/lib/dpkg",
    "/private/var/stash",
    "/var/stash",
    "/private/var/tmp/cydia.log",
    "/etc/ssh",
    "/usr/libexec/cydia",
    "/usr/libexec/sftp-server",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libellekit.dylib",
    "/usr/lib/TweakInject",
    "/Library/MobileSubstrate",
    "/Library/Frameworks/CydiaSubstrate.framework",
    "/Library/dpkg",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/etc/profile.d",
    "/usr/share/jailbreak",
    "/bin/sh",
    "/usr/bin/cycript",
    "/usr/sbin/frida-server",
    "/usr/lib/frida",
    // ---- rootless / modern ----
    "/var/jb",
    "/private/preboot",
    "/.installed_unc0ver",
    "/.installed_taurine",
    "/.installed_odyssey",
    "/.installed_palera1n",
    "/.installed_dopamine",
    "/.bootstrapped",
};
static const size_t kHiddenPrefixCount = sizeof(kHiddenPrefixes) / sizeof(kHiddenPrefixes[0]);

static NSString * const kHiddenSchemes[] = {
    @"cydia", @"sileo", @"zbra", @"installer", @"undecimus",
    @"filza", @"activator", @"trollstore",
};
static const size_t kHiddenSchemeCount = sizeof(kHiddenSchemes) / sizeof(kHiddenSchemes[0]);

static const char *kHiddenEnv[] = {
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_VERSIONED_LIBRARY_PATH",
    "DYLD_VERSIONED_FRAMEWORK_PATH",
    "DYLD_IMAGE_SUFFIX",
    "_MSSafeMode",
    "_SafeMode",
    "Substrate",
    "FRIDA_AGENT",
    "CYCRIPT",
};
static const size_t kHiddenEnvCount = sizeof(kHiddenEnv) / sizeof(kHiddenEnv[0]);

// Substrings of images that must not be reported to SHIELD.
static const char *kHiddenImages[] = {
    "OctopusJBHook", "Substrate", "Substitute", "libhooker",
    "ellekit", "TweakInject", "frida", "Frida", "cycript",
};
static const size_t kHiddenImageCount = sizeof(kHiddenImages) / sizeof(kHiddenImages[0]);

// ---------------------------------------------------------------------------
// 2.  Matching helpers (no Foundation: safe inside interposers)
// ---------------------------------------------------------------------------

static int jb_starts_with_ci(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        char a = *s, b = *prefix;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
        ++s; ++prefix;
    }
    return 1;
}

static int jb_path_hidden(const char *path) {
    if (!path) return 0;
    for (size_t i = 0; i < kHiddenPrefixCount; i++) {
        if (jb_starts_with_ci(path, kHiddenPrefixes[i])) {
            JBLog(@"hide path: %s", path);
            return 1;
        }
    }
    return 0;
}

static int jb_env_hidden(const char *name) {
    if (!name) return 0;
    for (size_t i = 0; i < kHiddenEnvCount; i++) {
        if (strcasecmp(name, kHiddenEnv[i]) == 0) return 1;
    }
    return 0;
}

static int jb_image_hidden(const char *name) {
    if (!name) return 0;
    for (size_t i = 0; i < kHiddenImageCount; i++) {
        if (strstr(name, kHiddenImages[i])) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 3.  Filesystem interposers
// ---------------------------------------------------------------------------

static FILE *jb_fopen(const char *path, const char *mode) {
    if (!orig_fopen) orig_fopen = (fopen_t)_interpose_fopen.replacee;
    if (jb_path_hidden(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static DIR *jb_opendir(const char *path) {
    if (!orig_opendir) orig_opendir = (opendir_t)_interpose_opendir.replacee;
    if (jb_path_hidden(path)) { errno = ENOENT; return NULL; }
    return orig_opendir(path);
}




static ssize_t jb_readlink(const char *path, char *buf, size_t len) {
    if (!orig_readlink) orig_readlink = (readlink_t)_interpose_readlink.replacee;
    if (jb_path_hidden(path)) { errno = ENOENT; return -1; }
    return orig_readlink(path, buf, len);
}

static char *jb_getenv(const char *name) {
    if (!orig_getenv) orig_getenv = (getenv_t)_interpose_getenv.replacee;
    if (jb_env_hidden(name)) return NULL;
    return orig_getenv(name);
}

DYLD_INTERPOSE(jb_fopen,    fopen)
DYLD_INTERPOSE(jb_opendir,  opendir)
DYLD_INTERPOSE(jb_readlink, readlink)
DYLD_INTERPOSE(jb_getenv,   getenv)

// ---------------------------------------------------------------------------
// 4.  Process / debugger interposers  (intentionally removed in v2)
//
//  fork()=-1 / ptrace / sysctl(KERN_PROC) were dropped: they are the most
//  invasive interpositions in the process and nothing on the Octopus path
//  (DTT, JailbreakCheck, SHIELD) needs them. SHIELD imports _pthread_atfork
//  but a successful fork() is not a signal a sandboxed app can produce, and
//  breaking fork hurt CFNetwork/TLS during early launch.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 5.  Hide our own image  (never return NULL: some callers do not check)
// ---------------------------------------------------------------------------

static const char *jb_dyld_get_image_name(uint32_t idx) {
    const char *name = _dyld_get_image_name(idx);
    if (jb_image_hidden(name)) {
        JBLog(@"mask image[%u]=%s", idx, name ? name : "(null)");
        return "/usr/lib/libSystem.B.dylib";
    }
    return name;
}
DYLD_INTERPOSE(jb_dyld_get_image_name, _dyld_get_image_name)

// ---------------------------------------------------------------------------
// 6.  ObjC IMP replacement helpers
// ---------------------------------------------------------------------------

static BOOL JBReplaceClassMethod(const char *cls, SEL sel, IMP repl) {
    Class c = objc_getClass(cls);
    if (!c) { JBLog(@"class %s absent", cls); return NO; }
    Method m = class_getClassMethod(c, sel);
    if (!m) { JBLog(@"no +%s on %s", sel_getName(sel), cls); return NO; }
    if (method_getImplementation(m) == repl) return YES;      // already installed
    method_setImplementation(m, repl);
    JBLog(@"hooked +[%s %s]", cls, sel_getName(sel));
    return YES;
}

static BOOL JBReplaceInstanceMethod(const char *cls, SEL sel, IMP repl) {
    Class c = objc_getClass(cls);
    if (!c) { JBLog(@"class %s absent", cls); return NO; }
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { JBLog(@"no -%s on %s", sel_getName(sel), cls); return NO; }
    if (method_getImplementation(m) == repl) return YES;
    method_setImplementation(m, repl);
    JBLog(@"hooked -[%s %s]", cls, sel_getName(sel));
    return YES;
}

// Replace an instance method but remember its original IMP (for fall-through).
// Idempotent: a second call is a no-op instead of capturing our own hook.
static void JBSwapInstance(const char *cls, SEL sel, IMP repl, IMP *storeOrig) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    IMP cur = method_getImplementation(m);
    if (cur == repl) return;
    if (storeOrig) *storeOrig = cur;
    method_setImplementation(m, repl);
    JBLog(@"hooked -[%s %s] (orig kept)", cls, sel_getName(sel));
}

// ---------------------------------------------------------------------------
// 7.  L1 / L2 — the app's own detectors
// ---------------------------------------------------------------------------

static BOOL jb_dtt_isJailbroken(id self, SEL _cmd) {
    JBLog(@"DTT +isJailbroken -> NO");
    return NO;
}

static BOOL jb_jc_isJailbroken(id self, SEL _cmd) {
    JBLog(@"JailbreakCheck +isJailbroken -> NO");
    return NO;
}

// Original returns an NSMutableString of '1'/'0' — one char per probe
// (Cydia.app, MobileSubstrate, /bin/bash, /usr/sbin/sshd, /etc/apt,
//  /usr/bin/ssh, /private write-test, cydia://). All zeros = "clean".
static id jb_jc_statusCode(id self, SEL _cmd) {
    JBLog(@"JailbreakCheck +jailbreakStatusCode -> 00000000");
    return @"00000000";
}

// ---------------------------------------------------------------------------
// 8.  Foundation-level probes
// ---------------------------------------------------------------------------

static BOOL (*real_fileExistsAtPath)(id, SEL, NSString *);
static BOOL (*real_fileExistsAtPathIsDir)(id, SEL, NSString *, BOOL *);
static BOOL (*real_writeToFile)(id, SEL, NSString *, BOOL, NSStringEncoding, NSError **);

static BOOL jb_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (path && jb_path_hidden([path fileSystemRepresentation])) return NO;
    return real_fileExistsAtPath(self, _cmd, path);
}

static BOOL jb_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (path && jb_path_hidden([path fileSystemRepresentation])) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return real_fileExistsAtPathIsDir(self, _cmd, path, isDir);
}

static BOOL jb_writeToFile(id self, SEL _cmd, NSString *path, BOOL atomically,
                           NSStringEncoding enc, NSError **err) {
    if (path && jb_path_hidden([path fileSystemRepresentation])) {
        if (err) {
            *err = [NSError errorWithDomain:NSCocoaErrorDomain
                                       code:NSFileWriteNoPermissionError
                                   userInfo:nil];
        }
        return NO;      // the DTT write test must fail -> sandbox looks intact
    }
    return real_writeToFile(self, _cmd, path, atomically, enc, err);
}

static BOOL (*real_canOpenURL)(id, SEL, NSURL *);

static BOOL jb_canOpenURL(id self, SEL _cmd, NSURL *url) {
    NSString *scheme = url.scheme.lowercaseString;
    for (size_t i = 0; i < kHiddenSchemeCount; i++) {
        if ([scheme isEqualToString:kHiddenSchemes[i]]) {
            JBLog(@"canOpenURL %@ -> NO", scheme);
            return NO;
        }
    }
    return real_canOpenURL ? real_canOpenURL(self, _cmd, url) : NO;
}

// ---------------------------------------------------------------------------
// 9.  L3 — Promon SHIELD: cut event delivery, suppress the block screen
// ---------------------------------------------------------------------------

static void jb_addObserver(id self, SEL _cmd, id observer) {
    JBLog(@"[PRM] -addObserver:%@ swallowed", NSStringFromClass([observer class]));
}

static void jb_performSecurityChecks(id self, SEL _cmd) {
    JBLog(@"[PRM] -performSecurityChecks swallowed");
}

static void jb_setObserver(id self, SEL _cmd, id observer) {
    JBLog(@"[PRM] +setObserver:%@ swallowed", NSStringFromClass([observer class]));
}

static BOOL jb_isPromonVC(id obj) {
    if (!obj) return NO;
    NSString *n = NSStringFromClass([obj class]);
    return [n containsString:@"PromonNotice"] ||
           [n containsString:@"PromonError"]  ||
           [n containsString:@"JailbreakNotice"];
}

static void (*real_presentVC)(id, SEL, UIViewController *, BOOL, void (^)(void));
static void jb_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated,
                         void (^completion)(void)) {
    if (jb_isPromonVC(vc)) {
        JBLog(@"blocked -presentViewController:%@", NSStringFromClass([vc class]));
        if (completion) completion();
        return;
    }
    real_presentVC(self, _cmd, vc, animated, completion);
}

static void (*real_pushVC)(id, SEL, UIViewController *, BOOL);
static void jb_pushVC(id self, SEL _cmd, UIViewController *vc, BOOL animated) {
    if (jb_isPromonVC(vc)) {
        JBLog(@"blocked -pushViewController:%@", NSStringFromClass([vc class]));
        return;
    }
    real_pushVC(self, _cmd, vc, animated);
}

static void (*real_setRootVC)(id, SEL, UIViewController *);
static void jb_setRootVC(id self, SEL _cmd, UIViewController *vc) {
    if (jb_isPromonVC(vc)) {
        JBLog(@"blocked -setRootViewController:%@", NSStringFromClass([vc class]));
        return;
    }
    real_setRootVC(self, _cmd, vc);
}

// ---------------------------------------------------------------------------
// 10.  Install  (idempotent, retried after dyld finishes / app launches)
// ---------------------------------------------------------------------------

static void JBInstall(void);

static void JBArmFileExists(void) {
    JBSwapInstance("NSFileManager", @selector(fileExistsAtPath:),
                   (IMP)jb_fileExistsAtPath, (IMP *)&real_fileExistsAtPath);
    JBSwapInstance("NSFileManager", @selector(fileExistsAtPath:isDirectory:),
                   (IMP)jb_fileExistsAtPathIsDir, (IMP *)&real_fileExistsAtPathIsDir);
    JBSwapInstance("NSString", @selector(writeToFile:atomically:encoding:error:),
                   (IMP)jb_writeToFile, (IMP *)&real_writeToFile);
}

static void JBArmUIKit(void) {
    JBSwapInstance("UIViewController", @selector(presentViewController:animated:completion:),
                   (IMP)jb_presentVC, (IMP *)&real_presentVC);
    JBSwapInstance("UINavigationController", @selector(pushViewController:animated:),
                   (IMP)jb_pushVC, (IMP *)&real_pushVC);
    JBSwapInstance("UIWindow", @selector(setRootViewController:),
                   (IMP)jb_setRootVC, (IMP *)&real_setRootVC);
}

static void JBInstall(void) {
    // L1 / L2 — the app's own detectors
    JBReplaceClassMethod("DTTJailbreakDetection", @selector(isJailbroken), (IMP)jb_dtt_isJailbroken);
    JBReplaceClassMethod("JailbreakCheck", @selector(isJailbroken), (IMP)jb_jc_isJailbroken);
    JBReplaceClassMethod("JailbreakCheck", @selector(jailbreakStatusCode), (IMP)jb_jc_statusCode);

    // filesystem / Foundation level
    JBArmFileExists();
    JBSwapInstance("UIApplication", @selector(canOpenURL:),
                   (IMP)jb_canOpenURL, (IMP *)&real_canOpenURL);

    // L3 — Promon SHIELD event delivery
    JBReplaceInstanceMethod("PRMShieldEventManager", @selector(addObserver:), (IMP)jb_addObserver);
    JBReplaceInstanceMethod("PRMShieldEventManager", @selector(performSecurityChecks), (IMP)jb_performSecurityChecks);
    JBReplaceClassMethod("PRMShieldEventManager", @selector(setObserver:), (IMP)jb_setObserver);
    JBReplaceInstanceMethod("ShieldCallbackManager", @selector(addObserver:), (IMP)jb_addObserver);
    JBReplaceInstanceMethod("ShieldCallbackManager", @selector(performSecurityChecks), (IMP)jb_performSecurityChecks);
    JBReplaceClassMethod("ShieldCallbackManager", @selector(setObserver:), (IMP)jb_setObserver);

    // F — never let the block screen appear
    JBArmUIKit();
}

__attribute__((constructor))
static void OctopusJBHookInit(void) {
    @autoreleasepool {
        JBLog(@"loaded pid=%d (TrollFools / launch-time LC_LOAD_DYLIB)", getpid());
        JBInstall();

        // Safety net: octopusx may register its ObjC classes slightly later than
        // this constructor on some dyld orders. Retry on the main queue and again
        // once the app has finished launching — every hook is idempotent.
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool { JBInstall(); JBLog(@"re-install after runloop"); }
        });
        [[NSNotificationCenter defaultCenter]
            addObserverForName:@"UIApplicationDidFinishLaunchingNotification"
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            @autoreleasepool { JBInstall(); JBLog(@"re-install after didFinishLaunching"); }
        }];

        JBLog(@"install pass complete");
    }
}
