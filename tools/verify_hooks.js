// verify_hooks.js — Frida validation for the Octopus jailbreak-detection bypass
//
//   frida -U -f com.octopuscards.octopus -l verify_hooks.js
//   (add --no-pause to run immediately)
//
// Checks, in order:
//   1. which detection layers actually exist in this build
//   2. what each detector returns BEFORE / AFTER the dylib is installed
//   3. whether the filesystem probes are being masked

if (!ObjC.available) {
    console.log("[!] Objective-C runtime not available");
} else {
    const out = (s) => console.log(s);

    out("=== 1. layer inventory ===");
    ["DTTJailbreakDetection", "JailbreakCheck",
     "PRMShieldEventManager", "ShieldCallbackManager", "PRMShieldConfig",
     "_TtC17OctopusQuickBuild26PromonNoticeViewController"].forEach((n) => {
        const c = ObjC.classes[n];
        out("  " + (c ? "[+] " : "[-] ") + n);
    });

    out("=== 2. detector return values ===");
    try {
        const JC = ObjC.classes.JailbreakCheck;
        if (JC) {
            const s = JC["+ jailbreakStatusCode"]();
            out("  +[JailbreakCheck jailbreakStatusCode] = " + (s ? s.toString() : "nil"));
            out("  +[JailbreakCheck isJailbroken]        = " +
                JC["+ isJailbroken"]().toString());
        }
    } catch (e) { out("  JailbreakCheck probe failed: " + e); }

    try {
        const D = ObjC.classes.DTTJailbreakDetection;
        if (D) {
            out("  +[DTT isJailbroken]                   = " +
                D["+ isJailbroken"]().toString());
        }
    } catch (e) { out("  DTT probe failed: " + e); }

    out("=== 3. filesystem masking ===");
    ["/Applications/Cydia.app",
     "/Library/MobileSubstrate/MobileSubstrate.dylib",
     "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/usr/bin/ssh",
     "/private/jailbreak.txt"].forEach((p) => {
        const fm = ObjC.classes.NSFileManager.defaultManager();
        const exists = fm.fileExistsAtPath_(p).toString();
        // raw fopen through the C ABI
        let fopenRet = "n/a";
        try {
            const fopen = new NativeFunction(Module.findExportByName(null, "fopen"),
                                             "pointer", ["pointer", "pointer"]);
            const r = fopen(Memory.allocUtf8String(p), Memory.allocUtf8String("r"));
            fopenRet = r.isNull() ? "NULL" : "OK";
        } catch (e) { fopenRet = "err"; }
        out("  " + p + "\n      NSFileManager=" + exists + "  fopen=" + fopenRet);
    });

    out("=== 4. env / image hiding ===");
    ["DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "_MSSafeMode"].forEach((v) => {
        out("  getenv(" + v + ") = " + (getenv(v) || "(null)"));
    });
    out("  images containing 'OctopusJB' / 'frida' / 'Substrate':");
    Process.enumerateModules()
        .filter((m) => /OctopusJB|frida|Substrate|Substitute|libhooker/i.test(m.name))
        .forEach((m) => out("    " + m.name + " @ " + m.base));

    out("=== done: every detector should report clean ===");
}
