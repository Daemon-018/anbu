package com.anbu.scanner;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * On-device scanner.
 *
 * <p>Reads what Android exposes for an installed package — the manifest, requested
 * permissions, components, signing certificate — and best-effort strings from the
 * APK's DEX files. Findings feed the same deterministic scoring model as the
 * desktop ANBU tool (see src/anbu/score.py and docs/02-risk-scoring.md).</p>
 */
public final class ScanEngine {

    private static final int GET_SIGNATURES = 0x00000040;

    /** Packer fingerprints from src/anbu/data/signals.json (lower-case needles). */
    private static final String[][] PACKERS = {
            {"qihoo/jiagu", "libjiagu", "com.qihoo.util", "com.stub.stubapp"},
            {"tencent/legu", "libshella", "libshellx", "com.tencent.stubshell"},
            {"baidu", "com.baidu.protect", "libbaiduprotect"},
            {"alibaba", "com.ali.mobisecenhive", "libmobisec"},
            {"bangcle", "libsecexe", "libsecmain", "com.secneo.apkwrapper"},
            {"ijiami", "libexec.so", "libexecmain.so", "com.shell.helper"},
            {"dexguard/dexprotector", "com.guardsquare.dexguard", "com.licel.dexprotector",
                    "libdexprotector"},
            {"netease", "libnesec"},
            {"kiwisec", "libkiwi"},
    };

    private ScanEngine() {
    }

    public interface Progress {
        void step(String label, String detail);
    }

    /** Lists launchable and non-launchable installed packages. */
    public static List<Model.AppEntry> listApps(Context context) {
        PackageManager pm = context.getPackageManager();
        List<Model.AppEntry> apps = new ArrayList<>();
        List<PackageInfo> packages = pm.getInstalledPackages(0);
        String self = context.getPackageName();
        for (PackageInfo info : packages) {
            if (info.packageName == null || info.applicationInfo == null) continue;
            if (info.packageName.equals(self)) continue;
            Model.AppEntry entry = new Model.AppEntry(info.packageName);
            entry.versionName = info.versionName;
            try {
                entry.label = pm.getApplicationLabel(info.applicationInfo).toString();
            } catch (RuntimeException e) {
                entry.label = info.packageName;
            }
            try {
                entry.icon = pm.getApplicationIcon(info.applicationInfo);
            } catch (RuntimeException e) {
                entry.icon = null;
            }
            entry.system = (info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            apps.add(entry);
        }
        Collections.sort(apps, (a, b) -> {
            if (a.system != b.system) return a.system ? 1 : -1;
            return String.CASE_INSENSITIVE_ORDER.compare(a.label, b.label);
        });
        return apps;
    }

    /** Resolves a single installed package into an entry the scan screen can display. */
    public static Model.AppEntry entryFor(Context context, String packageName) {
        Model.AppEntry entry = new Model.AppEntry(packageName);
        PackageManager pm = context.getPackageManager();
        try {
            PackageInfo info = pm.getPackageInfo(packageName, 0);
            entry.versionName = info.versionName;
            if (info.applicationInfo != null) {
                entry.label = pm.getApplicationLabel(info.applicationInfo).toString();
                entry.icon = pm.getApplicationIcon(info.applicationInfo);
                entry.system = (info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            }
        } catch (Exception e) {
            entry.label = packageName;
        }
        if (entry.label == null || entry.label.isEmpty()) entry.label = packageName;
        return entry;
    }

    public static Model.Report scan(Context context, Model.AppEntry entry, Progress progress) {
        Model.Report report = new Model.Report(entry);
        Ctx ctx = new Ctx();
        PackageManager pm = context.getPackageManager();

        if (progress != null) progress.step("Reading manifest", entry.label);

        PackageInfo info;
        try {
            int flags = PackageManager.GET_PERMISSIONS
                    | PackageManager.GET_ACTIVITIES
                    | PackageManager.GET_SERVICES
                    | PackageManager.GET_RECEIVERS
                    | PackageManager.GET_PROVIDERS
                    | GET_SIGNATURES;
            info = pm.getPackageInfo(entry.packageName, flags);
        } catch (PackageManager.NameNotFoundException e) {
            report.score.value = 0;
            report.score.band = "likely_benign";
            report.score.confidence = "low";
            report.score.notes.add("Package is no longer installed; nothing could be read.");
            return report;
        } catch (RuntimeException e) {
            report.score.notes.add("Android refused access to this package's details: " + e.getMessage());
            report.score.confidence = "low";
            return report;
        }

        ctx.info = info;
        readManifest(context, info, ctx);

        if (progress != null) progress.step("Inspecting code", "Limited to what the OS exposes");
        readApk(ctx);

        if (progress != null) progress.step("Applying rules", "Permission, API and manifest signals");
        detect(ctx, report);

        score(ctx, report);
        report.detailsOnly = !ctx.codeRead;
        report.scannedAt = System.currentTimeMillis();
        return report;
    }

    // ---------------------------------------------------------------- manifest

    private static void readManifest(Context context, PackageInfo info, Ctx ctx) {
        if (info.requestedPermissions != null) {
            for (String permission : info.requestedPermissions) {
                if (permission != null) ctx.permissions.add(permission);
            }
        }

        if (info.services != null) {
            for (android.content.pm.ServiceInfo service : info.services) {
                if (service.name == null) continue;
                ctx.services.add(service.name);
                if (service.permission != null) ctx.permissions.add(service.permission);
                if (service.exported && isEmpty(service.permission)) ctx.exportedUnprotected++;
            }
        }
        if (info.receivers != null) {
            for (android.content.pm.ActivityInfo receiver : info.receivers) {
                if (receiver.name == null) continue;
                ctx.receivers.add(receiver.name);
                if (receiver.permission != null) ctx.permissions.add(receiver.permission);
                if (receiver.exported && isEmpty(receiver.permission)) ctx.exportedUnprotected++;
            }
        }
        if (info.activities != null) {
            for (android.content.pm.ActivityInfo activity : info.activities) {
                if (activity.name == null) continue;
                ctx.activities.add(activity.name);
                if (activity.permission != null) ctx.permissions.add(activity.permission);
                if (activity.exported && isEmpty(activity.permission)) ctx.exportedUnprotected++;
            }
        }
        if (info.providers != null) {
            for (android.content.pm.ProviderInfo provider : info.providers) {
                if (provider.name == null) continue;
                ctx.providers.add(provider.name);
                if (provider.exported
                        && isEmpty(provider.readPermission)
                        && isEmpty(provider.writePermission)) {
                    ctx.exportedUnprotected++;
                }
            }
        }

        ApplicationInfo app = info.applicationInfo;
        if (app != null) {
            ctx.debug = (app.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            ctx.testOnly = (app.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0;
            ctx.cleartext = (app.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0;
        }

        readCertificate(info, ctx);
        ctx.smsReceiver = hasReceiver(context, info.packageName,
                "android.provider.Telephony.SMS_RECEIVED");
        ctx.self = context.getPackageName().equals(info.packageName);
    }

    /**
     * PackageInfo does not expose a component's intent filters, so ask the resolver which
     * package actually receives a broadcast. No permission is required for this query.
     */
    private static boolean hasReceiver(Context context, String packageName, String action) {
        try {
            List<android.content.pm.ResolveInfo> matches = context.getPackageManager()
                    .queryBroadcastReceivers(new android.content.Intent(action), 0);
            if (matches == null) return false;
            for (android.content.pm.ResolveInfo match : matches) {
                if (match.activityInfo != null
                        && packageName.equals(match.activityInfo.packageName)) {
                    return true;
                }
            }
        } catch (RuntimeException ignored) {
            // Resolver refused the query; treat the receiver as not observed.
        }
        return false;
    }

    private static void readCertificate(PackageInfo info, Ctx ctx) {
        if (info.signatures == null || info.signatures.length == 0) return;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(info.signatures[0].toByteArray()));
            String subject = cert.getSubjectDN() == null ? "" : cert.getSubjectDN().getName();
            ctx.certDebug = subject.contains("CN=Android Debug") || subject.contains("O=Android");
            ctx.certExpired = cert.getNotAfter() != null && cert.getNotAfter().before(new Date());
            ctx.certSubject = subject;
        } catch (Exception ignored) {
            // A vendor certificate that the platform cannot parse is not evidence of risk.
        }
    }

    // --------------------------------------------------------------------- apk

    private static void readApk(Ctx ctx) {
        if (ctx.info == null || ctx.info.applicationInfo == null) return;
        String source = ctx.info.applicationInfo.sourceDir;
        if (source == null) return;
        ZipFile zip = null;
        try {
            zip = new ZipFile(source);
            int dexCount = 0;
            int dexRead = 0;
            StringBuilder strings = new StringBuilder();
            List<ZipEntry> entries = new ArrayList<>();
            java.util.Enumeration<? extends ZipEntry> e = zip.entries();
            while (e.hasMoreElements()) entries.add(e.nextElement());

            for (ZipEntry entry : entries) {
                String name = entry.getName();
                if (name == null) continue;
                if (name.matches("classes[0-9]*\\.dex")) {
                    dexCount++;
                    String text = readStrings(zip, entry, 16 * 1024 * 1024);
                    if (text != null) {
                        dexRead++;
                        strings.append(text).append('\n');
                    }
                } else if (name.startsWith("assets/") && !entry.isDirectory()) {
                    String lower = name.toLowerCase(java.util.Locale.US);
                    boolean payloadName = lower.endsWith(".dex") || lower.endsWith(".jar")
                            || lower.endsWith(".apk") || lower.endsWith(".zip")
                            || lower.endsWith(".bin") || lower.endsWith(".enc")
                            || lower.endsWith(".dat");
                    if (payloadName && entry.getSize() != 0) {
                        ctx.assetPayload = true;
                        ctx.assetNames.add(name);
                    }
                    if (entry.getSize() > 32 * 1024 && entry.getSize() <= 32L * 1024 * 1024) {
                        byte[] head = readHead(zip, entry, 64 * 1024);
                        if (head != null && shannon(head) >= 7.2) {
                            ctx.highEntropyAsset = true;
                            ctx.assetNames.add(name);
                        }
                    }
                }
            }

            ctx.code = strings.toString();
            ctx.codeLower = ctx.code.toLowerCase(java.util.Locale.US);
            ctx.codeUpper = ctx.code.toUpperCase(java.util.Locale.US);
            ctx.codeRead = dexRead > 0;
            findPackers(ctx);
            ctx.coverage = dexCount == 0 ? 0d : (double) dexRead / (double) dexCount;
            ctx.dexCount = dexCount;
            ctx.dexRead = dexRead;
            if (ctx.code.isEmpty()) {
                // Some packages keep code in splits or hide it; still inspect the APK bytes.
                ctx.code = ctx.codeLower = "";
            }
        } catch (Exception e) {
            ctx.readError = e.getClass().getSimpleName();
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static void findPackers(Ctx ctx) {
        for (String[] packer : PACKERS) {
            for (int i = 1; i < packer.length; i++) {
                if (ctx.codeLower.contains(packer[i])) {
                    ctx.packers.add(packer[0]);
                    break;
                }
            }
        }
    }

    private static String readStrings(ZipFile zip, ZipEntry entry, long limit) {
        InputStream in = null;
        try {
            in = zip.getInputStream(entry);
            long size = entry.getSize();
            int cap = (int) Math.min(size > 0 ? size : limit, limit);
            byte[] data = new byte[cap];
            int read = 0;
            while (read < cap) {
                int n = in.read(data, read, cap - read);
                if (n < 0) break;
                read += n;
            }
            StringBuilder out = new StringBuilder(read / 3);
            StringBuilder word = new StringBuilder(48);
            for (int i = 0; i < read; i++) {
                int b = data[i] & 0xFF;
                if (b >= 32 && b <= 126) {
                    word.append((char) b);
                } else {
                    if (word.length() >= 4) out.append(word).append('\n');
                    word.setLength(0);
                }
            }
            if (word.length() >= 4) out.append(word).append('\n');
            return out.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static byte[] readHead(ZipFile zip, ZipEntry entry, int limit) {
        InputStream in = null;
        try {
            in = zip.getInputStream(entry);
            byte[] data = new byte[limit];
            int read = 0;
            while (read < limit) {
                int n = in.read(data, read, limit - read);
                if (n < 0) break;
                read += n;
            }
            byte[] out = new byte[read];
            System.arraycopy(data, 0, out, 0, read);
            return out;
        } catch (Exception e) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static double shannon(byte[] data) {
        if (data.length == 0) return 0;
        int[] counts = new int[256];
        for (byte b : data) counts[b & 0xFF]++;
        double entropy = 0;
        for (int count : counts) {
            if (count == 0) continue;
            double p = (double) count / data.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    // ------------------------------------------------------------------- rules

    private static void detect(Ctx c, Model.Report r) {
        // Permissions -------------------------------------------------------
        if (c.has("android.permission.RECEIVE_SMS")
                && (c.has("android.permission.READ_SMS") || c.has("android.permission.SEND_SMS"))
                && c.has("android.permission.INTERNET")) {
            add(r, "PERM-01", "Reads incoming SMS and has internet access", "high",
                    "sms_interception",
                    "The app can read or send text messages and can reach the network.",
                    "One-time passwords arrive by SMS. This combination is the core of OTP theft "
                            + "and premium-SMS fraud, and is rarely needed by apps that are not messaging clients.",
                    new String[]{"T1412"},
                    ev("AndroidManifest.xml", "RECEIVE_SMS + READ_SMS/SEND_SMS + INTERNET"));
        }

        boolean accessibility = c.has("android.permission.BIND_ACCESSIBILITY_SERVICE")
                || c.componentContains(c.services, "AccessibilityService");
        if (accessibility) {
            add(r, "PERM-02", "Requests accessibility-service control", "high",
                    "accessibility_abuse",
                    "The app can register a service that reads the screen and acts on the user's behalf.",
                    "Accessibility was built for assistive technology, but it also lets an app read "
                            + "every screen, click through dialogs and defeat permission prompts.",
                    new String[]{"T1417"},
                    ev("AndroidManifest.xml", c.has("android.permission.BIND_ACCESSIBILITY_SERVICE")
                            ? "BIND_ACCESSIBILITY_SERVICE" : firstMatch(c.services, "AccessibilityService")));
        }

        if (accessibility && c.has("android.permission.SYSTEM_ALERT_WINDOW")) {
            add(r, "PERM-03", "Accessibility control combined with draw-over-other-apps", "high",
                    "overlay_attack",
                    "The app can read the interface and draw windows on top of other apps.",
                    "Overlay windows are how banking trojans show fake login screens on top of the real app.",
                    new String[]{"T1417", "T1411"},
                    ev("AndroidManifest.xml", "BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW"));
        }

        if (c.has("android.permission.REQUEST_INSTALL_PACKAGES")) {
            add(r, "PERM-04", "Can install other applications", "medium", "dropper",
                    "The app can ask the system to install an APK.",
                    "Install capability is normal for stores, but it is also how droppers deliver a "
                            + "second stage that was never reviewed.",
                    new String[]{"T1418"},
                    ev("AndroidManifest.xml", "REQUEST_INSTALL_PACKAGES"));
        }

        if (c.has("android.permission.BIND_DEVICE_ADMIN")
                || c.componentContains(c.receivers, "DeviceAdmin")) {
            add(r, "PERM-05", "Requests device-administrator rights", "high", "device_admin",
                    "The app can register as a device administrator.",
                    "Device admin can lock or wipe the device and is abused by ransomware and "
                            + "by apps that resist uninstallation.",
                    new String[]{"T1629"},
                    ev("AndroidManifest.xml", "BIND_DEVICE_ADMIN"));
        }

        if (c.has("android.permission.RECEIVE_BOOT_COMPLETED")
                && (c.has("android.permission.FOREGROUND_SERVICE")
                || c.has("android.permission.FOREGROUND_SERVICE_DATA_SYNC"))) {
            add(r, "PERM-06", "Starts itself at boot with a long-running service", "medium",
                    "persistence",
                    "The app is notified at boot and can keep a foreground service alive.",
                    "Restarting without user action is how background surveillance survives a reboot.",
                    new String[]{"T1398"},
                    ev("AndroidManifest.xml", "RECEIVE_BOOT_COMPLETED + FOREGROUND_SERVICE"));
        }

        if ((c.has("android.permission.READ_CONTACTS") || c.has("android.permission.READ_CALL_LOG"))
                && c.has("android.permission.INTERNET")) {
            add(r, "PERM-07", "Reads contacts or call logs and has internet access", "high",
                    "data_harvesting",
                    "The app can read the address book or call history and upload it.",
                    "Contacts and call logs identify a user's social graph — the raw material of spyware.",
                    new String[]{"T1432"},
                    ev("AndroidManifest.xml", "READ_CONTACTS/READ_CALL_LOG + INTERNET"));
        }

        if (c.has("android.permission.MANAGE_EXTERNAL_STORAGE")
                || c.has("android.permission.QUERY_ALL_PACKAGES")) {
            add(r, "PERM-08", "Requests broad storage or package visibility", "medium",
                    "reconnaissance",
                    "The app asks for all-files access or a full list of installed packages.",
                    "Broad visibility supports profiling the device and is not needed by most apps.",
                    new String[]{"T1418"},
                    ev("AndroidManifest.xml", c.has("android.permission.MANAGE_EXTERNAL_STORAGE")
                            ? "MANAGE_EXTERNAL_STORAGE" : "QUERY_ALL_PACKAGES"));
        }

        if (c.has("android.permission.PACKAGE_USAGE_STATS")) {
            add(r, "PERM-09", "Requests usage-statistics access", "medium", "surveillance",
                    "The app can read which apps are used and when.",
                    "Usage history reveals behaviour, schedules and relationships; only a few "
                            + "legitimate categories need it.",
                    new String[]{"T1430"},
                    ev("AndroidManifest.xml", "PACKAGE_USAGE_STATS"));
        }

        if ((c.has("android.permission.RECORD_AUDIO") || c.has("android.permission.CAMERA"))
                && (c.has("android.permission.RECEIVE_BOOT_COMPLETED")
                || c.has("android.permission.FOREGROUND_SERVICE"))) {
            add(r, "PERM-10", "Can record audio or camera and run persistently", "high",
                    "spyware",
                    "The app can capture the microphone or camera and stay running.",
                    "Sensor capture plus persistence is the core of commercial spyware.",
                    new String[]{"T1429"},
                    ev("AndroidManifest.xml", "RECORD_AUDIO/CAMERA + persistence"));
        }

        if (c.has("android.permission.ACCESS_FINE_LOCATION")
                && c.has("android.permission.ACCESS_BACKGROUND_LOCATION")
                && c.has("android.permission.INTERNET")) {
            add(r, "PERM-11", "Tracks location in the background and can upload it", "high",
                    "stalkerware",
                    "The app can follow location while not in use and send it off the device.",
                    "Covert location tracking is the defining capability of stalkerware.",
                    new String[]{"T1430"},
                    ev("AndroidManifest.xml", "FINE_LOCATION + BACKGROUND_LOCATION + INTERNET"));
        }

        // Code-level signals ------------------------------------------------
        if (!c.self) {
            if (c.has("SmsManager") && c.hasAny("sendTextMessage", "sendMultipartTextMessage",
                    "sendDataMessage")) {
                add(r, "API-01", "Sends SMS from code", "high", "sms_fraud",
                        "The code calls the SMS manager directly.",
                        "Silent premium-SMS sending is fraud; OTP interception also sends or forwards messages.",
                        new String[]{"T1412"},
                        ev("classes.dex", "SmsManager + send*Message"));
            }
            if (c.hasAny("Ldalvik/system/DexClassLoader;", "Ldalvik/system/PathClassLoader;",
                    "Ldalvik/system/InMemoryDexClassLoader;")) {
                add(r, "API-02", "Loads code at runtime", "high", "dynamic_code",
                        "The app loads executable code that was not part of the installed APK.",
                        "Runtime loading hides the real payload from store review and from static analysis.",
                        new String[]{"T1407"},
                        ev("classes.dex", "DexClassLoader/PathClassLoader"));
            }
            if (c.has("Ljava/lang/ProcessBuilder;") || c.has("Runtime;->exec")) {
                add(r, "API-03", "Executes shell commands", "medium", "execution",
                        "The code can spawn an operating-system process.",
                        "Shell execution is rarely needed by ordinary apps and is common in droppers "
                                + "and exploit chains.",
                        new String[]{"T1623"},
                        ev("classes.dex", "ProcessBuilder / Runtime.exec"));
            }
            if (c.has("addJavascriptInterface") && c.has("setJavaScriptEnabled")
                    && c.has("loadUrl")) {
                add(r, "API-04", "Exposes a JavaScript bridge in a WebView", "high", "webview",
                        "The app enables JavaScript and exposes native methods to web content.",
                        "A bridge reachable from remote or attacker-controlled content can lead to "
                                + "code execution in the app's context.",
                        new String[]{"T1417"},
                        ev("classes.dex", "addJavascriptInterface + setJavaScriptEnabled"));
            }
            if (c.has("Ljavax/crypto/Cipher;")
                    && (c.codeUpper.contains("AES/ECB") || c.codeUpper.contains("DES/ECB")
                    || c.codeUpper.contains("DESEDE/ECB"))) {
                add(r, "API-05", "Uses weak or hardcoded cryptography", "medium", "obfuscation",
                        "The code selects ECB mode, which leaks patterns in encrypted data.",
                        "ECB is deterministic and unsuitable for protecting user data.",
                        new String[]{"T1521"},
                        ev("classes.dex", "Cipher + AES/ECB"));
            }
            if (c.has("TelephonyManager")
                    && c.hasAny("getDeviceId", "getSubscriberId", "getLine1Number", "getImei")) {
                add(r, "API-06", "Reads telephony identifiers", "medium", "fingerprinting",
                        "The app reads hardware or subscriber identifiers.",
                        "Persistent identifiers let an app re-identify a device after uninstall or reset.",
                        new String[]{"T1426"},
                        ev("classes.dex", "TelephonyManager identifiers"));
            }
            if (c.has("ContentResolver") && c.hasAny("query", "rawQuery")
                    && c.hasAny("content://sms", "content://mms", "content://contacts",
                    "content://call_log")) {
                add(r, "API-07", "Queries SMS, contacts or call-log providers", "high",
                        "data_harvesting",
                        "The code reads protected content providers directly.",
                        "Direct provider access is how bulk SMS and contact collection is implemented.",
                        new String[]{"T1432"},
                        ev("classes.dex", "ContentResolver + content://sms/contacts"));
            }
            if (c.has("AccessibilityService") && c.has("performGlobalAction")) {
                add(r, "API-08", "Automates the interface through accessibility", "high",
                        "accessibility_abuse",
                        "The service performs global navigation actions.",
                        "Global actions let malware click through consent and payment screens.",
                        new String[]{"T1417"},
                        ev("classes.dex", "AccessibilityService + performGlobalAction"));
            }
            if (c.has("DevicePolicyManager") && c.hasAny("lockNow", "wipeData")) {
                add(r, "API-09", "Can lock or wipe the device", "critical", "ransomware",
                        "The code calls device-administrator lock or wipe APIs.",
                        "Locking or wiping on command is the enforcement half of Android ransomware.",
                        new String[]{"T1629"},
                        ev("classes.dex", "DevicePolicyManager lockNow/wipeData"));
            }
            if (c.has("getPrimaryClip")) {
                add(r, "API-10", "Reads the clipboard", "medium", "credential_theft",
                        "The app reads clipboard contents.",
                        "Users copy passwords and card numbers; clipboard access is a cheap "
                                + "credential-harvesting path.",
                        new String[]{"T1414"},
                        ev("classes.dex", "getPrimaryClip"));
            }
            if (c.hasAny("getInstalledPackages", "getInstalledApplications")
                    && c.hasAny("Ljava/net/Socket;", "Ljava/net/HttpURLConnection;",
                    "Lokhttp3/OkHttpClient;")) {
                add(r, "API-11", "Inventories installed apps and can upload the list", "low",
                        "reconnaissance",
                        "The app enumerates other installed packages and has a network client.",
                        "The installed-app list is a strong fingerprint and is used to target victims.",
                        new String[]{"T1418"},
                        ev("classes.dex", "getInstalledPackages + network client"));
            }
            if (c.has("forName") && c.hasAny("getDeclaredMethod", "getDeclaredField")) {
                add(r, "API-12", "Resolves methods and fields by reflection", "medium",
                        "anti_analysis",
                        "The code looks up classes and members dynamically.",
                        "Reflection hides API use from simple inspection and can reach private APIs.",
                        new String[]{"T1620"},
                        ev("classes.dex", "Class.forName + getDeclared*"));
            }
            if (c.has("Landroid/util/Base64;") && c.has("Ljavax/crypto/Cipher;")
                    && c.hasAny("Ldalvik/system/DexClassLoader;", "Ldalvik/system/PathClassLoader;",
                    "Ldalvik/system/InMemoryDexClassLoader;")) {
                add(r, "API-15", "Combines Base64, crypto and a class loader", "high",
                        "obfuscation",
                        "The app decodes and decrypts a blob and loads it as code.",
                        "This chain is the standard packer/loader pattern for hidden payloads.",
                        new String[]{"T1027", "T1407"},
                        ev("classes.dex", "Base64 + Cipher + ClassLoader"));
            }
        }

        // Network indicators -------------------------------------------------
        if (matches(c.code, "https?://\\d{1,3}(\\.\\d{1,3}){3}(:\\d{2,5})?", 0)) {
            add(r, "NET-01", "Contacts a raw IP address or non-standard port", "medium", "c2",
                    "An embedded URL points at a numeric address.",
                    "Legitimate services use domain names; raw IP endpoints are common in C2 and "
                            + "short-lived exfiltration infrastructure.",
                    new String[]{"T1071"},
                    ev("classes.dex", firstMatchPattern(c.code, "https?://\\d{1,3}(\\.\\d{1,3}){3}")));
        }
        if (c.hasAny("api.telegram.org/bot", "discord.com/api/webhooks",
                "discordapp.com/api/webhooks")) {
            add(r, "NET-02", "Ships a Telegram or Discord exfiltration endpoint", "high",
                    "exfiltration",
                    "The app embeds a chat-platform bot or webhook URL.",
                    "Free chat APIs are widely used to receive stolen data without owning infrastructure.",
                    new String[]{"T1567"},
                    ev("classes.dex", "telegram/discord webhook"));
        }
        if (c.cleartext || matches(c.code, "^http://", Pattern.MULTILINE)) {
            add(r, "NET-03", "Allows cleartext HTTP traffic", "low", "transport",
                    "The app may send data over unencrypted HTTP.",
                    "Cleartext traffic can be read or modified on the network.",
                    new String[]{"T1040"},
                    ev("AndroidManifest.xml", c.cleartext ? "usesCleartextTraffic=true" : "http:// URL"));
        }
        if (c.containsAnyLower("duckdns", "no-ip", "ngrok", "pastebin", ".onion", "serveo",
                "trycloudflare")) {
            add(r, "NET-04", "Uses disposable or anonymised infrastructure", "medium", "c2",
                    "A URL uses a dynamic-DNS, tunnel or paste service.",
                    "These services are cheap to rotate and hide the operator's identity.",
                    new String[]{"T1583"},
                    ev("classes.dex", "dynamic DNS / tunnel domain"));
        }
        String credential = firstMatchPattern(c.code,
                "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}");
        if (credential != null) {
            add(r, "NET-05", "Contains a hardcoded cloud credential", "medium",
                    "credential_leak",
                    "An AWS or Google API key is embedded in the APK.",
                    "Anyone who downloads the APK can extract and abuse the key.",
                    new String[]{"T1552"},
                    ev("classes.dex", credential));
        }

        // Identity and posture ----------------------------------------------
        if (c.certDebug || c.certExpired) {
            add(r, "ID-01", "Signed with a debug or expired certificate", "low", "identity",
                    "The signing certificate is a debug key or has expired.",
                    "Debug keys are not controlled; an expired certificate stops clean updates and "
                            + "suggests the build is not maintained.",
                    new String[]{"T1553"},
                    ev("APK signature", c.certExpired ? "expired certificate" : "debug certificate"));
        }
        if (c.debug || c.testOnly) {
            add(r, "ID-04", "Insecure build flags", "low", "posture",
                    "The manifest enables debuggable or test-only mode.",
                    "A debuggable app allows attaching a debugger and reading private data.",
                    new String[]{"T1622"},
                    ev("AndroidManifest.xml", c.debug ? "android:debuggable=\"true\""
                            : "android:testOnly=\"true\""));
        }
        if (!c.packers.isEmpty()) {
            add(r, "ID-05", "Known packer or protector detected", "medium", "obfuscation",
                    "Strings belonging to a commercial packer were found.",
                    "Packing is not malicious by itself, but it hides the code from this scan. "
                            + "Treat a low score as inconclusive.",
                    new String[]{"T1027"},
                    ev("classes.dex", join(c.packers)));
        }
        if (c.assetPayload || c.highEntropyAsset) {
            add(r, "ID-06", "Ships a hidden second-stage payload in assets", "high", "dropper",
                    "The APK contains a bundled archive, executable or high-entropy blob in assets.",
                    "Attackers ship an encrypted payload that the app decrypts and loads after install.",
                    new String[]{"T1407"},
                    ev("assets/", c.assetNames.isEmpty() ? "high-entropy asset" : join(c.assetNames)));
        }
        if (c.exportedUnprotected > 0) {
            add(r, "ID-07", "Exports components without protecting them", "medium",
                    "attack_surface",
                    c.exportedUnprotected + " component(s) are exported with no permission guard.",
                    "Any app on the device can invoke an exported component, which may expose data "
                            + "or trigger privileged actions.",
                    new String[]{"T1626"},
                    ev("AndroidManifest.xml", "android:exported=\"true\" without permission"));
        }

        // Components ---------------------------------------------------------
        if (c.componentContains(c.services, "AccessibilityService")) {
            add(r, "CMP-01", "Declares an accessibility service", "high",
                    "accessibility_abuse",
                    "A service is declared with accessibility capability.",
                    "Accessibility services can observe and control other apps' interfaces.",
                    new String[]{"T1417"},
                    ev("AndroidManifest.xml", firstMatch(c.services, "AccessibilityService")));
        }
        if (c.componentContains(c.services, "NotificationListenerService")) {
            add(r, "CMP-02", "Declares a notification listener", "high",
                    "notification_interception",
                    "A service can read all notifications.",
                    "Notification access exposes one-time passcodes and message previews in real time.",
                    new String[]{"T1414"},
                    ev("AndroidManifest.xml", firstMatch(c.services, "NotificationListenerService")));
        }
        if (c.smsReceiver) {
            add(r, "CMP-05", "Registers for incoming SMS broadcasts", "high",
                    "sms_interception",
                    "A receiver is registered for the SMS_RECEIVED broadcast.",
                    "Listening for incoming messages is how OTP-harvesting apps get the code first.",
                    new String[]{"T1412"},
                    ev("AndroidManifest.xml", "SMS_RECEIVED receiver"));
        }

        // Combinations -------------------------------------------------------
        combo(r, "BANKER", "Banking-trojan pattern",
                "Screen control, draw-over windows, SMS access and a network path together "
                        + "describe a banking trojan campaign rather than isolated risky permissions.",
                new String[]{"PERM-01", "PERM-02", "PERM-03", "NET-01"});
        combo(r, "OTP-STEALER", "One-time-passcode interception pattern",
                "Reading incoming SMS while listening for the broadcast, with no visible messaging "
                        + "purpose, is how OTPs are harvested.",
                new String[]{"PERM-01", "CMP-05"});
        combo(r, "DROPPER", "Second-stage dropper pattern",
                "Install capability plus runtime DEX loading plus a shipped blob means the analysed "
                        + "file is only the first stage.",
                new String[]{"PERM-04", "API-02", "ID-06"});
        combo(r, "RANSOM", "Ransomware pattern",
                "Device-admin rights, lock or wipe calls and boot persistence are the standard "
                        + "Android ransomware chain.",
                new String[]{"PERM-05", "API-09", "PERM-06"});
        combo(r, "STALKER", "Stalkerware pattern",
                "Background location combined with reboot persistence and upload capability "
                        + "describes covert tracking.",
                new String[]{"PERM-11", "PERM-06"});
        combo(r, "SPYWARE", "Bulk personal-data harvesting",
                "Contacts or call logs plus SMS plus a network path is bulk collection of the data "
                        + "spyware sells.",
                new String[]{"PERM-07", "PERM-01", "NET-01"});
        combo(r, "NOTIF-SNIFFER", "Notification interception with exfiltration",
                "A notification listener plus an embedded exfiltration endpoint lets the app "
                        + "forward 2FA codes in real time.",
                new String[]{"CMP-02", "NET-02"});
    }

    private static void combo(Model.Report report, String id, String title, String rationale,
                              String[] ids) {
        for (String finding : ids) {
            if (!report.has(finding)) return;
        }
        List<String> list = new ArrayList<>();
        Collections.addAll(list, ids);
        report.combos.add(new Model.Combo(id, title, rationale, list));
    }

    private static void add(Model.Report report, String id, String title, String severity,
                            String category, String description, String rationale,
                            String[] mitre, Model.Evidence evidence) {
        Model.Finding finding = new Model.Finding(id, title, severity, category, description, rationale);
        if (mitre != null) Collections.addAll(finding.mitre, mitre);
        if (evidence != null) finding.evidence.add(evidence);
        report.findings.add(finding);
    }

    private static Model.Evidence ev(String artifact, String quote) {
        return new Model.Evidence(artifact, quote);
    }

    // ----------------------------------------------------------------- scoring

    private static void score(Ctx c, Model.Report report) {
        int base = 0;
        int withEvidence = 0;
        for (Model.Finding finding : report.findings) {
            base += ScoreMath.points(finding.severity);
            if (!finding.evidence.isEmpty()) withEvidence++;
        }
        double saturated = ScoreMath.saturate(base);
        int bonus = ScoreMath.comboBonus(report.combos.size());
        boolean inconclusive = ScoreMath.inconclusive(!c.packers.isEmpty(), c.coverage);
        int value = ScoreMath.value(base, report.combos.size(), 0);

        Model.Score score = report.score;
        score.basePoints = base;
        score.saturated = saturated;
        score.comboBonus = bonus;
        score.value = value;
        score.band = ScoreMath.bandFor(value);
        score.coverage = c.coverage;
        score.inconclusive = inconclusive;
        score.confidence = ScoreMath.confidence(
                c.coverage, report.findings.size(), withEvidence, inconclusive);

        if (inconclusive) {
            score.notes.add("Inconclusive — dynamic analysis recommended: code was hidden from "
                    + "static analysis, so a low score is not evidence of safety.");
        }
        if (!c.packers.isEmpty()) {
            score.notes.add("Packer detected: " + join(c.packers) + ".");
        }
        if (report.findings.isEmpty()) {
            score.notes.add("No known malicious signals found in the code that could be inspected.");
        }
        if (!c.codeRead) {
            score.notes.add("Android did not expose this app's DEX to the scanner, so only the "
                    + "manifest and certificate were checked.");
        } else if (c.coverage < 1.0 && c.packers.isEmpty()) {
            score.notes.add("Static coverage is " + Ui.percent(c.coverage) + " of the DEX files.");
        }
        if (score.notes.isEmpty()) {
            score.notes.add("Findings are derived from the manifest, permissions, components and "
                    + "strings in the DEX.");
        }
    }

    // ----------------------------------------------------------------- helpers

    private static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private static boolean matches(String text, String regex, int flags) {
        if (text == null || text.isEmpty()) return false;
        return Pattern.compile(regex, flags).matcher(text).find();
    }

    private static String firstMatchPattern(String text, String regex) {
        if (text == null || text.isEmpty()) return null;
        try {
            Matcher matcher = Pattern.compile(regex).matcher(text);
            if (matcher.find()) return matcher.group();
        } catch (RuntimeException ignored) {
        }
        return null;
    }

    private static String firstMatch(Set<String> values, String needle) {
        for (String value : values) {
            if (value.contains(needle)) return value;
        }
        return needle;
    }

    private static String join(Set<String> values) {
        StringBuilder builder = new StringBuilder();
        for (String value : values) {
            if (builder.length() > 0) builder.append(", ");
            builder.append(value);
        }
        return builder.toString();
    }

    /** Everything extracted for a single package while a scan runs. */
    private static final class Ctx {
        PackageInfo info;
        final Set<String> permissions = new HashSet<>();
        final Set<String> services = new HashSet<>();
        final Set<String> receivers = new HashSet<>();
        final Set<String> activities = new HashSet<>();
        final Set<String> providers = new HashSet<>();
        final Set<String> packers = new HashSet<>();
        final Set<String> assetNames = new HashSet<>();

        String code = "";
        String codeLower = "";
        String codeUpper = "";
        boolean codeRead;
        double coverage;
        int dexCount;
        int dexRead;
        String readError;
        String certSubject;

        boolean self;
        boolean debug;
        boolean testOnly;
        boolean cleartext;
        boolean certDebug;
        boolean certExpired;
        boolean smsReceiver;
        boolean assetPayload;
        boolean highEntropyAsset;
        int exportedUnprotected;

        boolean has(String permission) {
            return permissions.contains(permission);
        }

        boolean hasAny(String... needles) {
            for (String needle : needles) {
                if (code.contains(needle)) return true;
            }
            return false;
        }

        boolean containsAnyLower(String... needles) {
            for (String needle : needles) {
                if (codeLower.contains(needle)) return true;
            }
            return false;
        }

        boolean componentContains(Set<String> names, String needle) {
            for (String name : names) {
                if (name.contains(needle)) return true;
            }
            return false;
        }
    }
}
