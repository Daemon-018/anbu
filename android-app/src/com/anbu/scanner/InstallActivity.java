package com.anbu.scanner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.app.PendingIntent;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * Gatekeeper installer: Scan first, then decide.
 * Handles ACTION_VIEW/SEND for APKs and bundles.
 */
public final class InstallActivity extends Activity {

    public static final int REQ_OPEN_APK = 9101;
    public static final String EXTRA_APK_URI = "com.anbu.scanner.APK_URI";

    public InstallSet.Result set;
    public Model.Report report;
    public LinearLayout content;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(buildRoot());

        Uri uri = null;
        Intent intent = getIntent();
        if (intent == null) return;

        if ("android.intent.action.SEND".equals(intent.getAction())) {
            uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        } else if ("android.intent.action.VIEW".equals(intent.getAction())) {
            uri = intent.getData();
        } else {
            uri = intent.getParcelableExtra(EXTRA_APK_URI);
        }

        if (uri == null) {
            Toast.makeText(this, "No APK provided", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        prepareAndScan(uri);
    }

    private View buildRoot() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.getBg());
        root.setFitsSystemWindows(true);

        content = Ui.column(this);
        content.setPadding(Ui.dp(this, 18), Ui.dp(this, 18), Ui.dp(this, 18), Ui.dp(this, 18));
        content.setVisibility(View.GONE);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        // Loading state: The "Deassemble" animation container
        LinearLayout loading = Ui.column(this);
        loading.setGravity(Gravity.CENTER);
        
        // Center Icon
        ImageView iconView = new ImageView(this);
        iconView.setLayoutParams(new LinearLayout.LayoutParams(Ui.dp(this, 120), Ui.dp(this, 120)));
        iconView.setPadding(Ui.dp(this, 10), Ui.dp(this, 10), Ui.dp(this, 10), Ui.dp(this, 10));
        iconView.setElevation(20f);
        // Use a default image if R is missing during compilation
        loading.addView(iconView);
        this.scanIcon = iconView;

        // Progress Text
        TextView msg = Ui.text(this, "Initializing...", 16, Ui.getText(), true);
        msg.setGravity(Gravity.CENTER);
        msg.setPadding(0, Ui.dp(this, 24), 0, 0);
        loading.addView(msg);
        this.loadingText = msg;

        root.addView(loading, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        loading.setId(View.generateViewId());
        this.loadingView = loading;

        return root;
    }

    public View loadingView;
    public ImageView scanIcon;
    public TextView loadingText;

    private void prepareAndScan(Uri uri) {
        new Thread(new InstallHelpers.ScanWorker(this, uri), "anbu-gatekeeper").start();
    }

// Remove the now redundant static inner classes from InstallActivity


    public void animateShatter() {
        if (scanIcon == null) return;
        scanIcon.animate()
                .scaleX(0.8f)
                .scaleY(0.8f)
                .setDuration(300)
                .withEndAction(() -> {
                    scanIcon.animate().scaleX(1.0f).scaleY(1.0f).setDuration(200).start();
                })
                .start();
    }

    public void animatePulse() {
        if (scanIcon == null) return;
        scanIcon.animate()
                .scaleX(1.1f)
                .scaleY(1.1f)
                .setDuration(100)
                .withEndAction(() -> {
                    scanIcon.animate().scaleX(1.0f).scaleY(1.0f).setDuration(100).start();
                })
                .start();
    }

    public void renderDecision() {
        if (loadingView != null) loadingView.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        content.removeAllViews();

        // Header
        LinearLayout header = Ui.row(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = Ui.text(this, set.displayName, 22, Ui.getText(), true);
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        
        String band = report.score.band;
        TextView bandChip = Ui.chip(this, Ui.bandLabel(band), Ui.bandColor(band));
        header.addView(bandChip);
        content.addView(header);
        Ui.slideUp(header);

        Ui.addSpace(content, 20);

        // Verdict Card
        LinearLayout verdict = Ui.card(this);
        TextView vTitle = Ui.text(this, "Verdict", 14, Ui.getMuted(), false);
        verdict.addView(vTitle);
        Ui.addSpace(verdict, 8);
        TextView vMsg = Ui.text(this, Ui.bandLabel(band), 20, Ui.bandColor(band), true);
        verdict.addView(vMsg);
        content.addView(verdict);
        Ui.slideUp(verdict);

        Ui.addSpace(content, 20);

        // Findings Card
        if (!report.findings.isEmpty()) {
            LinearLayout findings = Ui.card(this);
            findings.addView(Ui.text(this, "Findings", 14, Ui.getMuted(), false));
            Ui.addSpace(findings, 8);
            for (Model.Finding f : report.findings) {
                LinearLayout row = Ui.row(this);
                TextView sev = Ui.chip(this, f.severity, Ui.severityColor(f.severity));
                row.addView(sev);
                Ui.addSpace(row, 8);
                TextView desc = Ui.text(this, f.title, 14, Ui.getText(), false);
                row.addView(desc);
                findings.addView(row);
                Ui.addSpace(findings, 6);
            }
            content.addView(findings);
            Ui.slideUp(findings);
            Ui.addSpace(content, 20);
        }

        // Actions
        LinearLayout actions = Ui.column(this);
        if ("likely_benign".equals(band) || "low".equals(band)) {
            Button btn = Ui.button(this, "Install", true);
            btn.setOnClickListener(v -> startInstall());
            actions.addView(btn);
        } else if ("suspicious".equals(band)) {
            Button btn = Ui.button(this, "Install anyway (Own Risk)", true);
            btn.setOnClickListener(v -> {
                new AlertDialog.Builder(this)
                        .setTitle("Suspicious App")
                        .setMessage("This app has signals that may be dangerous. Do you want to proceed anyway?")
                        .setPositiveButton("Proceed", (d, w) -> startInstall())
                        .setNegativeButton("Cancel", null)
                        .show();
            });
            actions.addView(btn);
        } else {
            // High / Critical
            Button btn = Ui.button(this, "Block & Delete", true);
            btn.setOnClickListener(v -> {
                InstallSet.cleanup(set);
                Toast.makeText(this, "File deleted", Toast.LENGTH_SHORT).show();
                finish();
            });
            actions.addView(btn);

            Ui.addSpace(actions, 12);
            Button override = Ui.button(this, "Override Block (Dangerous)", false);
            override.setOnClickListener(v -> {
                new AlertDialog.Builder(this)
                        .setTitle("Critical Warning")
                        .setMessage("This app is highly likely to be malicious. Installing it may compromise your device. Are you absolutely sure?")
                        .setPositiveButton("I accept the risk", (d, w) -> startInstall())
                        .setNegativeButton("Cancel", null)
                        .show();
            });
            actions.addView(override);
        }
        content.addView(actions);
        Ui.slideUp(actions);
    }

    private void startInstall() {
        if (!canInstall()) {
            requestInstallPermission();
            return;
        }

        new Thread(() -> {
            try {
                PackageInstaller pi = getPackageManager().getPackageInstaller();
                PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                        PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                int sessionId = pi.createSession(params);
                PackageInstaller.Session session = pi.openSession(sessionId);

                // Write APKs to session
                for (File apk : set.apks) {
                    try (OutputStream os = session.openWrite(apk.getName(), 0, apk.length())) {
                        try (FileInputStream is = new FileInputStream(apk)) {
                            byte[] buffer = new byte[64 * 1024];
                            int read;
                            while ((read = is.read(buffer)) > 0) {
                                os.write(buffer, 0, read);
                            }
                        }
                        os.flush();
                    }
                }

                // Result receiver
                Intent intent = new Intent(this, InstallResultReceiver.class);
                intent.putExtra(InstallResultReceiver.EXTRA_SESSION_DIR, set.dir);
                PendingIntent pendingIntent = android.app.PendingIntent.getBroadcast(
                        this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);

                session.commit(pendingIntent.getIntentSender());
                session.close();

                runOnUiThread(() -> {
                    Toast.makeText(this, "Installation started...", Toast.LENGTH_SHORT).show();
                    finish();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    showError("Install failed: " + e.getMessage());
                    finish();
                });
            }
        }, "anbu-install").start();
    }

    private boolean canInstall() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return getPackageManager().canRequestPackageInstalls();
        }
        return true;
    }

    private void requestInstallPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES);
            intent.setData(Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } else {
            startInstall(); // Fallback for older APIs
        }
    }

    public void showError(String msg) {
        new AlertDialog.Builder(this)
                .setTitle("Error")
                .setMessage(msg)
                .setPositiveButton("OK", null)
                .show();
    }
}
