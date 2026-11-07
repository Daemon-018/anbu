package com.anbu.scanner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Home screen: lists installed packages and sends one — or all user apps — to the scanner.
 * Nothing is read until the user taps a row or the scan button.
 */
public final class MainActivity extends Activity {

    private static final String PREFS = "anbu";
    private static final String PREF_SEEN = "disclosure_seen_v1";

    private final List<Model.AppEntry> apps = new ArrayList<>();
    private LinearLayout list;
    private TextView listStatus;
    private EditText filter;
    private TextView systemToggle;
    private boolean showSystem;
    private boolean loaded;
    private String query = "";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(build());
        showDisclosureOnce();
        loadApps();
    }

    private View build() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);
        root.setFitsSystemWindows(true);

        LinearLayout header = Ui.column(this);
        int hp = Ui.dp(this, 20);
        header.setPadding(hp, Ui.dp(this, 18), hp, Ui.dp(this, 6));
        header.addView(Ui.text(this, "ANBU", 30, Ui.TEXT, true));
        header.addView(Ui.text(this,
                "On-device app auditor \u00B7 nothing leaves this phone", 12, Ui.MUTED, false));
        root.addView(header);

        LinearLayout controls = Ui.column(this);
        int cp = Ui.dp(this, 18);
        controls.setPadding(cp, Ui.dp(this, 8), cp, Ui.dp(this, 8));

        LinearLayout topRow = Ui.row(this);
        filter = new EditText(this);
        filter.setHint("Filter installed apps");
        filter.setSingleLine(true);
        filter.setTextSize(14);
        filter.setTextColor(Ui.TEXT);
        filter.setHintTextColor(Ui.MUTED);
        filter.setBackground(Ui.background(this, Ui.SURFACE, 12, Ui.LINE));
        int fp = Ui.dp(this, 14);
        filter.setPadding(fp, Ui.dp(this, 10), fp, Ui.dp(this, 10));
        filter.addTextChangedListener(new FilterWatcher(() -> {
            query = filter.getText() == null
                    ? ""
                    : filter.getText().toString().trim().toLowerCase(Locale.US);
            renderList();
        }));
        topRow.addView(filter, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button openBtn = Ui.button(this, "Open APK...", false);
        openBtn.setOnClickListener(v -> openApkPicker());
        topRow.addView(openBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        controls.addView(topRow);

        LinearLayout actions = Ui.row(this);
        actions.setPadding(0, Ui.dp(this, 10), 0, 0);
        android.widget.Button scanAll = Ui.button(this, "Scan all user apps", true);
        scanAll.setOnClickListener(v -> scanAll());
        actions.addView(scanAll, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        View gap = new View(this);
        actions.addView(gap, new LinearLayout.LayoutParams(Ui.dp(this, 8), 1));

        systemToggle = Ui.button(this, systemLabel(), false);
        systemToggle.setOnClickListener(v -> {
            showSystem = !showSystem;
            systemToggle.setText(systemLabel());
            renderList();
        });
        actions.addView(systemToggle, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        controls.addView(actions);

        listStatus = Ui.text(this, "Reading installed packages\u2026", 12, Ui.MUTED, false);
        listStatus.setPadding(0, Ui.dp(this, 14), 0, Ui.dp(this, 6));
        controls.addView(listStatus);
        root.addView(controls);

        list = Ui.column(this);
        list.setPadding(cp, 0, cp, Ui.dp(this, 24));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(list, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private String systemLabel() {
        return showSystem ? "System: on" : "System: off";
    }

    private void showDisclosureOnce() {
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        if (prefs.getBoolean(PREF_SEEN, false)) return;
        new AlertDialog.Builder(this)
                .setTitle("Before you scan")
                .setMessage("ANBU inspects apps that are already installed: their manifest, "
                        + "permissions, exported components, signing certificate and readable "
                        + "code strings. Everything stays on this device.\n\n"
                        + "A low score is not a promise of safety. Apps may already have run, "
                        + "and dynamic or server-side behaviour cannot be seen from here.")
                .setPositiveButton("I understand", (dialog, which) ->
                        prefs.edit().putBoolean(PREF_SEEN, true).apply())
                .setCancelable(false)
                .show();
    }

    private void loadApps() {
        new Thread(() -> {
            List<Model.AppEntry> result = ScanEngine.listApps(getApplicationContext());
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                apps.clear();
                apps.addAll(result);
                loaded = true;
                renderList();
            });
        }, "anbu-list").start();
    }

    private void openApkPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        String[] mimeTypes = {"application/vnd.android.package-archive", "application/octet-stream", "application/zip"};
        intent.putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes);
        startActivityForResult(intent, InstallActivity.REQ_OPEN_APK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == InstallActivity.REQ_OPEN_APK && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                Intent intent = new Intent(this, InstallActivity.class);
                intent.putExtra(InstallActivity.EXTRA_APK_URI, uri);
                startActivity(intent);
            }
        }
    }

    private void renderList() {
        if (list == null) return;
        list.removeAllViews();
        if (!loaded) {
            listStatus.setText("Reading installed packages\u2026");
            return;
        }

        List<Model.AppEntry> visible = new ArrayList<>();
        int userCount = 0;
        for (Model.AppEntry app : apps) {
            if (!app.system) userCount++;
            if (app.system && !showSystem) continue;
            if (!query.isEmpty()) {
                String label = app.label == null ? "" : app.label.toLowerCase(Locale.US);
                String pkg = app.packageName == null ? "" : app.packageName.toLowerCase(Locale.US);
                if (!label.contains(query) && !pkg.contains(query)) continue;
            }
            visible.add(app);
        }

        listStatus.setText(visible.size() + " shown \u00B7 " + userCount
                + " user apps \u00B7 tap an app to scan it");

        if (visible.isEmpty()) {
            LinearLayout empty = Ui.card(this);
            empty.addView(Ui.text(this, query.isEmpty() ? "No apps to show" : "No matches",
                    15, Ui.TEXT, true));
            empty.addView(Ui.text(this, query.isEmpty()
                            ? "Android did not return any installed packages."
                            : "Try part of the app name or package id.",
                    12, Ui.MUTED, false));
            list.addView(empty, margins(0, 6, 0, 8));
            return;
        }

        for (Model.AppEntry app : visible) {
            list.addView(appRow(app), margins(0, 0, 0, 8));
        }
    }

    private View appRow(Model.AppEntry app) {
        LinearLayout row = Ui.card(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        row.addView(Ui.image(this, app.icon, 44));

        LinearLayout texts = Ui.column(this);
        texts.setPadding(Ui.dp(this, 12), 0, Ui.dp(this, 8), 0);
        String label = app.label == null || app.label.isEmpty() ? app.packageName : app.label;
        texts.addView(Ui.text(this, label, 15, Ui.TEXT, true));
        texts.addView(Ui.text(this, app.packageName, 11, Ui.MUTED, false));

        String meta = app.versionName == null || app.versionName.isEmpty()
                ? "" : "v" + app.versionName;
        if (app.system) meta = meta.isEmpty() ? "system app" : meta + " \u00B7 system app";
        if (!meta.isEmpty()) texts.addView(Ui.text(this, meta, 11, Ui.MUTED, false));

        row.addView(texts, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(Ui.text(this, "\u203A", 26, Ui.MUTED, false));

        row.setOnClickListener(v -> {
            Intent intent = new Intent(this, ScanActivity.class);
            intent.putExtra(ScanActivity.EXTRA_PACKAGE, app.packageName);
            startActivity(intent);
        });
        return row;
    }

    private void scanAll() {
        List<String> packages = new ArrayList<>();
        for (Model.AppEntry app : apps) {
            if (!app.system) packages.add(app.packageName);
        }
        if (packages.isEmpty()) {
            if (!loaded) {
                Toast.makeText(this, "Still reading installed packages\u2026",
                        Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "No user apps to scan", Toast.LENGTH_SHORT).show();
            }
            return;
        }
        Intent intent = new Intent(this, ScanActivity.class);
        intent.putExtra(ScanActivity.EXTRA_PACKAGES, packages.toArray(new String[0]));
        startActivity(intent);
    }

    private LinearLayout.LayoutParams margins(int left, int top, int right, int bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(Ui.dp(this, left), Ui.dp(this, top),
                Ui.dp(this, right), Ui.dp(this, bottom));
        return params;
    }

    /** Named watcher; an anonymous inner class trips the bundled D8 version. */
    private static final class FilterWatcher implements TextWatcher {
        private final Runnable onChange;

        FilterWatcher(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        }

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {
        }

        @Override
        public void afterTextChanged(Editable s) {
            onChange.run();
        }
    }
}
