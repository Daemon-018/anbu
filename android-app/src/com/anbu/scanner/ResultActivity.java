package com.anbu.scanner;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Score and verdict for a single app. The numeric score is never shown without the
 * band, the confidence and how much code was actually inspected.
 */
public final class ResultActivity extends Activity {

    public static final String EXTRA_REPORT = "com.anbu.scanner.REPORT";
    public static final String EXTRA_PACKAGE = "com.anbu.scanner.PACKAGE";

    private static final int REQUEST_DELETE = 41;

    private String reportKey;
    private String packageName;
    private Model.Report report;

    private LinearLayout content;
    private LinearLayout postUninstall;
    private ScrollView reportScroll;
    private TextView barTitle;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        reportKey = getIntent().getStringExtra(EXTRA_REPORT);
        packageName = getIntent().getStringExtra(EXTRA_PACKAGE);
        report = reportKey == null ? null : Model.Store.get(reportKey);
        if (report == null && getIntent().hasExtra(EXTRA_REPORT)) {
            // The process was recreated after Android killed it; stored reports do not survive.
            packageName = packageName == null ? getIntent().getStringExtra(EXTRA_PACKAGE) : packageName;
        } else if (report != null) {
            packageName = report.app.packageName;
        }

        setContentView(build());

        if (report == null) {
            showMissing();
        } else {
            showReport();
        }
    }

    private View build() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);
        root.setFitsSystemWindows(true);

        LinearLayout top = Ui.row(this);
        top.setPadding(Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 18), Ui.dp(this, 4));
        TextView back = Ui.text(this, "\u2039 Back", 14, Ui.MUTED, true);
        back.setPadding(Ui.dp(this, 6), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        back.setOnClickListener(v -> finish());
        top.addView(back);
        barTitle = Ui.text(this, "Result", 18, Ui.TEXT, true);
        top.addView(barTitle, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(top);

        reportScroll = new ScrollView(this);
        reportScroll.setFillViewport(true);
        content = Ui.column(this);
        int p = Ui.dp(this, 18);
        content.setPadding(p, Ui.dp(this, 4), p, Ui.dp(this, 28));
        reportScroll.addView(content, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(reportScroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        postUninstall = Ui.column(this);
        postUninstall.setPadding(p, Ui.dp(this, 4), p, Ui.dp(this, 28));
        postUninstall.setVisibility(View.GONE);
        root.addView(postUninstall, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return root;
    }

    // ------------------------------------------------------------------ report

    private void showReport() {
        content.removeAllViews();
        postUninstall.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        barTitle.setText("Result");

        content.addView(headerCard());
        Ui.addSpace(content, 12);
        content.addView(verdictCard());

        if (!report.combos.isEmpty()) {
            Ui.addSpace(content, 12);
            content.addView(comboCard(report.combos.get(0)));
        }

        Ui.addSpace(content, 12);
        content.addView(findingsCard());

        if (!report.score.notes.isEmpty()) {
            Ui.addSpace(content, 12);
            content.addView(notesCard());
        }

        Ui.addSpace(content, 16);
        addActions();
        Ui.addSpace(content, 14);
        content.addView(Ui.text(this,
                "Static observation, not runtime proof. A scan cannot see server-side behaviour "
                        + "or code downloaded later, and cannot guarantee an app is safe.",
                11, Ui.MUTED, false));
    }

    private View headerCard() {
        LinearLayout card = Ui.card(this);
        LinearLayout head = Ui.row(this);
        head.setGravity(Gravity.TOP);
        head.addView(Ui.image(this, report.app.icon, 54));

        LinearLayout texts = Ui.column(this);
        texts.setPadding(Ui.dp(this, 12), 0, 0, 0);
        String label = report.app.label == null || report.app.label.isEmpty()
                ? report.app.packageName : report.app.label;
        texts.addView(Ui.text(this, label, 20, Ui.TEXT, true));
        TextView pkg = Ui.text(this, report.app.packageName, 11, Ui.MUTED, false);
        pkg.setTypeface(Typeface.MONOSPACE);
        texts.addView(pkg);
        String meta = report.app.versionName == null || report.app.versionName.isEmpty()
                ? "" : "v" + report.app.versionName;
        if (report.app.system) meta = meta.isEmpty() ? "system app" : meta + " \u00B7 system app";
        if (!meta.isEmpty()) texts.addView(Ui.text(this, meta, 11, Ui.MUTED, false));
        head.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(head);

        LinearLayout chips = Ui.row(this);
        chips.setPadding(0, Ui.dp(this, 12), 0, 0);
        chips.addView(chip(report.detailsOnly ? "Details only" : "Full scan", Ui.MUTED));
        addChipGap(chips);
        chips.addView(chip(report.score.confidence + " confidence",
                "high".equals(report.score.confidence) ? Ui.OK : Ui.MUTED));
        addChipGap(chips);
        chips.addView(chip(Ui.percent(report.score.coverage) + " of code", Ui.MUTED));
        card.addView(chips);
        return card;
    }

    private View verdictCard() {
        LinearLayout card = Ui.card(this);
        Model.Score score = report.score;

        if (score.inconclusive || report.detailsOnly) {
            card.addView(Ui.text(this, "LIMITED INSPECTION", 12, Ui.ACCENT, true));
            TextView headline = Ui.text(this, limitedHeadline(), 20, Ui.TEXT, true);
            headline.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 6));
            card.addView(headline);
            card.addView(Ui.text(this, limitedBody(), 13, Ui.MUTED, false));
            if (score.value > 0) {
                TextView partial = Ui.text(this,
                        "Partial score " + score.value + "/100 \u00B7 low confidence",
                        13, Ui.bandColor(score.band), true);
                partial.setPadding(0, Ui.dp(this, 12), 0, 0);
                card.addView(partial);
            }
            return card;
        }

        LinearLayout figure = Ui.row(this);
        TextView value = Ui.text(this, String.valueOf(score.value), 56,
                Ui.bandColor(score.band), true);
        figure.addView(value);

        LinearLayout words = Ui.column(this);
        words.setPadding(Ui.dp(this, 14), 0, 0, 0);
        words.addView(Ui.text(this, Ui.bandLabel(score.band).toUpperCase(), 16,
                Ui.bandColor(score.band), true));
        words.addView(Ui.text(this, summary(), 13, Ui.TEXT, false));
        figure.addView(words, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(figure);

        String inspected = "Inspected " + Ui.percent(score.coverage) + " of code \u00B7 "
                + report.findings.size() + (report.findings.size() == 1 ? " finding" : " findings");
        TextView stats = Ui.text(this, inspected, 11, Ui.MUTED, false);
        stats.setPadding(0, Ui.dp(this, 10), 0, 0);
        card.addView(stats);
        return card;
    }

    private View comboCard(Model.Combo combo) {
        LinearLayout card = Ui.card(this);
        LinearLayout head = Ui.row(this);
        head.addView(Ui.text(this, "MATCHED PATTERN", 11, Ui.ACCENT, true));
        card.addView(head);
        TextView title = Ui.text(this, combo.title, 17, Ui.TEXT, true);
        title.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 4));
        card.addView(title);
        card.addView(Ui.text(this, combo.rationale, 12, Ui.MUTED, false));
        return card;
    }

    private View findingsCard() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, report.findings.isEmpty() ? "No findings"
                        : report.findings.size() + (report.findings.size() == 1
                        ? " finding" : " findings"),
                17, Ui.TEXT, true));

        if (report.findings.isEmpty()) {
            card.addView(Ui.text(this,
                    "Nothing in the manifest, permissions, certificate or readable code matched "
                            + "a known detection. " + (report.detailsOnly
                            ? "Android did not allow this app's code to be read on this device."
                            : "No scan can guarantee an app is safe."),
                    12, Ui.MUTED, false));
            return card;
        }

        List<Model.Finding> sorted = sortedFindings();
        int shown = Math.min(3, sorted.size());
        for (int i = 0; i < shown; i++) {
            card.addView(findingRow(sorted.get(i)));
        }
        if (sorted.size() > shown) {
            TextView more = Ui.text(this, "+ " + (sorted.size() - shown) + " more", 12, Ui.MUTED, false);
            more.setPadding(0, Ui.dp(this, 4), 0, 0);
            card.addView(more);
        }
        return card;
    }

    private View findingRow(Model.Finding finding) {
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 12), 0, 0);
        row.setGravity(Gravity.TOP);

        TextView severity = Ui.chip(this, finding.severity.toUpperCase(),
                Ui.severityColor(finding.severity));
        row.addView(severity);

        LinearLayout texts = Ui.column(this);
        texts.setPadding(Ui.dp(this, 10), 0, 0, 0);
        texts.addView(Ui.text(this, finding.title, 13, Ui.TEXT, true));
        texts.addView(Ui.text(this, Ui.title(finding.category), 11, Ui.MUTED, false));
        row.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(Ui.text(this, "\u203A", 20, Ui.MUTED, false));
        row.setOnClickListener(v -> openFindings(finding.id));
        return row;
    }

    private View notesCard() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, "About this result", 14, Ui.TEXT, true));
        for (String note : report.score.notes) {
            TextView line = Ui.text(this, "\u2022  " + note, 12, Ui.MUTED, false);
            line.setPadding(0, Ui.dp(this, 7), 0, 0);
            card.addView(line);
        }
        return card;
    }

    // ----------------------------------------------------------------- actions

    private void addActions() {
        String band = report.score.band;
        boolean serious = "high".equals(band) || "critical".equals(band);
        boolean suspicious = "suspicious".equals(band);
        int findings = report.findings.size();

        if (serious) {
            Button uninstall = Ui.button(this, "Uninstall", true);
            uninstall.setOnClickListener(v -> uninstall());
            content.addView(uninstall, fullWidth());

            Ui.addSpace(content, 8);
            Button see = Ui.button(this, "See " + findings
                    + (findings == 1 ? " finding" : " findings"), false);
            see.setOnClickListener(v -> openFindings(null));
            content.addView(see, fullWidth());

            keepAction();
        } else if (suspicious) {
            Button see = Ui.button(this, "Review " + findings
                    + (findings == 1 ? " finding" : " findings"), true);
            see.setOnClickListener(v -> openFindings(null));
            content.addView(see, fullWidth());

            Ui.addSpace(content, 8);
            Button uninstall = Ui.button(this, "Uninstall", false);
            uninstall.setOnClickListener(v -> uninstall());
            content.addView(uninstall, fullWidth());

            keepAction();
        } else {
            Button done = Ui.button(this, "Done", true);
            done.setOnClickListener(v -> finish());
            content.addView(done, fullWidth());

            if (findings > 0) {
                Ui.addSpace(content, 8);
                Button see = Ui.button(this, "See findings", false);
                see.setOnClickListener(v -> openFindings(null));
                content.addView(see, fullWidth());
            }
            Ui.addSpace(content, 8);
            Button again = Ui.button(this, "Scan again", false);
            again.setOnClickListener(v -> rescan());
            content.addView(again, fullWidth());
        }
    }

    private void keepAction() {
        Ui.addSpace(content, 12);
        TextView keep = Ui.text(this, "Keep app (not recommended)", 13, Ui.MUTED, true);
        keep.setGravity(Gravity.CENTER);
        keep.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 10));
        keep.setOnClickListener(v -> confirmKeep());
        content.addView(keep);
    }

    private void confirmKeep() {
        new AlertDialog.Builder(this)
                .setTitle("Keep this app?")
                .setMessage("It shows behaviour commonly used to steal data. ANBU will keep this "
                        + "report on this device and stop treating this version as new.")
                .setPositiveButton("Keep app", (dialog, which) -> {
                    Toast.makeText(this,
                            "Report kept. ANBU will not re-prompt for this version.",
                            Toast.LENGTH_LONG).show();
                    finish();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void openFindings(String focus) {
        Intent intent = new Intent(this, DetailActivity.class);
        intent.putExtra(DetailActivity.EXTRA_REPORT, reportKey);
        intent.putExtra(DetailActivity.EXTRA_PACKAGE, packageName);
        if (focus != null) intent.putExtra(DetailActivity.EXTRA_FOCUS, focus);
        startActivity(intent);
    }

    private void rescan() {
        Intent intent = new Intent(this, ScanActivity.class);
        intent.putExtra(ScanActivity.EXTRA_PACKAGE, packageName);
        startActivity(intent);
        finish();
    }

    // --------------------------------------------------------------- uninstall

    private void uninstall() {
        if (packageName == null || packageName.isEmpty()) {
            Toast.makeText(this, "This app is no longer installed", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!installed()) {
            showAfterUninstall();
            return;
        }
        if (isDeviceAdmin()) {
            new AlertDialog.Builder(this)
                    .setTitle("This app has device administrator access")
                    .setMessage("Android will not uninstall it until you turn that off. "
                            + "Open Settings \u2192 Security \u2192 Device admin apps, turn it off, "
                            + "then try again.")
                    .setPositiveButton("Open settings", (dialog, which) -> {
                        try {
                            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
                        } catch (RuntimeException e) {
                            Toast.makeText(this, "Could not open Settings",
                                    Toast.LENGTH_SHORT).show();
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }
        try {
            Intent intent = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + packageName));
            startActivityForResult(intent, REQUEST_DELETE);
        } catch (RuntimeException e) {
            new AlertDialog.Builder(this)
                    .setTitle("Android could not uninstall this app")
                    .setMessage("No uninstall screen is available for this package. You can "
                            + "remove it from Android Settings \u2192 Apps.")
                    .setPositiveButton("Open app settings", (dialog, which) -> {
                        Intent settings = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:" + packageName));
                        try {
                            startActivity(settings);
                        } catch (RuntimeException ignored) {
                            Toast.makeText(this, "Could not open app settings",
                                    Toast.LENGTH_SHORT).show();
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        }
    }

    private boolean isDeviceAdmin() {
        DevicePolicyManager dpm = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
        if (dpm == null) return false;
        List<ComponentName> admins = dpm.getActiveAdmins();
        if (admins == null) return false;
        for (ComponentName admin : admins) {
            if (packageName.equals(admin.getPackageName())) return true;
        }
        return false;
    }

    private boolean installed() {
        try {
            getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != REQUEST_DELETE) return;
        if (!installed()) {
            showAfterUninstall();
        } else {
            Toast.makeText(this, "Uninstall cancelled", Toast.LENGTH_SHORT).show();
        }
    }

    private void showAfterUninstall() {
        // Hide the whole scroller, not just its child, so the report does not leave an
        // empty weighted gap above the post-uninstall card.
        reportScroll.setVisibility(View.GONE);
        postUninstall.removeAllViews();
        postUninstall.setVisibility(View.VISIBLE);
        barTitle.setText("Uninstalled");

        LinearLayout card = Ui.card(this);
        String label = report != null && report.app.label != null && !report.app.label.isEmpty()
                ? report.app.label : packageName;
        card.addView(Ui.text(this, "\u2713  Uninstalled", 13, Ui.OK, true));
        TextView headline = Ui.text(this, label + " was removed from this device.", 20,
                Ui.TEXT, true);
        headline.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 6));
        card.addView(headline);
        card.addView(Ui.text(this,
                "The report stays on screen so you can still read what was found. "
                        + "The app is no longer installed.",
                12, Ui.MUTED, false));

        Ui.addSpace(card, 16);
        Button view = Ui.button(this, "View report", true);
        view.setOnClickListener(v -> {
            reportScroll.setVisibility(View.VISIBLE);
            postUninstall.setVisibility(View.GONE);
            barTitle.setText("Result");
            if (report != null) showReport();
        });
        card.addView(view, fullWidth());

        Ui.addSpace(card, 8);
        Button done = Ui.button(this, "Done", false);
        done.setOnClickListener(v -> finish());
        card.addView(done, fullWidth());

        postUninstall.addView(card);
    }

    // ----------------------------------------------------------------- missing

    private void showMissing() {
        content.removeAllViews();
        barTitle.setText("Result");

        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, "Report unavailable", 19, Ui.TEXT, true));
        card.addView(Ui.text(this,
                "Reports are kept in memory and Android cleared this one when it stopped ANBU. "
                        + "The app was not judged. Scan it again for a fresh result.",
                12, Ui.MUTED, false));
        if (packageName != null && !packageName.isEmpty()) {
            TextView pkg = Ui.text(this, packageName, 11, Ui.MUTED, false);
            pkg.setTypeface(Typeface.MONOSPACE);
            pkg.setPadding(0, Ui.dp(this, 10), 0, 0);
            card.addView(pkg);

            Ui.addSpace(card, 16);
            Button again = Ui.button(this, "Scan again", true);
            again.setOnClickListener(v -> rescan());
            card.addView(again, fullWidth());
        }
        content.addView(card);
    }

    // ------------------------------------------------------------------ helpers

    private List<Model.Finding> sortedFindings() {
        List<Model.Finding> sorted = new ArrayList<>(report.findings);
        Collections.sort(sorted, Comparator.comparingInt(
                (Model.Finding f) -> severityRank(f.severity)));
        return sorted;
    }

    static int severityRank(String severity) {
        if ("critical".equals(severity)) return 0;
        if ("high".equals(severity)) return 1;
        if ("medium".equals(severity)) return 2;
        return 3;
    }

    private String summary() {
        if (!report.findings.isEmpty()) return sortedFindings().get(0).title;
        for (String note : report.score.notes) {
            if (note.startsWith("No known")) return note;
        }
        return "Nothing matched the detections that ran on this device.";
    }

    private String limitedHeadline() {
        if (report.detailsOnly) return "Android did not allow ANBU to read this app's code.";
        return "Most of this app's code could not be read.";
    }

    private String limitedBody() {
        if (report.detailsOnly) {
            return "Only the app's details, permissions and signing certificate were checked. "
                    + "That is not enough to judge what the app does, so this is not a clean result.";
        }
        return "The app appears to be packed or protected, so string inspection found little. "
                + "A low partial score is not evidence of safety; treat this app as unexamined.";
    }

    private TextView chip(String label, int color) {
        TextView chip = Ui.chip(this, label, color);
        chip.setTextSize(10);
        return chip;
    }

    private void addChipGap(LinearLayout row) {
        View gap = new View(this);
        row.addView(gap, new LinearLayout.LayoutParams(Ui.dp(this, 6), 1));
    }

    private LinearLayout.LayoutParams fullWidth() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }
}
