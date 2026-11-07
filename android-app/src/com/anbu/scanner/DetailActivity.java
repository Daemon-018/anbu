package com.anbu.scanner;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Every finding for one app, with its evidence, on a single screen scrolled in severity
 * order. Tapping a finding on the result screen passes its id so it is shown first.
 */
public final class DetailActivity extends Activity {

    public static final String EXTRA_REPORT = "com.anbu.scanner.REPORT";
    public static final String EXTRA_PACKAGE = "com.anbu.scanner.PACKAGE";
    public static final String EXTRA_FOCUS = "com.anbu.scanner.FOCUS";

    private String reportKey;
    private String packageName;
    private String focus;
    private Model.Report report;
    private LinearLayout content;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        reportKey = getIntent().getStringExtra(EXTRA_REPORT);
        packageName = getIntent().getStringExtra(EXTRA_PACKAGE);
        focus = getIntent().getStringExtra(EXTRA_FOCUS);
        report = reportKey == null ? null : Model.Store.get(reportKey);
        if (report != null) packageName = report.app.packageName;

        setContentView(build());

        if (report == null) {
            showMissing();
        } else {
            showFindings();
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
        top.addView(Ui.text(this, "Findings", 18, Ui.TEXT, true),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(top);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        content = Ui.column(this);
        int p = Ui.dp(this, 18);
        content.setPadding(p, Ui.dp(this, 4), p, Ui.dp(this, 28));
        scroll.addView(content, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private void showFindings() {
        content.removeAllViews();
        content.addView(headerCard());

        List<Model.Finding> findings = orderedFindings();
        if (findings.isEmpty()) {
            Ui.addSpace(content, 12);
            content.addView(emptyCard());
        } else {
            for (Model.Finding finding : findings) {
                Ui.addSpace(content, 12);
                content.addView(findingCard(finding, finding.id.equals(focus)));
            }
        }

        Ui.addSpace(content, 14);
        content.addView(Ui.text(this,
                "Static observation, not runtime proof. Evidence quotes come from the installed "
                        + "APK's manifest, certificate or readable code; nothing here was executed.",
                11, Ui.MUTED, false));
    }

    private View headerCard() {
        LinearLayout card = Ui.card(this);

        LinearLayout head = Ui.row(this);
        head.setGravity(Gravity.TOP);
        head.addView(Ui.image(this, report.app.icon, 44));

        LinearLayout texts = Ui.column(this);
        texts.setPadding(Ui.dp(this, 12), 0, 0, 0);
        String label = report.app.label == null || report.app.label.isEmpty()
                ? report.app.packageName : report.app.label;
        texts.addView(Ui.text(this, label, 17, Ui.TEXT, true));
        TextView pkg = Ui.text(this, report.app.packageName, 11, Ui.MUTED, false);
        pkg.setTypeface(Typeface.MONOSPACE);
        texts.addView(pkg);
        head.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(head);

        LinearLayout chips = Ui.row(this);
        chips.setPadding(0, Ui.dp(this, 12), 0, 0);
        chips.addView(Ui.chip(this, report.findings.size()
                        + (report.findings.size() == 1 ? " finding" : " findings"),
                report.findings.isEmpty() ? Ui.OK : Ui.TEXT));
        chipGap(chips);
        chips.addView(Ui.chip(this,
                Ui.percent(report.score.coverage) + " of code", Ui.MUTED));
        chipGap(chips);
        chips.addView(Ui.chip(this, report.detailsOnly ? "Details only" : "Full scan", Ui.MUTED));
        card.addView(chips);

        String limitation = report.detailsOnly
                ? "Android did not allow this app's code to be read, so these are manifest and "
                + "signature findings only."
                : "Sorted by severity. Nothing matched is not proof that the app is safe.";
        TextView note = Ui.text(this, limitation, 11, Ui.MUTED, false);
        note.setPadding(0, Ui.dp(this, 10), 0, 0);
        card.addView(note);
        return card;
    }

    private View emptyCard() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, "No findings", 18, Ui.TEXT, true));
        TextView body = Ui.text(this,
                "Permissions, components, signing certificate and "
                        + (report.detailsOnly ? "no" : Ui.percent(report.score.coverage) + " of")
                        + " code were checked. Nothing matched the detections that ran on this "
                        + "device. A scan cannot guarantee an app is safe.",
                12, Ui.MUTED, false);
        body.setPadding(0, Ui.dp(this, 8), 0, 0);
        card.addView(body);
        return card;
    }

    private View findingCard(Model.Finding finding, boolean focused) {
        LinearLayout card = Ui.card(this);
        if (focused) {
            card.setBackground(Ui.background(this, Ui.SURFACE, 14, Ui.ACCENT));
        }

        LinearLayout chips = Ui.row(this);
        chips.addView(Ui.chip(this, finding.severity.toUpperCase(),
                Ui.severityColor(finding.severity)));
        chipGap(chips);
        chips.addView(Ui.chip(this, Ui.title(finding.category), Ui.MUTED));
        if (focused) {
            chipGap(chips);
            chips.addView(Ui.chip(this, "Opened", Ui.ACCENT));
        }
        card.addView(chips);

        TextView title = Ui.text(this, finding.title, 17, Ui.TEXT, true);
        title.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 4));
        card.addView(title);

        TextView id = Ui.text(this, finding.id, 10, Ui.MUTED, false);
        id.setTypeface(Typeface.MONOSPACE);
        card.addView(id);

        card.addView(section("What we saw", finding.description));
        card.addView(section("Why it matters", finding.rationale));

        if (!finding.evidence.isEmpty()) {
            TextView heading = Ui.text(this, "Evidence", 12, Ui.TEXT, true);
            heading.setPadding(0, Ui.dp(this, 14), 0, Ui.dp(this, 2));
            card.addView(heading);
            for (Model.Evidence evidence : finding.evidence) {
                card.addView(evidenceBlock(evidence));
            }
        }

        if (!finding.mitre.isEmpty()) {
            TextView mitre = Ui.text(this, "MITRE ATT&CK Mobile: " + join(finding.mitre),
                    11, Ui.MUTED, false);
            mitre.setPadding(0, Ui.dp(this, 14), 0, 0);
            card.addView(mitre);
        }
        return card;
    }

    private View section(String heading, String body) {
        LinearLayout block = Ui.column(this);
        block.setPadding(0, Ui.dp(this, 12), 0, 0);
        block.addView(Ui.text(this, heading, 12, Ui.TEXT, true));
        TextView text = Ui.text(this,
                body == null || body.isEmpty() ? "No further detail recorded." : body,
                13, Ui.MUTED, false);
        text.setPadding(0, Ui.dp(this, 4), 0, 0);
        block.addView(text);
        return block;
    }

    private View evidenceBlock(final Model.Evidence evidence) {
        LinearLayout block = Ui.column(this);
        block.setBackground(Ui.background(this, Ui.SURFACE_2, 8, Ui.LINE));
        int p = Ui.dp(this, 10);
        block.setPadding(p, p, p, p);
        block.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        Ui.margins(block, 0, 10, 0, 0);

        TextView artifact = Ui.text(this, evidence.artifact, 10, Ui.MUTED, true);
        artifact.setTypeface(Typeface.MONOSPACE);
        block.addView(artifact);

        TextView quote = Ui.text(this, evidence.quote, 11, Ui.TEXT, false);
        quote.setTypeface(Typeface.MONOSPACE);
        quote.setTextIsSelectable(true);
        quote.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 8));
        block.addView(quote);

        TextView copy = Ui.text(this, "Copy evidence", 11, Ui.ACCENT, true);
        copy.setPadding(0, Ui.dp(this, 2), 0, Ui.dp(this, 2));
        copy.setOnClickListener(v -> copy(evidence));
        block.addView(copy);
        return block;
    }

    private void copy(Model.Evidence evidence) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "Clipboard unavailable", Toast.LENGTH_SHORT).show();
            return;
        }
        String value = evidence.artifact + "\n" + evidence.quote;
        clipboard.setPrimaryClip(ClipData.newPlainText("ANBU evidence", value));
        Toast.makeText(this, "Evidence copied", Toast.LENGTH_SHORT).show();
    }

    private void showMissing() {
        content.removeAllViews();
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, "Findings unavailable", 18, Ui.TEXT, true));
        card.addView(Ui.text(this,
                "Reports are kept in memory and Android cleared this one when it stopped ANBU. "
                        + "Run the scan again for a fresh result.",
                12, Ui.MUTED, false));
        if (packageName != null && !packageName.isEmpty()) {
            TextView pkg = Ui.text(this, packageName, 11, Ui.MUTED, false);
            pkg.setTypeface(Typeface.MONOSPACE);
            pkg.setPadding(0, Ui.dp(this, 10), 0, 0);
            card.addView(pkg);
        }
        content.addView(card);
    }

    private List<Model.Finding> orderedFindings() {
        List<Model.Finding> sorted = new ArrayList<>(report.findings);
        Collections.sort(sorted, Comparator.comparingInt(
                (Model.Finding f) -> ResultActivity.severityRank(f.severity)));
        if (focus != null) {
            for (int i = 0; i < sorted.size(); i++) {
                if (focus.equals(sorted.get(i).id)) {
                    Model.Finding picked = sorted.remove(i);
                    sorted.add(0, picked);
                    break;
                }
            }
        }
        return sorted;
    }

    private String join(List<String> values) {
        StringBuilder builder = new StringBuilder();
        for (String value : values) {
            if (builder.length() > 0) builder.append(", ");
            builder.append(value);
        }
        return builder.toString();
    }

    private void chipGap(LinearLayout row) {
        View gap = new View(this);
        row.addView(gap, new LinearLayout.LayoutParams(Ui.dp(this, 6), 1));
    }
}
