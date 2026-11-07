package com.anbu.scanner;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Batch inbox: one row per scanned app, highest score first. Tapping a row opens that
 * app's full report; nothing is re-scanned here.
 */
public final class AllResultsActivity extends Activity {

    public static final String EXTRA_LIST = "com.anbu.scanner.LIST";

    private static final class Row {
        final String reportKey;
        final Model.Report report;

        Row(String reportKey, Model.Report report) {
            this.reportKey = reportKey;
            this.report = report;
        }
    }

    private final List<Row> rows = new ArrayList<>();
    private int missing;
    private LinearLayout content;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        load();
        setContentView(build());
        show();
    }

    private void load() {
        String listKey = getIntent().getStringExtra(EXTRA_LIST);
        List<String> keys = listKey == null ? null : Model.Store.getList(listKey);
        if (keys == null) {
            missing = -1;
            return;
        }
        for (String key : keys) {
            Model.Report report = Model.Store.get(key);
            if (report == null) {
                missing++;
            } else {
                rows.add(new Row(key, report));
            }
        }
        Collections.sort(rows, (a, b) -> {
            int byScore = Integer.compare(b.report.score.value, a.report.score.value);
            if (byScore != 0) return byScore;
            return label(a.report).compareToIgnoreCase(label(b.report));
        });
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
        top.addView(Ui.text(this, "Scan results", 18, Ui.TEXT, true),
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

    private void show() {
        content.removeAllViews();
        if (missing == -1) {
            content.addView(unavailableCard());
            return;
        }
        if (rows.isEmpty()) {
            // An empty list with nothing missing is a batch that scanned no apps; it is not
            // the same as reports having been cleared from memory.
            content.addView(missing > 0 ? unavailableCard() : emptyCard());
            return;
        }

        content.addView(summaryCard());
        for (Row row : rows) {
            Ui.addSpace(content, 10);
            content.addView(rowView(row));
        }

        if (missing > 0) {
            Ui.addSpace(content, 12);
            TextView note = Ui.text(this, missing + (missing == 1
                            ? " report was" : " reports were")
                            + " cleared when Android stopped ANBU. Scan those apps again to "
                            + "restore them.", 11, Ui.MUTED, false);
            content.addView(note);
        }

        Ui.addSpace(content, 16);
        Button done = Ui.button(this, "Done", true);
        done.setOnClickListener(v -> finish());
        content.addView(done, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Ui.addSpace(content, 14);
        content.addView(Ui.text(this,
                "Static observation, not runtime proof. Rows are ordered by score, not by "
                        + "certainty; a low score is not a guarantee of safety.",
                11, Ui.MUTED, false));
    }

    private View summaryCard() {
        LinearLayout card = Ui.card(this);

        int critical = 0;
        int high = 0;
        int suspicious = 0;
        int low = 0;
        int benign = 0;
        int inconclusive = 0;
        for (Row row : rows) {
            String band = row.report.score.band;
            if ("critical".equals(band)) critical++;
            else if ("high".equals(band)) high++;
            else if ("suspicious".equals(band)) suspicious++;
            else if ("low".equals(band)) low++;
            else benign++;
            if (row.report.score.inconclusive || row.report.detailsOnly) inconclusive++;
        }

        card.addView(Ui.text(this, rows.size()
                        + (rows.size() == 1 ? " app scanned" : " apps scanned"),
                20, Ui.TEXT, true));
        TextView order = Ui.text(this, "Highest score first. Tap an app to read its findings.",
                12, Ui.MUTED, false);
        order.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 12));
        card.addView(order);

        LinearLayout chips = Ui.row(this);
        if (critical > 0) addBandChip(chips, critical + " critical", Ui.ACCENT, Ui.surfaceGap(this));
        if (high > 0) addBandChip(chips, high + " high", Ui.severityColor("high"), 0);
        if (suspicious > 0) addBandChip(chips, suspicious + " suspicious",
                Ui.severityColor("medium"), 0);
        if (low > 0) addBandChip(chips, low + " low", Ui.severityColor("low"), 0);
        if (benign > 0) addBandChip(chips, benign + " quiet", Ui.OK, 0);
        if (chips.getChildCount() > 0) card.addView(chips);

        if (inconclusive > 0) {
            TextView note = Ui.text(this, inconclusive + (inconclusive == 1
                            ? " app had" : " apps had")
                            + " limited inspection; those scores are low confidence.",
                    11, Ui.MUTED, false);
            note.setPadding(0, Ui.dp(this, 10), 0, 0);
            card.addView(note);
        }
        return card;
    }

    private void addBandChip(LinearLayout row, String label, int color, int leftGap) {
        if (leftGap > 0) {
            View gap = new View(this);
            row.addView(gap, new LinearLayout.LayoutParams(leftGap, 1));
        }
        row.addView(Ui.chip(this, label, color));
    }

    private View rowView(final Row row) {
        LinearLayout card = Ui.card(this);
        card.setPadding(Ui.dp(this, 14), Ui.dp(this, 12),
                Ui.dp(this, 14), Ui.dp(this, 12));

        LinearLayout line = Ui.row(this);
        line.setGravity(Gravity.TOP);
        line.addView(Ui.image(this, row.report.app.icon, 40));

        LinearLayout texts = Ui.column(this);
        texts.setPadding(Ui.dp(this, 12), 0, Ui.dp(this, 8), 0);
        texts.addView(Ui.text(this, label(row.report), 15, Ui.TEXT, true));
        TextView pkg = Ui.text(this, row.report.app.packageName, 10, Ui.MUTED, false);
        pkg.setTypeface(Typeface.MONOSPACE);
        texts.addView(pkg);

        String meta = row.report.findings.size()
                + (row.report.findings.size() == 1 ? " finding" : " findings");
        if (row.report.score.inconclusive || row.report.detailsOnly) {
            meta += " \u00B7 limited inspection";
        }
        TextView metaView = Ui.text(this, meta, 11, Ui.MUTED, false);
        metaView.setPadding(0, Ui.dp(this, 3), 0, 0);
        texts.addView(metaView);
        line.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout figure = Ui.column(this);
        figure.setGravity(Gravity.CENTER_HORIZONTAL);
        String value = row.report.score.inconclusive || row.report.detailsOnly
                ? "\u2014" : String.valueOf(row.report.score.value);
        TextView score = Ui.text(this, value, 24, Ui.bandColor(row.report.score.band), true);
        score.setGravity(Gravity.CENTER_HORIZONTAL);
        figure.addView(score);
        TextView band = Ui.text(this, Ui.bandLabel(row.report.score.band), 9,
                Ui.bandColor(row.report.score.band), true);
        band.setGravity(Gravity.CENTER_HORIZONTAL);
        figure.addView(band);
        line.addView(figure);

        card.addView(line);
        card.setOnClickListener(v -> open(row));
        return card;
    }

    private void open(Row row) {
        Intent intent = new Intent(this, ResultActivity.class);
        intent.putExtra(ResultActivity.EXTRA_REPORT, row.reportKey);
        intent.putExtra(ResultActivity.EXTRA_PACKAGE, row.report.app.packageName);
        startActivity(intent);
    }

    private View unavailableCard() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, "Results unavailable", 18, Ui.TEXT, true));
        card.addView(Ui.text(this,
                "Batch reports are kept in memory, and Android cleared them when it stopped "
                        + "ANBU. The apps were not judged by this screen. Scan them again for "
                        + "fresh results.",
                12, Ui.MUTED, false));

        Ui.addSpace(card, 16);
        Button done = Ui.button(this, "Done", true);
        done.setOnClickListener(v -> finish());
        card.addView(done, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return card;
    }

    private View emptyCard() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, "Nothing scanned", 18, Ui.TEXT, true));
        card.addView(Ui.text(this,
                "This batch finished without a report. Pick an app on the home screen and "
                        + "scan it again.",
                12, Ui.MUTED, false));

        Ui.addSpace(card, 16);
        Button done = Ui.button(this, "Done", true);
        done.setOnClickListener(v -> finish());
        card.addView(done, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return card;
    }

    private String label(Model.Report report) {
        if (report.app.label != null && !report.app.label.isEmpty()) return report.app.label;
        return report.app.packageName;
    }
}
