package com.anbu.scanner;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Runs one scan, or a queued batch, in the app process. The report is stored in
 * {@link Model.Store} and handed to the result screens by key.
 */
public final class ScanActivity extends Activity {

    public static final String EXTRA_PACKAGE = "com.anbu.scanner.PACKAGE";
    public static final String EXTRA_PACKAGES = "com.anbu.scanner.PACKAGES";

    private static final String STATE_RUNNING = "running";
    private static final String STATE_PACKAGES = "packages";

    private final List<String> queue = new ArrayList<>();
    private final List<String> reportKeys = new ArrayList<>();

    private LinearLayout progressCard;
    private LinearLayout interruptedCard;
    private LinearLayout stageBox;
    private TextView headline;
    private TextView subline;
    private TextView counter;
    private TextView stageText;
    private ProgressBar bar;
    private Button cancelButton;

    private volatile boolean cancelled;
    private boolean running;
    private boolean finished;
    private int index;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        String[] batch = getIntent().getStringArrayExtra(EXTRA_PACKAGES);
        if (batch != null) {
            queue.addAll(Arrays.asList(batch));
        } else {
            String single = getIntent().getStringExtra(EXTRA_PACKAGE);
            if (single != null) queue.add(single);
        }

        setContentView(build());

        if (state != null && state.getBoolean(STATE_RUNNING, false)) {
            String[] saved = state.getStringArray(STATE_PACKAGES);
            if (saved != null && saved.length > 0) {
                queue.clear();
                queue.addAll(Arrays.asList(saved));
            }
            showInterrupted();
            return;
        }

        if (queue.isEmpty()) {
            Toast.makeText(this, "No app selected", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        startScan();
    }

    private View build() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.getBg());
        root.setFitsSystemWindows(true);

        LinearLayout top = Ui.row(this);
        top.setPadding(Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 18), Ui.dp(this, 4));
        TextView back = Ui.text(this, "\u2039 Back", 14, Ui.getMuted(), true);
        back.setPadding(Ui.dp(this, 6), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        back.setOnClickListener(v -> cancelAndLeave());
        top.addView(back);
        top.addView(Ui.text(this, "Scan", 18, Ui.getText(), true),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(top);

        LinearLayout body = Ui.column(this);
        int p = Ui.dp(this, 18);
        body.setPadding(p, Ui.dp(this, 6), p, p);

        progressCard = Ui.card(this);
        headline = Ui.text(this, "Preparing scan", 19, Ui.getText(), true);
        subline = Ui.text(this, "Reading what Android exposes for this app.", 12, Ui.getMuted(), false);
        subline.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 14));
        progressCard.addView(headline);
        progressCard.addView(subline);

        counter = Ui.text(this, "", 12, Ui.getMuted(), false);
        counter.setPadding(0, 0, 0, Ui.dp(this, 8));
        progressCard.addView(counter);

        bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setIndeterminate(true);
        bar.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(Ui.getAccent()));
        progressCard.addView(bar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 4)));

        stageText = Ui.text(this, "Starting\u2026", 14, Ui.getText(), true);
        stageText.setPadding(0, Ui.dp(this, 14), 0, Ui.dp(this, 6));
        progressCard.addView(stageText);

        stageBox = Ui.column(this);
        progressCard.addView(stageBox);

        Ui.addSpace(progressCard, 16);
        cancelButton = Ui.button(this, "Cancel", false);
        cancelButton.setOnClickListener(v -> cancelScan());
        progressCard.addView(cancelButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Ui.addSpace(progressCard, 12);
        progressCard.addView(Ui.text(this,
                "A scan reads names and strings; it cannot see what an app does at runtime.",
                11, Ui.getMuted(), false));
        body.addView(progressCard);

        interruptedCard = Ui.card(this);
        interruptedCard.setVisibility(View.GONE);
        interruptedCard.addView(Ui.text(this, "Scan interrupted", 19, Ui.getText(), true));
        interruptedCard.addView(Ui.text(this,
                "Android stopped ANBU before the report was finished. Nothing was kept, so "
                        + "the app has not been half-judged. Run the scan again to get a result.",
                12, Ui.getMuted(), false));
        Ui.addSpace(interruptedCard, 16);
        Button again = Ui.button(this, "Scan again", true);
        again.setOnClickListener(v -> restart());
        interruptedCard.addView(again, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        body.addView(interruptedCard);

        root.addView(body);
        return root;
    }

    private void startScan() {
        running = true;
        finished = false;
        cancelled = false;
        index = 0;
        reportKeys.clear();
        progressCard.setVisibility(View.VISIBLE);
        interruptedCard.setVisibility(View.GONE);
        cancelButton.setEnabled(true);
        cancelButton.setText("Cancel");
        counter.setText(queue.size() > 1 ? "Scanning 1 of " + queue.size() : "");
        addStage("Reading manifest");
        addStage("Inspecting code");
        addStage("Applying rules");
        addStage("Preparing report");

        new Thread(() -> {
            for (int i = 0; i < queue.size(); i++) {
                if (cancelled) break;
                index = i;
                final int position = i;
                final String packageName = queue.get(i);
                final Model.AppEntry entry = ScanEngine.entryFor(getApplicationContext(), packageName);

                post(() -> updateRunning(entry, position));
                Model.Report report = ScanEngine.scan(getApplicationContext(), entry, (label, detail) ->
                        post(() -> updateStage(label, detail, position, entry)));
                if (cancelled) break;
                reportKeys.add(Model.Store.put(report));
            }
            post(this::complete);
        }, "anbu-scan").start();
    }

    private void updateRunning(Model.AppEntry entry, int position) {
        if (isGone()) return;
        headline.setText("Scanning " + safeLabel(entry));
        subline.setText(entry.packageName + (entry.versionName == null || entry.versionName.isEmpty()
                ? "" : "  \u00B7  v" + entry.versionName));
        if (queue.size() > 1) counter.setText("Scanning " + (position + 1) + " of " + queue.size());
        stageBox.removeAllViews();
        addStage("Reading manifest");
        addStage("Inspecting code");
        addStage("Applying rules");
        addStage("Preparing report");
    }

    private void updateStage(String label, String detail, int position, Model.AppEntry entry) {
        if (isGone()) return;
        stageText.setText(label);
        if (detail != null && !detail.isEmpty()) subline.setText(detail);
        markStages(label);
        if (queue.size() > 1) counter.setText("Scanning " + (position + 1) + " of " + queue.size());
    }

    private void addStage(String label) {
        TextView row = Ui.text(this, "\u25CB  " + label, 13, Ui.getMuted(), false);
        row.setTag(label);
        row.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        stageBox.addView(row);
    }

    private void markStages(String current) {
        for (int i = 0; i < stageBox.getChildCount(); i++) {
            TextView row = (TextView) stageBox.getChildAt(i);
            String label = String.valueOf(row.getTag());
            if (label.equals(current)) {
                row.setText("\u25CF  " + label);
                row.setTextColor(Ui.getText());
            } else if (isBefore(label, current)) {
                row.setText("\u2713  " + label);
                row.setTextColor(Ui.COLOR_OK);
            } else {
                row.setText("\u25CB  " + label);
                row.setTextColor(Ui.getMuted());
            }
        }
    }

    private boolean isBefore(String label, String current) {
        String[] order = {"Reading manifest", "Inspecting code", "Applying rules", "Preparing report"};
        int a = Arrays.asList(order).indexOf(label);
        int b = Arrays.asList(order).indexOf(current);
        return a >= 0 && b >= 0 && a < b;
    }

    private void complete() {
        if (finished) return;
        finished = true;
        running = false;

        if (cancelled) {
            if (!isGone()) Toast.makeText(this, "Scan cancelled", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        if (isGone()) return;

        if (reportKeys.isEmpty()) {
            Toast.makeText(this, "The scan did not produce a report", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        if (reportKeys.size() == 1) {
            Intent intent = new Intent(this, ResultActivity.class);
            intent.putExtra(ResultActivity.EXTRA_REPORT, reportKeys.get(0));
            intent.putExtra(ResultActivity.EXTRA_PACKAGE, queue.get(0));
            startActivity(intent);
        } else {
            String key = Model.Store.putList(reportKeys);
            Intent intent = new Intent(this, AllResultsActivity.class);
            intent.putExtra(AllResultsActivity.EXTRA_LIST, key);
            startActivity(intent);
        }
        finish();
    }

    private void cancelScan() {
        if (!running) {
            finish();
            return;
        }
        cancelled = true;
        cancelButton.setEnabled(false);
        cancelButton.setText("Cancelling\u2026");
        stageText.setText("Stopping after the current file");
        bar.setIndeterminate(true);
    }

    private void cancelAndLeave() {
        cancelled = true;
        finish();
    }

    private void showInterrupted() {
        running = false;
        progressCard.setVisibility(View.GONE);
        interruptedCard.setVisibility(View.VISIBLE);
    }

    private void restart() {
        startScan();
    }

    private void post(Runnable action) {
        runOnUiThread(() -> {
            if (isGone()) return;
            action.run();
        });
    }

    private boolean isGone() {
        return isFinishing() || isDestroyed();
    }

    private String safeLabel(Model.AppEntry entry) {
        if (entry.label != null && !entry.label.isEmpty()) return entry.label;
        return entry.packageName;
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        out.putBoolean(STATE_RUNNING, running);
        out.putStringArray(STATE_PACKAGES, queue.toArray(new String[0]));
    }

    @Override
    protected void onDestroy() {
        cancelled = true;
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        cancelAndLeave();
    }
}
