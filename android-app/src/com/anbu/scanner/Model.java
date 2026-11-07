package com.anbu.scanner;

import android.graphics.drawable.Drawable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/** Plain data objects shared between the scanner and the screens. */
public final class Model {

    private Model() {
    }

    public static final class AppEntry {
        public final String packageName;
        public String label;
        public String versionName;
        public Drawable icon;
        public boolean system;

        public AppEntry(String packageName) {
            this.packageName = packageName;
        }
    }

    public static final class Evidence {
        public final String artifact;
        public final String quote;

        public Evidence(String artifact, String quote) {
            this.artifact = artifact;
            this.quote = quote;
        }
    }

    public static final class Finding {
        public final String id;
        public final String title;
        public final String severity;
        public final String category;
        public final String description;
        public final String rationale;
        public final List<Evidence> evidence = new ArrayList<>();
        public final List<String> mitre = new ArrayList<>();

        public Finding(String id, String title, String severity, String category,
                       String description, String rationale) {
            this.id = id;
            this.title = title;
            this.severity = severity;
            this.category = category;
            this.description = description;
            this.rationale = rationale;
        }
    }

    public static final class Combo {
        public final String id;
        public final String title;
        public final String rationale;
        public final List<String> findingIds;

        public Combo(String id, String title, String rationale, List<String> findingIds) {
            this.id = id;
            this.title = title;
            this.rationale = rationale;
            this.findingIds = findingIds;
        }
    }

    public static final class Score {
        public int value;
        public String band = "likely_benign";
        public String confidence = "low";
        public double coverage;
        public boolean inconclusive;
        public int basePoints;
        public double saturated;
        public int comboBonus;
        public final List<String> notes = new ArrayList<>();
    }

    public static final class Report {
        public final AppEntry app;
        public final List<Finding> findings = new ArrayList<>();
        public final List<Combo> combos = new ArrayList<>();
        public final Score score = new Score();
        public long scannedAt;
        public boolean detailsOnly;

        public Report(AppEntry app) {
            this.app = app;
        }

        public boolean has(String findingId) {
            for (Finding f : findings) {
                if (f.id.equals(findingId)) return true;
            }
            return false;
        }
    }

    /**
     * Reports live in memory between activities. Everything is produced by a scan in this
     * process, so a static map avoids Parcelable plumbing across four screens.
     */
    public static final class Store {
        private static final HashMap<String, Report> REPORTS = new HashMap<>();
        private static final HashMap<String, List<String>> LISTS = new HashMap<>();

        private Store() {
        }

        public static synchronized String put(Report report) {
            String key = report.app.packageName + "#" + System.nanoTime();
            REPORTS.put(key, report);
            return key;
        }

        public static synchronized Report get(String key) {
            return REPORTS.get(key);
        }

        public static synchronized void putList(String key, List<String> reportKeys) {
            LISTS.put(key, reportKeys);
        }

        public static synchronized String putList(List<String> reportKeys) {
            String key = "list#" + System.nanoTime();
            LISTS.put(key, new ArrayList<>(reportKeys));
            return key;
        }

        public static synchronized List<String> getList(String key) {
            return LISTS.get(key);
        }
    }
}
