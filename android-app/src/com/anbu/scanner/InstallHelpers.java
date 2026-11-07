package com.anbu.scanner;

import android.net.Uri;
import android.view.View;
import android.widget.TextView;

/**
 * Flattened helpers to bypass D8 8.2.2-dev anonymous class crash.
 */
public final class InstallHelpers {

    public static class ScanWorker implements Runnable {
        private final InstallActivity activity;
        private final Uri uri;

        public ScanWorker(InstallActivity activity, Uri uri) {
            this.activity = activity;
            this.uri = uri;
        }

        @Override
        public void run() {
            activity.runOnUiThread(new UiUpdate(activity, 0));

            InstallSet.Result res = InstallSet.prepare(activity, uri);
            if (res.error != null) {
                activity.runOnUiThread(new UiUpdate(activity, 1, res.error));
                return;
            }

            final ScanProgressListener progress = new ScanProgressListener(activity);
            Model.Report rep = ScanEngine.scanFiles(activity, res.apks, res.primary, progress);

            activity.runOnUiThread(new UiUpdate(activity, 2, res, rep));
        }
    }

    public static class UiUpdate implements Runnable {
        private final InstallActivity activity;
        private final int type;
        private final Object data1;
        private final Object data2;

        public UiUpdate(InstallActivity activity, int type) {
            this(activity, type, null, null);
        }

        public UiUpdate(InstallActivity activity, int type, Object d1) {
            this(activity, type, d1, null);
        }

        public UiUpdate(InstallActivity activity, int type, Object d1, Object d2) {
            this.activity = activity;
            this.type = type;
            this.data1 = d1;
            this.data2 = d2;
        }

        @Override
        public void run() {
            switch (type) {
                case 0: activity.animateShatter(); break;
                case 1: 
                    activity.showError((String) data1);
                    activity.finish(); 
                    break;
                case 2:
                    activity.set = (InstallSet.Result) data1;
                    activity.report = (Model.Report) data2;
                    activity.renderDecision();
                    break;
            }
        }
    }

    public static class ScanProgressListener implements ScanEngine.Progress {
        private final InstallActivity activity;

        public ScanProgressListener(InstallActivity activity) {
            this.activity = activity;
        }

        @Override
        public void step(String stage, String detail) {
            activity.runOnUiThread(new ProgressUiUpdate(activity, stage, detail));
        }
    }

    public static class ProgressUiUpdate implements Runnable {
        private final InstallActivity activity;
        private final String stage;
        private final String detail;

        public ProgressUiUpdate(InstallActivity activity, String stage, String detail) {
            this.activity = activity;
            this.stage = stage;
            this.detail = detail;
        }

        @Override
        public void run() {
            if (activity.loadingText != null) {
                activity.loadingText.setText(stage + "\n" + detail);
            }
            activity.animatePulse();
        }
    }
}
