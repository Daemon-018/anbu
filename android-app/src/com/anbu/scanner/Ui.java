package com.anbu.scanner;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Small helpers so the screens can be built without layout XML. */
public final class Ui {

    public static final int BG = 0xFF0E1116;
    public static final int SURFACE = 0xFF161B22;
    public static final int SURFACE_2 = 0xFF1C2430;
    public static final int LINE = 0xFF2A3441;
    public static final int TEXT = 0xFFE6EDF3;
    public static final int MUTED = 0xFF8B949E;
    public static final int ACCENT = 0xFFE8533F;
    public static final int OK = 0xFF3FB950;

    private Ui() {
    }

    public static int dp(Context context, float value) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value,
                context.getResources().getDisplayMetrics());
    }

    public static TextView text(Context context, String value, float sp, int color, boolean bold) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setLineSpacing(dp(context, 2), 1f);
        return view;
    }

    public static LinearLayout column(Context context) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    public static LinearLayout row(Context context) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        layout.setGravity(Gravity.CENTER_VERTICAL);
        return layout;
    }

    public static GradientDrawable background(Context context, int color, float radiusDp, int strokeColor) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(context, radiusDp));
        if (strokeColor != 0) {
            drawable.setStroke(dp(context, 1), strokeColor);
        }
        return drawable;
    }

    public static LinearLayout card(Context context) {
        LinearLayout layout = column(context);
        layout.setBackground(background(context, SURFACE, 14, LINE));
        int p = dp(context, 16);
        layout.setPadding(p, p, p, p);
        return layout;
    }

    public static void margins(View view, int left, int top, int right, int bottom) {
        if (!(view.getLayoutParams() instanceof ViewGroup.MarginLayoutParams)) return;
        ViewGroup.MarginLayoutParams params = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
        params.setMargins(dp(view.getContext(), left), dp(view.getContext(), top),
                dp(view.getContext(), right), dp(view.getContext(), bottom));
        view.setLayoutParams(params);
    }

    public static String bandLabel(String band) {
        if ("likely_benign".equals(band)) return "No known signals";
        if ("low".equals(band)) return "Low risk";
        if ("suspicious".equals(band)) return "Suspicious";
        if ("high".equals(band)) return "High risk";
        return "Critical";
    }

    public static int bandColor(String band) {
        if ("likely_benign".equals(band)) return OK;
        if ("low".equals(band)) return 0xFF58A6FF;
        if ("suspicious".equals(band)) return 0xFFD29922;
        if ("high".equals(band)) return 0xFFF0883E;
        return ACCENT;
    }

    public static int severityColor(String severity) {
        if ("critical".equals(severity)) return ACCENT;
        if ("high".equals(severity)) return 0xFFF0883E;
        if ("medium".equals(severity)) return 0xFFD29922;
        return 0xFF58A6FF;
    }

    public static String title(String category) {
        if (category == null || category.isEmpty()) return "Signal";
        String spaced = category.replace('_', ' ');
        return Character.toUpperCase(spaced.charAt(0)) + spaced.substring(1);
    }

    public static String percent(double value) {
        return Math.round(value * 100) + "%";
    }

    public static Button button(Context context, String label, boolean primary) {
        Button button = new Button(context);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextSize(15);
        button.setTextColor(primary ? 0xFFFFFFFF : TEXT);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setBackground(background(context, primary ? ACCENT : SURFACE_2, 12,
                primary ? 0 : LINE));
        int h = dp(context, 20);
        button.setPadding(dp(context, 18), h, dp(context, 18), h);
        button.setMinHeight(dp(context, 48));
        return button;
    }

    public static TextView chip(Context context, String label, int color) {
        TextView chip = text(context, label, 11, color, true);
        chip.setBackground(background(context, SURFACE_2, 8, LINE));
        int h = dp(context, 5);
        int v = dp(context, 10);
        chip.setPadding(v, h, v, h);
        return chip;
    }

    public static ImageView image(Context context, Drawable drawable, int sizeDp) {
        ImageView view = new ImageView(context);
        view.setLayoutParams(new LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp)));
        if (drawable != null) view.setImageDrawable(drawable);
        return view;
    }

    public static LinearLayout.LayoutParams stack(Context context, int width, int height,
                                                  float left, float top, float right, float bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(width, height);
        params.setMargins(dp(context, left), dp(context, top), dp(context, right), dp(context, bottom));
        return params;
    }

    /** Width in pixels used to separate chips in a horizontal row. */
    public static int surfaceGap(Context context) {
        return dp(context, 6);
    }

    public static void addSpace(LinearLayout parent, float heightDp) {
        View space = new View(parent.getContext());
        space.setLayoutParams(new LinearLayout.LayoutParams(1, dp(parent.getContext(), heightDp)));
        parent.addView(space);
    }

    public static int parseColor(String value, int fallback) {
        try {
            return android.graphics.Color.parseColor(value);
        } catch (RuntimeException e) {
            return fallback;
        }
    }
}
