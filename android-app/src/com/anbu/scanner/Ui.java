package com.anbu.scanner;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Polished UI kit for ANBU.
 * Supports Light and Dark modes with an energetic, modern security aesthetic.
 */
public final class Ui {

    public static final int MODE_LIGHT = 0;
    public static final int MODE_DARK = 1;
    public static int currentMode = MODE_DARK;

    // --- Dark Palette (Cyber-Pro) ---
    public static final int DARK_BG = 0xFF0B0E14;
    public static final int DARK_SURFACE = 0xFF151B24;
    public static final int DARK_SURFACE_2 = 0xFF1F2733;
    public static final int DARK_LINE = 0xFF2D3748;
    public static final int DARK_TEXT = 0xFFF8FAFC;
    public static final int DARK_MUTED = 0xFF94A3B8;
    public static final int DARK_ACCENT = 0xFF6366F1; // Electric Indigo

    // --- Light Palette (Clean-Modern) ---
    public static final int LIGHT_BG = 0xFFF8FAFC;
    public static final int LIGHT_SURFACE = 0xFFFFFFFF;
    public static final int LIGHT_SURFACE_2 = 0xFFF1F5F9;
    public static final int LIGHT_LINE = 0xFFE2E8F0;
    public static final int LIGHT_TEXT = 0xFF1E293B;
    public static final int LIGHT_MUTED = 0xFF64748B;
    public static final int LIGHT_ACCENT = 0xFF4F46E5; // Deep Indigo

    // --- Universal Status Colors ---
    public static final int COLOR_OK = 0xFF10B981;      // Mint Green
    public static final int COLOR_WARN = 0xFFF59E0B;    // Amber
    public static final int COLOR_CRIT = 0xFFEF4444;    // Vivid Red
    public static final int COLOR_INFO = 0xFF3B82F6;    // Bright Blue

    private Ui() {
    }

    public static int color(int dark, int light) {
        return currentMode == MODE_DARK ? dark : light;
    }

    public static int getBg() { return color(DARK_BG, LIGHT_BG); }
    public static int getSurface() { return color(DARK_SURFACE, LIGHT_SURFACE); }
    public static int getSurface2() { return color(DARK_SURFACE_2, LIGHT_SURFACE_2); }
    public static int getLine() { return color(DARK_LINE, LIGHT_LINE); }
    public static int getText() { return color(DARK_TEXT, LIGHT_TEXT); }
    public static int getMuted() { return color(DARK_MUTED, LIGHT_MUTED); }
    public static int getAccent() { return color(DARK_ACCENT, LIGHT_ACCENT); }

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
        layout.setBackground(background(context, getSurface(), 16, getLine()));
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
        if ("likely_benign".equals(band)) return "Clean";
        if ("low".equals(band)) return "Low Risk";
        if ("suspicious".equals(band)) return "Suspicious";
        if ("high".equals(band)) return "High Risk";
        return "Critical";
    }

    public static int bandColor(String band) {
        if ("likely_benign".equals(band)) return COLOR_OK;
        if ("low".equals(band)) return COLOR_INFO;
        if ("suspicious".equals(band)) return COLOR_WARN;
        if ("high".equals(band)) return 0xFFF97316; // Orange
        return COLOR_CRIT;
    }

    public static int severityColor(String severity) {
        if ("critical".equals(severity)) return COLOR_CRIT;
        if ("high".equals(severity)) return 0xFFF97316;
        if ("medium".equals(severity)) return COLOR_WARN;
        return COLOR_INFO;
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
        button.setTextColor(primary ? 0xFFFFFFFF : getText());
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setBackground(background(context, primary ? getAccent() : getSurface2(), 12,
                primary ? 0 : getLine()));
        int h = dp(context, 20);
        button.setPadding(dp(context, 18), h, dp(context, 18), h);
        button.setMinHeight(dp(context, 48));
        return button;
    }

    public static TextView chip(Context context, String label, int color) {
        TextView chip = text(context, label, 11, color, true);
        chip.setBackground(background(context, getSurface2(), 8, getLine()));
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

    /**
     * Smoothly animates a view sliding up and fading in.
     */
    public static void slideUp(View view) {
        view.setTranslationY(100f);
        view.setAlpha(0f);
        view.animate()
            .translationY(0f)
            .alpha(1f)
            .setDuration(400)
            .setInterpolator(new AccelerateDecelerateInterpolator())
            .start();
    }
}
