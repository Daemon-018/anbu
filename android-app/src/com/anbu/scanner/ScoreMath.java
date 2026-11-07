package com.anbu.scanner;

/**
 * Pure-Java port of {@code src/anbu/score.py}.
 *
 * <p>Deliberately free of Android imports so the parity test in
 * {@code android-app/test/ScoreMathTest.java} can compile it with a plain JDK.
 * The desktop CLI and the on-device scanner must return the same number and
 * band for the same findings; anything changed here has to change in the
 * Python module (and the test vectors) at the same time.</p>
 */
public final class ScoreMath {

    public static final int COMBO_BONUS = 12;
    public static final int MAX_COMBOS_SCORED = 3;
    public static final int LLM_ADJUST_MIN = -8;
    public static final int LLM_ADJUST_MAX = 12;
    public static final double INCONCLUSIVE_COVERAGE = 0.35;

    /** (upper bound inclusive, band), in the same order as score.py. */
    private static final int[] BAND_CEILINGS = {19, 44, 69, 84, 100};
    private static final String[] BAND_NAMES = {
            "likely_benign", "low", "suspicious", "high", "critical"
    };

    private ScoreMath() {
    }

    /** Points for a severity, or 0 for an unknown one, like SEVERITY_POINTS.get(..., 0). */
    public static int points(String severity) {
        if ("critical".equals(severity)) return 30;
        if ("high".equals(severity)) return 15;
        if ("medium".equals(severity)) return 6;
        if ("low".equals(severity)) return 2;
        return 0;
    }

    /** Map additive points to 0..100 with diminishing returns. */
    public static double saturate(int basePoints) {
        return 100 * (1 - Math.exp(-basePoints / 45.0));
    }

    public static String bandFor(int value) {
        for (int i = 0; i < BAND_CEILINGS.length; i++) {
            if (value <= BAND_CEILINGS[i]) return BAND_NAMES[i];
        }
        return "critical";
    }

    public static double clamp(double value, double low, double high) {
        return Math.max(low, Math.min(high, value));
    }

    public static int comboBonus(int comboCount) {
        return COMBO_BONUS * Math.min(comboCount, MAX_COMBOS_SCORED);
    }

    /**
     * Final 0..100 score.
     *
     * <p>Python's {@code round()} is half-to-even, while {@link Math#round}
     * is half-up. Use {@link Math#rint} so a value landing exactly on .5 rounds
     * the same way in both implementations.</p>
     */
    public static int value(int basePoints, int comboCount, int llmAdjust) {
        double saturated = saturate(basePoints);
        int bonus = comboBonus(comboCount);
        int adjust = (int) clamp(llmAdjust, LLM_ADJUST_MIN, LLM_ADJUST_MAX);
        return roundScore(clamp(saturated + bonus + adjust, 0, 100));
    }

    /** Python's {@code round()} semantics: ties go to the nearest even integer. */
    public static int roundScore(double value) {
        return (int) Math.rint(value);
    }

    public static boolean inconclusive(boolean hasPackerHints, double coverage) {
        return hasPackerHints || coverage < INCONCLUSIVE_COVERAGE;
    }

    /** Mirrors score._confidence with coverage/evidence counts passed explicitly. */
    public static String confidence(
            double coverage, int findingCount, int withEvidence, boolean inconclusive) {
        if (inconclusive) return "low";
        if (findingCount == 0) return coverage >= 0.9 ? "high" : "medium";
        double ratio = (double) withEvidence / findingCount;
        if (coverage >= 0.9 && ratio >= 0.75) return "high";
        return "medium";
    }
}
