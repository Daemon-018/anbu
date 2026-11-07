package com.anbu.scanner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Plain-JDK parity test for {@link ScoreMath} against vectors produced by the
 * real {@code src/anbu/score.py} (see {@code generate_vectors.py}).
 *
 * <p>No Android SDK or JUnit needed. Run {@code android-app/test/run.sh}.</p>
 */
public final class ScoreMathTest {

    private static int checks;
    private static int failures;

    public static void main(String[] args) throws IOException {
        Path dir = Paths.get(args.length > 0 ? args[0] : "test");

        points();
        rounding();
        bands(rows(dir.resolve("band-vectors.tsv")));
        scores(rows(dir.resolve("score-vectors.tsv")));
        confidence(rows(dir.resolve("confidence-vectors.tsv")));
        inconclusive(rows(dir.resolve("inconclusive-vectors.tsv")));

        System.out.println();
        if (failures == 0) {
            System.out.println("PASS " + checks + " checks against src/anbu/score.py vectors");
            return;
        }
        System.out.println("FAIL " + failures + " of " + checks + " checks");
        System.exit(1);
    }

    private static void points() {
        expect("points(critical)", 30, ScoreMath.points("critical"));
        expect("points(high)", 15, ScoreMath.points("high"));
        expect("points(medium)", 6, ScoreMath.points("medium"));
        expect("points(low)", 2, ScoreMath.points("low"));
        expect("points(unknown)", 0, ScoreMath.points("bogus"));
        expect("points(null)", 0, ScoreMath.points(null));
    }

    /** Python round() is half-to-even; Math.round() would be half-up. */
    private static void rounding() {
        expect("roundScore(0.5)", 0, ScoreMath.roundScore(0.5));
        expect("roundScore(1.5)", 2, ScoreMath.roundScore(1.5));
        expect("roundScore(2.5)", 2, ScoreMath.roundScore(2.5));
        expect("roundScore(3.5)", 4, ScoreMath.roundScore(3.5));
        expect("roundScore(42.4)", 42, ScoreMath.roundScore(42.4));
        expect("roundScore(42.6)", 43, ScoreMath.roundScore(42.6));
    }

    private static void bands(List<String[]> rows) {
        for (String[] row : rows) {
            int value = Integer.parseInt(row[0]);
            expect("bandFor(" + value + ")", row[1], ScoreMath.bandFor(value));
        }
    }

    private static void scores(List<String[]> rows) {
        for (String[] row : rows) {
            String severities = row[0];
            int combos = Integer.parseInt(row[1]);
            int adjust = Integer.parseInt(row[2]);
            int expectedBase = Integer.parseInt(row[3]);
            double expectedSaturated = Double.parseDouble(row[4]);
            int expectedBonus = Integer.parseInt(row[5]);
            int expectedValue = Integer.parseInt(row[6]);
            String expectedBand = row[7];

            int base = 0;
            if (!"-".equals(severities)) {
                for (String severity : severities.split(",")) {
                    base += ScoreMath.points(severity);
                }
            }

            String label = severities + "/combos=" + combos + "/adjust=" + adjust;
            expect(label + " base", expectedBase, base);
            expect(label + " saturated", expectedSaturated, ScoreMath.saturate(base));
            expect(label + " bonus", expectedBonus, ScoreMath.comboBonus(combos));
            expect(label + " value", expectedValue, ScoreMath.value(base, combos, adjust));
            expect(label + " band", expectedBand, ScoreMath.bandFor(expectedValue));
        }
    }

    private static void confidence(List<String[]> rows) {
        for (String[] row : rows) {
            double coverage = Double.parseDouble(row[0]);
            int findings = Integer.parseInt(row[1]);
            int evidence = Integer.parseInt(row[2]);
            boolean inconclusive = Boolean.parseBoolean(row[3]);
            String expected = row[4];
            expect(
                    "confidence(" + row[0] + "," + findings + "," + evidence + ","
                            + inconclusive + ")",
                    expected,
                    ScoreMath.confidence(coverage, findings, evidence, inconclusive));
        }
    }

    private static void inconclusive(List<String[]> rows) {
        for (String[] row : rows) {
            boolean packers = Boolean.parseBoolean(row[0]);
            double coverage = Double.parseDouble(row[1]);
            boolean expected = Boolean.parseBoolean(row[2]);
            expect(
                    "inconclusive(" + packers + "," + row[1] + ")",
                    expected,
                    ScoreMath.inconclusive(packers, coverage));
        }
    }

    // ------------------------------------------------------------------ helpers

    private static List<String[]> rows(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        if (lines.isEmpty()) {
            throw new IOException("empty vector file: " + path);
        }
        List<String[]> rows = new java.util.ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isEmpty()) continue;
            rows.add(line.split("\t", -1));
        }
        return rows;
    }

    private static void expect(String label, Object expected, Object actual) {
        checks++;
        if (!expected.equals(actual)) {
            failures++;
            if (failures <= 20) {
                System.out.println("FAIL " + label + ": expected " + expected + ", got " + actual);
            }
        }
    }

    private static void expect(String label, double expected, double actual) {
        checks++;
        if (Math.abs(expected - actual) > 1e-9) {
            failures++;
            if (failures <= 20) {
                System.out.println("FAIL " + label + ": expected " + expected + ", got " + actual);
            }
        }
    }

    private ScoreMathTest() {
    }
}
