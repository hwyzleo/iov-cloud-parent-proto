import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * KEYPROV-LIFECYCLE-1 (KL1) lifecycle vector bundle check
 * (PAR-PROTO-DSN-CR-010 §8.6.3/§8.6.4/§8.6.5, PAR-PROTO-REQ-CR-010).
 *
 * <p>Consumes {@code verify/keyprov-lifecycle-kl1-v1/} — the frozen,
 * byte-identical CR-010 vector package (JSON SHA-256
 * 5226b92733a93634d9bdd11ec7090b1ba655979e3beca0399784e9db7de855e3) — and verifies:
 *
 * <ol>
 *   <li>bundle file integrity via {@code SHA256SUMS} (README.md /
 *       lifecycle-vectors.json / oracle.py / reference-report.json);</li>
 *   <li>the JSON hash equals the normative CR-010 value, case-set name is
 *       {@code keyprov-lifecycle-kl1-v1}, profile is KEYPROV-LIFECYCLE-1 and
 *       T0 = 1800000000000ms (never the execution machine's clock);</li>
 *   <li>profile parameters in the JSON equal the pinned Java reference-model
 *       constants (the semantic profile, not the unchanged descriptor, is what
 *       proves KL1 support);</li>
 *   <li>exactly 57 unique sub-cases covering scenario groups LC01..LC24
 *       (the earlier 48-sub-case preflight package is NOT a release input);</li>
 *   <li>every {@code input_hash} / {@code expected_hash} is recomputed with the
 *       canonical JSON convention (Python {@code json.dumps} compact, sorted
 *       keys, ensure_ascii=False) and matches the frozen value;</li>
 *   <li>the Java reference model ({@link KeyprovLifecycleDecide}) runs all 57
 *       sub-cases and matches the frozen expected outputs byte-for-byte —
 *       cross-language reference self-consistency with oracle.py;</li>
 *   <li>{@code reference-report.json} is a consistent 57/57 reference report
 *       marked REFERENCE_ORACLE_ONLY_NOT_PRODUCTION_CI.</li>
 * </ol>
 *
 * <p>Writes the CR-010 §8.6.4 CI reconciliation report
 * {@code verify/out/keyprov-lifecycle-ci-report.json} with the per-case schema
 * {@code {case_id, input_hash, expected_hash, actual_action, counters, pass}}
 * plus profile / parameters / vector hash, so the release gate can compare the
 * case-ID set, profile parameters, input/expected hashes and actual results
 * item-by-item against VEH-PROTO / TSP / SEC reports. Fail-fast: any violation
 * exits non-zero; the frozen expected values may never be hand-edited to mask a
 * difference.
 *
 * <p>Scope: reference-model self-consistency only — NOT production conformance.
 * Per CR-010 §8.6.4, production adapters must run the same inputs through their
 * real decision functions and real side-effect counters; they must NOT invoke
 * this oracle to fabricate an "actual" result, and a green check here never
 * proves VMD/TSP/SEC/mock/real-vehicle readiness.
 */
public final class KeyprovLifecycleVectorCheck {

  static final Path BUNDLE = Paths.get("verify/keyprov-lifecycle-kl1-v1");
  static final Path OUT = Paths.get("verify/out");
  static final Path REPORT = OUT.resolve("keyprov-lifecycle-ci-report.json");

  static final String CASE_SET = "keyprov-lifecycle-kl1-v1";
  static final String PROFILE = "KEYPROV-LIFECYCLE-1";
  static final long T0 = 1_800_000_000_000L;
  static final String VECTOR_JSON_SHA256 =
      "5226b92733a93634d9bdd11ec7090b1ba655979e3beca0399784e9db7de855e3";

  /** Normative reference oracle hash (oracle.py, frozen by SHA256SUMS). */
  static final String ORACLE_PY_SHA256 =
      "9e0b704065553695ab8e48336b135dcb2fd78ab9bcfb91b39a3770f7bac89c74";

  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    if (!Files.isDirectory(BUNDLE)) {
      System.out.println("✗ bundle directory missing: " + BUNDLE);
      System.exit(1);
    }

    // ---- 1. SHA256SUMS integrity ----------------------------------------------
    String sums = readString(BUNDLE.resolve("SHA256SUMS"));
    String[] files = {"README.md", "lifecycle-vectors.json", "oracle.py", "reference-report.json"};
    Map<String, String> recorded = new LinkedHashMap<>();
    for (String line : sums.trim().split("\n")) {
      String[] parts = line.trim().split("\\s+");
      if (parts.length >= 2) {
        recorded.put(parts[1], parts[0]);
      }
    }
    for (String f : files) {
      check("SHA256SUMS records " + f, recorded.containsKey(f));
      if (recorded.containsKey(f)) {
        check("SHA256SUMS hash matches " + f,
            recorded.get(f).equals(KeyprovLifecycleJson.sha256Hex(read(BUNDLE.resolve(f)))));
      }
    }

    // ---- 2. frozen JSON identity ----------------------------------------------
    String vectorsJson = readString(BUNDLE.resolve("lifecycle-vectors.json"));
    check("lifecycle-vectors.json sha256 == CR-010 normative hash",
        KeyprovLifecycleJson.sha256Hex(vectorsJson).equals(VECTOR_JSON_SHA256));

    @SuppressWarnings("unchecked")
    Map<String, Object> vectors = (Map<String, Object>) KeyprovLifecycleJson.parse(vectorsJson);
    check("profile == KEYPROV-LIFECYCLE-1",
        PROFILE.equals(KeyprovLifecycleJson.canonical(vectors.get("profile")))
            || PROFILE.equals(String.valueOf(vectors.get("profile"))));
    check("case_set == keyprov-lifecycle-kl1-v1",
        CASE_SET.equals(String.valueOf(vectors.get("case_set"))));
    check("T0 == 1800000000000 (fixed, not machine time)",
        T0 == lng(vectors.get("T0")));

    // ---- 3. profile parameters == pinned reference constants ------------------
    @SuppressWarnings("unchecked")
    Map<String, Object> params = (Map<String, Object>) vectors.get("parameters");
    Map<String, Long> pinned = new LinkedHashMap<>();
    pinned.put("response_ttl_ms", KeyprovLifecycleDecide.RESPONSE_TTL_MS);
    pinned.put("batch_ms", KeyprovLifecycleDecide.BATCH_MS);
    pinned.put("ack_grace_ms", KeyprovLifecycleDecide.ACK_GRACE_MS);
    pinned.put("skew_ms", KeyprovLifecycleDecide.SKEW_MS);
    pinned.put("issue_min_ms", KeyprovLifecycleDecide.ISSUE_MIN_MS);
    pinned.put("import_min_ms", KeyprovLifecycleDecide.IMPORT_MIN_MS);
    pinned.put("request_limit", KeyprovLifecycleDecide.REQUEST_LIMIT);
    pinned.put("request_window_ms", KeyprovLifecycleDecide.REQUEST_WINDOW_MS);
    pinned.put("readonly_limit", KeyprovLifecycleDecide.READONLY_LIMIT);
    pinned.put("readonly_window_ms", KeyprovLifecycleDecide.READONLY_WINDOW_MS);
    pinned.put("ack_limit", KeyprovLifecycleDecide.ACK_LIMIT);
    pinned.put("chain_ids", KeyprovLifecycleDecide.CHAIN_IDS);
    pinned.put("chain_window_ms", KeyprovLifecycleDecide.CHAIN_WINDOW_MS);
    pinned.put("sec_nf_observations", KeyprovLifecycleDecide.SEC_NF_OBSERVATIONS);
    pinned.put("sec_nf_span_ms", KeyprovLifecycleDecide.SEC_NF_SPAN_MS);
    boolean paramsOk = params != null;
    for (Map.Entry<String, Long> e : pinned.entrySet()) {
      boolean ok = params != null && params.containsKey(e.getKey())
          && lng(params.get(e.getKey())) == e.getValue();
      paramsOk = paramsOk && ok;
      check("profile parameter " + e.getKey() + " == " + e.getValue(), ok);
    }
    check("profile parameter set complete (no extra keys)",
        params != null && params.size() == pinned.size());

    // ---- 4. case-set identity: 57 unique sub-cases covering LC01..LC24 ---------
    @SuppressWarnings("unchecked")
    List<Object> cases = (List<Object>) vectors.get("cases");
    check("case count == 57 (24 groups / 57 sub-cases)", cases != null && cases.size() == 57);
    TreeSet<String> ids = new TreeSet<>();
    TreeSet<String> groups = new TreeSet<>();
    if (cases != null) {
      for (Object cObj : cases) {
        @SuppressWarnings("unchecked")
        Map<String, Object> c = (Map<String, Object>) cObj;
        String id = String.valueOf(c.get("case_id"));
        ids.add(id);
        String group = id.contains(".") ? id.substring(0, id.indexOf('.')) : id;
        groups.add(group);
      }
    }
    check("all 57 case IDs unique", ids.size() == 57);
    boolean allGroups = true;
    for (int i = 1; i <= 24; i++) {
      String g = String.format("LC%02d", i);
      if (!groups.contains(g)) {
        allGroups = false;
        check("scenario group " + g + " covered", false);
      }
    }
    check("scenario groups LC01..LC24 all covered", allGroups);

    // ---- 5. recompute input/expected hashes + run Java reference model ---------
    int passed = 0;
    List<Map<String, Object>> rows = new ArrayList<>();
    if (cases != null) {
      for (Object cObj : cases) {
        @SuppressWarnings("unchecked")
        Map<String, Object> c = (Map<String, Object>) cObj;
        String id = String.valueOf(c.get("case_id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> input = (Map<String, Object>) c.get("input");
        @SuppressWarnings("unchecked")
        Map<String, Object> expected = (Map<String, Object>) c.get("expected");
        String expectedInputHash = String.valueOf(c.get("input_hash"));
        String expectedExpectedHash = String.valueOf(c.get("expected_hash"));

        String recomputedInputHash =
            KeyprovLifecycleJson.sha256Hex(KeyprovLifecycleJson.canonical(input));
        String recomputedExpectedHash =
            KeyprovLifecycleJson.sha256Hex(KeyprovLifecycleJson.canonical(expected));
        boolean inputHashOk = recomputedInputHash.equals(expectedInputHash);
        boolean expectedHashOk = recomputedExpectedHash.equals(expectedExpectedHash);
        check(id + " input_hash recomputed", inputHashOk);
        check(id + " expected_hash recomputed", expectedHashOk);

        Map<String, Object> actual = KeyprovLifecycleDecide.decide(input);
        boolean casePass = inputHashOk && expectedHashOk
            && KeyprovLifecycleJson.canonical(actual)
                .equals(KeyprovLifecycleJson.canonical(expected));
        if (casePass) {
          passed++;
        }
        check(id + " reference model matches frozen expected", casePass);

        // CR-010 §8.6.4 CI row schema {case_id, input_hash, expected_hash,
        // actual_action, counters, pass}
        Map<String, Object> counters = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : actual.entrySet()) {
          if (!e.getKey().equals("action")) {
            counters.put(e.getKey(), e.getValue());
          }
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("case_id", id);
        row.put("input_hash", expectedInputHash);
        row.put("expected_hash", expectedExpectedHash);
        row.put("actual_action", actual.get("action"));
        row.put("counters", counters);
        row.put("pass", casePass);
        rows.add(row);
      }
    }

    // ---- 6. frozen reference-report.json is consistent 57/57 ------------------
    String reportJson = readString(BUNDLE.resolve("reference-report.json"));
    @SuppressWarnings("unchecked")
    Map<String, Object> report = (Map<String, Object>) KeyprovLifecycleJson.parse(reportJson);
    check("reference-report scope == REFERENCE_ORACLE_ONLY_NOT_PRODUCTION_CI",
        "REFERENCE_ORACLE_ONLY_NOT_PRODUCTION_CI".equals(String.valueOf(report.get("scope"))));
    check("reference-report total == 57", lng(report.get("total")) == 57L);
    check("reference-report passed == 57",
        lng(report.get("passed")) == 57L && lng(report.get("passed")) == lng(report.get("total")));
    @SuppressWarnings("unchecked")
    List<Object> reportRows = (List<Object>) report.get("results");
    check("reference-report results length == 57", reportRows != null && reportRows.size() == 57);

    // ---- 7. write the CR-010 CI reconciliation report --------------------------
    Files.createDirectories(OUT);
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("scope", "PAR_PROTO_REFERENCE_CI_NOT_PRODUCTION_CI");
    out.put("profile", PROFILE);
    out.put("case_set", CASE_SET);
    out.put("vector_json_sha256", VECTOR_JSON_SHA256);
    out.put("parameters", params);
    out.put("total", (long) rows.size());
    out.put("passed", (long) passed);
    out.put("results", rows);
    Files.write(REPORT,
        (KeyprovLifecycleJson.canonical(out) + "\n").getBytes(StandardCharsets.UTF_8));
    check("CI reconciliation report written " + REPORT,
        Files.size(REPORT) > 0L);
    check("all 57 sub-cases pass the Java reference model", passed == 57);

    if (failures == 0) {
      System.out.println("✅ KEYPROV-LIFECYCLE-1: 57/57 sub-cases pass the Java reference model;"
          + " vector bundle hash, profile parameters and CI report verified");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " KEYPROV-LIFECYCLE-1 VECTOR CHECK failure(s)");
      System.exit(1);
    }
  }

  private static byte[] read(Path p) throws Exception {
    return Files.readAllBytes(p);
  }

  private static String readString(Path p) throws Exception {
    return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
  }

  private static long lng(Object v) {
    if (v instanceof Long) {
      return (Long) v;
    }
    if (v instanceof Integer) {
      return (Integer) v;
    }
    if (v instanceof Number) {
      return ((Number) v).longValue();
    }
    throw new IllegalArgumentException("expected numeric value, got " + v);
  }

  private static void check(String label, boolean ok) {
    if (ok) {
      System.out.println("  ✓ " + label);
    } else {
      System.out.println("  ✗ " + label);
      failures++;
    }
  }
}
