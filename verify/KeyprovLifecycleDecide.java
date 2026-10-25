import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * KEYPROV-LIFECYCLE-1 (KL1) pure decision reference model
 * (PAR-PROTO-DSN-CR-010 §8.6.2 / §8.6.3, PAR-PROTO-REQ-CR-010 KL-REQ-001..007).
 *
 * <p>This is a faithful Java port of the CR-010 reference oracle
 * {@code verify/keyprov-lifecycle-kl1-v1/oracle.py}. It implements the 14
 * pure decision functions (issue / accept / ack / dedupe / budget / reconcile /
 * stabilize / expired / transport / new_attempt / time / chain / sec_contract /
 * store) that the semantic case-set {@code keyprov-lifecycle-kl1-v1} pins.
 *
 * <p>Contract:
 * <ul>
 *   <li>EVERY decision is a pure function of its input map — no wall clock,
 *       no sleep, no RNG, no I/O; time is always the fixed T0-based values
 *       carried inside each case input (T0 = 1800000000000ms is normative);</li>
 *   <li>profile parameters are pinned as constants and MUST equal
 *       {@code lifecycle-vectors.json} "parameters" (the check enforces it),
 *       exactly like the Python oracle hardcodes them;</li>
 *   <li>outputs are produced in the same canonical JSON form as the oracle
 *       (sorted keys, compact) so {@code actual == expected} comparison is
 *       byte-for-byte over the canonical representation;</li>
 *   <li>it is a REFERENCE model only: per CR-010 §8.6.4, production adapters
 *       must map the same inputs onto their real decision functions, schedulers
 *       and storage — this class must NOT be called by any adapter to fabricate
 *       an "actual" result, and its verdict never proves production conformance.</li>
 * </ul>
 */
public final class KeyprovLifecycleDecide {

  /** Normative KL1 profile parameters — MUST equal lifecycle-vectors.json "parameters". */
  public static final long RESPONSE_TTL_MS = 60_000L;
  public static final long BATCH_MS = 300_000L;
  public static final long ACK_GRACE_MS = 30_000L;      // E = min(now+60s, B-30s)
  public static final long SKEW_MS = 2_000L;
  public static final long ISSUE_MIN_MS = 20_000L;      // E-now < 20s -> EXPIRED_NO_ITEMS
  public static final long IMPORT_MIN_MS = 15_000L;     // E-U < 15s -> LEASE_TOO_SHORT
  public static final long REQUEST_LIMIT = 8L;
  public static final long REQUEST_WINDOW_MS = 120_000L;
  public static final long READONLY_LIMIT = 12L;
  public static final long READONLY_WINDOW_MS = 300_000L;
  public static final long ACK_LIMIT = 3L;
  public static final long CHAIN_IDS = 3L;
  public static final long CHAIN_WINDOW_MS = 600_000L;
  public static final long SEC_NF_OBSERVATIONS = 3L;
  public static final long SEC_NF_SPAN_MS = 12_000L;

  /** KL-REQ-001 trusted-time gates: uncertainty <=1000ms, freshness <=300000ms, skew <=2000ms. */
  public static final long UNCERTAINTY_MAX_MS = 1_000L;
  public static final long SAMPLE_AGE_MAX_MS = 300_000L;

  /** Python oracle's unbounded budget sentinel for the ACK phase ("10**18"). */
  static final long ACK_TIME_UNBOUNDED = 1_000_000_000_000_000_000L;

  private KeyprovLifecycleDecide() {}

  /** Run the pure decision function for one case input; result is a canonical-JSON-able map. */
  public static Map<String, Object> decide(Map<String, Object> x) {
    String op = str(x, "operation");
    switch (op) {
      case "issue":
        return issue(x);
      case "accept":
        return accept(x);
      case "ack":
        return ack(x);
      case "dedupe":
        return dedupe(x);
      case "budget":
        return budget(x);
      case "reconcile":
        return reconcile(x);
      case "stabilize":
        return stabilize(x);
      case "expired":
        return expired(x);
      case "transport":
        return transport(x);
      case "new_attempt":
        return newAttempt(x);
      case "time":
        return time(x);
      case "chain":
        return chain(x);
      case "sec_contract":
        return secContract(x);
      case "store":
        return store(x);
      default:
        throw new IllegalArgumentException("unknown lifecycle operation: " + op);
    }
  }

  /** LC01/LC03/LC20 — VMD response issue / lease signing. */
  private static Map<String, Object> issue(Map<String, Object> x) {
    if (!bool(x.get("safety_valid_through_E"), true)) {
      return map("action", "SECURITY_BLOCKED", "provider_calls", 0L, "item_changes", 0L);
    }
    long now = lng(x.get("now"));
    long e = Math.min(now + RESPONSE_TTL_MS, lng(x.get("B")) - ACK_GRACE_MS);
    if (e - now < ISSUE_MIN_MS) {
      return map("action", "EXPIRED_NO_ITEMS", "provider_calls", 0L, "item_changes", 0L);
    }
    return map("action", "FRESH_RESPONSE", "E", e, "provider_calls", 0L, "item_changes", 0L);
  }

  /** LC02/LC06 — TSP import admission against the device upper-bound time U. */
  private static Map<String, Object> accept(Map<String, Object> x) {
    String a;
    if (bool(x.get("terminalized"), false)) {
      a = "LATE_RESPONSE";
    } else if (lng(x.get("U")) >= lng(x.get("E"))) {
      a = "RESPONSE_EXPIRED";
    } else if (lng(x.get("E")) - lng(x.get("U")) < IMPORT_MIN_MS) {
      a = "LEASE_TOO_SHORT";
    } else {
      a = "IMPORT";
    }
    return map("action", a, "import_calls", a.equals("IMPORT") ? 1L : 0L);
  }

  /** LC04/LC05/LC19 — VMD ACK linearization at the fixed hard deadline B. */
  private static Map<String, Object> ack(Map<String, Object> x) {
    String state = str(x, "state");
    boolean valid = bool(x.get("valid_dual_proof"), false);
    if (state.equals("ACTIVE")) {
      return map("action", valid ? "ACTIVE" : "REJECT_ACK",
          "active_purposes", 2L, "new_events", 0L);
    }
    if (state.equals("FAILED") || lng(x.get("now")) >= lng(x.get("B"))) {
      return map("action", "FAILED_ACK_TIMEOUT", "active_purposes", 0L, "new_events", 0L);
    }
    if (!valid) {
      return map("action", "REJECT_ACK", "active_purposes", 0L, "new_events", 0L);
    }
    return map("action", "ACTIVE", "active_purposes", 2L, "new_events", 1L);
  }

  /** LC07/LC08 — same requestId dedupe: same business content vs 806095 conflict. */
  private static Map<String, Object> dedupe(Map<String, Object> x) {
    boolean same = bool(x.get("same_business_digest"), false);
    return map("action", same ? "SAME_BATCH_FRESH_LEASE" : "CONFLICT_806095",
        "new_material_versions", 0L, "provider_calls", 0L);
  }

  /** LC09/LC10 — per-phase bounded budgets, persisted across restart (never reset). */
  private static Map<String, Object> budget(Map<String, Object> x) {
    String phase = str(x, "phase");
    long n;
    long t;
    if (phase.equals("REQUEST")) {
      n = REQUEST_LIMIT;
      t = REQUEST_WINDOW_MS;
    } else if (phase.equals("ACK")) {
      n = ACK_LIMIT;
      t = ACK_TIME_UNBOUNDED;
    } else { // STATUS / SEC share the read-only window
      n = READONLY_LIMIT;
      t = READONLY_WINDOW_MS;
    }
    boolean exhausted = lng(x.get("count")) >= n
        || lng(x.get("elapsed")) >= t
        || (phase.equals("ACK") && !bool(x.get("before_D"), false));
    String action = exhausted
        ? (phase.equals("REQUEST") || phase.equals("ACK") ? "READONLY" : "BLOCKED")
        : "SEND";
    return map("action", action, "new_sends", exhausted ? 0L : 1L);
  }

  /** LC11/LC14/LC15 — device reconcile branch on SEC evidence + cloud status. */
  private static Map<String, Object> reconcile(Map<String, Object> x) {
    String a = "READONLY";
    if (str(x, "sec").equals("COMMITTED")) {
      if (str(x, "cloud").equals("FAILED")) {
        a = "BLOCKED_REMOTE_REPAIR";
      } else if (str(x, "cloud").equals("ACK_PENDING")
          && bool(x.get("ack_budget"), false) && bool(x.get("before_D"), false)) {
        a = "RESTORE_ORIGINAL_ACK";
      }
    }
    return map("action", a, "import_calls", 0L, "new_ids", 0L, "nf_increment", 0L);
  }

  /** LC12/LC13 — NO_SIDE_EFFECT_PROVEN stabilization + CAS unique successor. */
  @SuppressWarnings("unchecked")
  private static Map<String, Object> stabilize(Map<String, Object> x) {
    List<Object> observations = (List<Object>) x.get("observations");
    List<Long> run = new java.util.ArrayList<>();
    String epoch = null;
    for (Object obsObj : observations) {
      Map<String, Object> obs = (Map<String, Object>) obsObj;
      if (!str(obs, "kind").equals("NOT_FOUND")) {
        run = new java.util.ArrayList<>();
        epoch = null;
        continue;
      }
      String obsEpoch = str(obs, "epoch");
      if (!obsEpoch.equals(epoch)) {
        run = new java.util.ArrayList<>();
        epoch = obsEpoch;
      }
      run.add(lng(obs.get("t")));
    }
    boolean proven = run.size() >= SEC_NF_OBSERVATIONS
        && run.get(run.size() - 1) - run.get(0) >= SEC_NF_SPAN_MS;
    boolean remoteReleasable = str(x, "cloud").equals("FAILED")
        || (str(x, "cloud").equals("UNSPECIFIED")
            && lng(x.get("error_code")) == 806099L
            && Boolean.FALSE.equals(x.get("retryable"))
            && "DO_NOT_RETRY".equals(str(x, "error_action")));
    boolean eligible = proven && remoteReleasable;
    String a;
    if (eligible && x.get("successor") != null && !((String) x.get("successor")).isEmpty()) {
      a = "RESTORE_SUCCESSOR";
    } else if (eligible && lng(x.get("chain_ids")) < CHAIN_IDS
        && lng(x.get("chain_elapsed")) < CHAIN_WINDOW_MS) {
      a = "SUPERSEDE_ONCE";
    } else {
      a = "READONLY";
    }
    return map("action", a, "proven", proven, "new_ids", a.equals("SUPERSEDE_ONCE") ? 1L : 0L);
  }

  /** LC16 — at most one post-expiry same-ID freshen; afterwards Status-only. */
  private static Map<String, Object> expired(Map<String, Object> x) {
    boolean fresh = bool(x.get("proven"), false)
        && str(x, "cloud").equals("ACK_PENDING")
        && lng(x.get("freshen_used")) == 0L
        && bool(x.get("request_budget"), false)
        && bool(x.get("deliverable"), false);
    return map("action", fresh ? "FRESHEN_SAME_ID" : "READONLY",
        "new_requests", fresh ? 1L : 0L);
  }

  /** LC17 — Envelope and payload admission are two independent gates. */
  private static Map<String, Object> transport(Map<String, Object> x) {
    boolean ok = bool(x.get("envelope_fresh"), false) && bool(x.get("payload_fresh"), false);
    return map("action", ok ? "ADMIT" : "REJECT", "import_calls", ok ? 1L : 0L);
  }

  /** LC18 — successor attempt: same logical material, brand-new wrap operation. */
  private static Map<String, Object> newAttempt(Map<String, Object> x) {
    boolean ok = bool(x.get("old_terminal"), false)
        && bool(x.get("proven"), false)
        && bool(x.get("same_material"), false)
        && !bool(x.get("same_rid"), false);
    return map("action", ok ? "NEW_WRAP_SAME_MATERIAL" : "BLOCKED",
        "new_material_versions", 0L, "new_wrap_operations", ok ? 1L : 0L,
        "new_rid_bound_aad", ok);
  }

  /** LC21 — trusted-time health gates with equality boundaries (no TTL extension). */
  private static Map<String, Object> time(Map<String, Object> x) {
    boolean bad = num(x.get("uncertainty"), 0L) > UNCERTAINTY_MAX_MS
        || num(x.get("sample_age"), 0L) > SAMPLE_AGE_MAX_MS
        || bool(x.get("rollback"), false)
        || Math.abs(num(x.get("skew"), 0L)) > SKEW_MS;
    return map("action", bad ? "TIME_UNTRUSTED" : "TIME_READY",
        "import_calls", 0L, "new_leases", 0L);
  }

  /** LC22 — recovery chain bound: at most 3 ids / 600s, no auto new chain. */
  private static Map<String, Object> chain(Map<String, Object> x) {
    boolean blocked = lng(x.get("chain_ids")) >= CHAIN_IDS || lng(x.get("elapsed")) >= CHAIN_WINDOW_MS;
    return map("action", blocked ? "BLOCKED" : "ALLOW_SUCCESSOR",
        "new_ids", blocked ? 0L : 1L);
  }

  /** LC23 — legacy SDK unknowns are ContractUnknown, never NOT_FOUND. */
  private static Map<String, Object> secContract(Map<String, Object> x) {
    boolean ok = bool(x.get("version_known"), false) && bool(x.get("state_consistent"), false);
    return map("action", ok ? "READY" : "CONTRACT_UNKNOWN", "proven", false);
  }

  /** LC24 — replay store fail-closed; never re-derive to "repair" missing input. */
  private static Map<String, Object> store(Map<String, Object> x) {
    boolean ok = bool(x.get("digest_valid"), true)
        && bool(x.get("codec_known"), true)
        && bool(x.get("profile_known"), true);
    return map("action", ok ? "REPLAY" : "STORE_QUARANTINE", "provider_calls", 0L);
  }

  // ---- helpers ----------------------------------------------------------------

  static Map<String, Object> map(Object... kv) {
    Map<String, Object> m = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) {
      m.put(String.valueOf(kv[i]), kv[i + 1]);
    }
    return m;
  }

  static String str(Map<String, Object> x, String key) {
    Object v = x.get(key);
    return v == null ? "" : String.valueOf(v);
  }

  static long lng(Object v) {
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

  static long num(Object v, long dflt) {
    return v == null ? dflt : lng(v);
  }

  static boolean bool(Object v, boolean dflt) {
    return v instanceof Boolean ? (Boolean) v : dflt;
  }
}
