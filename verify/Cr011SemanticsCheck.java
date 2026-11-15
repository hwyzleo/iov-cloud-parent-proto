import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import vehicle.fota.v1.Download;
import vehicle.fota.v1.Types;

/**
 * CR-011 download-progress acceptance reference model + semantic checks
 * (PAR-PROTO-DSN-CR-011 §6 / §11, SPEC 设计 §6.5.2/§6.5.3).
 *
 * This is NOT production cloud code: PAR-PROTO freezes the acceptance algorithm
 * (idempotency, second unique key, current/late matrix, byte monotonicity,
 * RESET_OFFSET baseline, completion boundary, sampling, time fields) so that
 * IOV-OTA (Java) and CGW-FOTA (C++) implementations can be reconciled against
 * the same deterministic semantics and golden bytes.
 *
 * Test matrix coverage (CR-011 §11):
 *   normal flow / idempotency / ordering / regression / object boundary /
 *   completion boundary / sampling / time / unknown-enum fail-closed.
 */
public class Cr011SemanticsCheck {
  private static int failures = 0;

  private static final long TOTAL = 1048576L;
  private static final long T0 = 1800000000000L;

  public static void main(String[] args) throws Exception {
    normalFlow();
    idempotency();
    secondUniqueKey();
    ordering();
    byteMonotonicity();
    resetOffset();
    objectBoundary();
    completionBoundary();
    timeFields();
    legality();
    unknownState();
    sampling();

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ CR-011 DOWNLOAD SEMANTICS CHECK PASSED (acceptance reference model)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " CR-011 semantics check failure(s)");
      System.exit(1);
    }
  }

  // ===========================================================================
  // Test groups
  // ===========================================================================

  /** STARTED -> PROGRESS -> COMPLETED with monotonic seq/bytes. */
  private static void normalFlow() {
    DownloadAcceptance a = new DownloadAcceptance();
    AcceptResult r1 = a.accept(base("DP-1", 1).setDownloadedBytes(0).build());
    expect("normal: STARTED seq1 -> CURRENT", r1, Disposition.CURRENT, true, 1);
    AcceptResult r2 = a.accept(base("DP-2", 2).setDownloadedBytes(TOTAL / 2).build());
    expect("normal: PROGRESS seq2 -> CURRENT", r2, Disposition.CURRENT, true, 2);
    AcceptResult r3 = a.accept(base("DP-3", 3).setDownloadedBytes(TOTAL)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_COMPLETED).build());
    expect("normal: COMPLETED seq3 -> CURRENT", r3, Disposition.CURRENT, true, 3);
    check("normal: COMPLETED does not create Execution", !a.executionCreated);
    check("normal: COMPLETED does not advance READY_TO_INSTALL", !a.readyToInstall);
    check("normal: COMPLETED never enters the Execution event watermark",
        a.executionEventWatermark == 0);
  }

  /** progressId first idempotency key + eventDigest comparison. */
  private static void idempotency() {
    DownloadAcceptance a = new DownloadAcceptance();
    Download.DownloadProgressReport p2 = base("DP-2", 2).setDownloadedBytes(TOTAL / 2).build();
    a.accept(base("DP-1", 1).build());
    a.accept(p2);
    int history = a.history.size();

    AcceptResult dup = a.accept(p2);
    expect("idempotency: same id + same digest -> DUPLICATE", dup, Disposition.DUPLICATE, true, 2);
    check("idempotency: DUPLICATE reuses first accepted result", dup.accepted && dup.latestAcceptedProgressSeq == 2);
    check("idempotency: DUPLICATE appends no history", a.history.size() == history);
    check("idempotency: DUPLICATE does not advance snapshot", a.current(1).seq == 2);

    AcceptResult conflict = a.accept(p2.toBuilder()
        .setEventDigest(digest("different-content")).build());
    expect("idempotency: same id + different digest -> CONFLICT", conflict, Disposition.CONFLICT, false, 2);
    check("idempotency: CONFLICT appends no history", a.history.size() == history);
    check("idempotency: CONFLICT does not change snapshot",
        a.current(1).seq == 2 && a.current(1).downloadedBytes == TOTAL / 2);

    // a rejected first result must be replayed as the original rejection
    Download.DownloadProgressReport bad = base("DP-BAD", 9).setTotalBytes(0).build();
    AcceptResult firstRejected = a.accept(bad);
    expect("idempotency: illegal first report -> REJECTED", firstRejected, Disposition.REJECTED, false, 2);
    AcceptResult replayRejected = a.accept(bad);
    check("idempotency: rejected replay keeps REJECTED (never rewritten to success)",
        replayRejected.disposition == Disposition.REJECTED && !replayRejected.accepted);
    check("idempotency: rejected replay appends no history", a.history.size() == history);
  }

  /** Second unique key = (vehicleTaskId, packageId, downloadAttemptNo, progressSeq). */
  private static void secondUniqueKey() {
    DownloadAcceptance a = new DownloadAcceptance();
    a.accept(base("DP-1", 1).build());
    a.accept(base("DP-2", 2).setDownloadedBytes(1000).build());

    AcceptResult clash = a.accept(base("DP-OTHER", 2).setDownloadedBytes(1000).build());
    expect("second key: different id on same (task,pkg,attempt,seq) -> CONFLICT",
        clash, Disposition.CONFLICT, false, 2);
    check("second key: CONFLICT appends no history", a.history.size() == 2);

    AcceptResult sameDigestClash = a.accept(base("DP-OTHER-2", 2)
        .setEventDigest(digest("DP-2")).setDownloadedBytes(1000).build());
    expect("second key: clash with identical digest is still CONFLICT",
        sameDigestClash, Disposition.CONFLICT, false, 2);

    // a different download attempt reuses the same progress sequences legally
    AcceptResult newAttempt = a.accept(base("DP-A2", 3).setDownloadAttemptNo(2)
        .setDownloadedBytes(1000).build());
    expect("second key: new downloadAttemptNo is an independent sequence", newAttempt,
        Disposition.CURRENT, true, 3);
  }

  /** current vs late observation matrix. */
  private static void ordering() {
    DownloadAcceptance a = new DownloadAcceptance();
    a.accept(base("DP-1", 1).build());
    a.accept(base("DP-3", 3).setDownloadedBytes(3000).build());

    AcceptResult late = a.accept(base("DP-2", 2).setDownloadedBytes(2000).build());
    expect("ordering: older legal seq -> LATE_OBSERVATION", late, Disposition.LATE_OBSERVATION, true, 3);
    check("ordering: LATE_OBSERVATION appended as immutable history", a.history.contains("DP-2"));
    check("ordering: LATE_OBSERVATION leaves snapshot seq", a.current(1).seq == 3);
    check("ordering: LATE_OBSERVATION leaves snapshot bytes", a.current(1).downloadedBytes == 3000);

    AcceptResult equalSeq = a.accept(base("DP-EQ", 3).setDownloadedBytes(3000).build());
    expect("ordering: equal seq with new id -> CONFLICT", equalSeq, Disposition.CONFLICT, false, 3);
  }

  /** byte/resume-offset monotonicity for non RESET_OFFSET reports. */
  private static void byteMonotonicity() {
    DownloadAcceptance a = new DownloadAcceptance();
    a.accept(base("DP-1", 1).build());
    a.accept(base("DP-2", 2).setDownloadedBytes(5000).setResumeOffset(5000).build());

    AcceptResult regressBytes = a.accept(base("DP-3", 3).setDownloadedBytes(4000).setResumeOffset(4000).build());
    expect("monotonic: higher seq with downloadedBytes regression -> REJECTED",
        regressBytes, Disposition.REJECTED, false, 2);
    check("monotonic: regression appends no history", a.history.size() == 2);

    AcceptResult regressOffset = a.accept(base("DP-4", 4).setDownloadedBytes(6000).setResumeOffset(100).build());
    expect("monotonic: higher seq with resumeOffset regression -> REJECTED",
        regressOffset, Disposition.REJECTED, false, 2);

    AcceptResult forward = a.accept(base("DP-5", 5).setDownloadedBytes(6000).setResumeOffset(5000).build());
    expect("monotonic: higher seq with equal/greater bytes -> CURRENT", forward,
        Disposition.CURRENT, true, 5);
  }

  /** RESET_OFFSET baseline semantics (0 always legal, non-zero needs a grant). */
  private static void resetOffset() {
    DownloadAcceptance a = new DownloadAcceptance();
    a.accept(base("DP-1", 1).build());
    a.accept(base("DP-2", 2).setDownloadedBytes(5000).setResumeOffset(5000).build());

    Download.DownloadProgressReport unauthorized = reset("DP-R", 3, 262144);
    expect("reset: non-zero offset without DownloadGrant -> REJECTED", a.accept(unauthorized),
        Disposition.REJECTED, false, 2);

    a.grant = new Grant("REV-1", "etag-1", 262144L, true);
    // a fresh progressId: the rejected report above is an idempotent first result
    AcceptResult authorized = a.accept(reset("DP-R1", 3, 262144));
    expect("reset: granted non-zero offset matching current_offset_bytes -> CURRENT",
        authorized, Disposition.CURRENT, true, 3);
    check("reset: baseline == resume_offset", a.current(1).downloadedBytes == 262144L
        && a.current(1).resumeOffset == 262144L);

    AcceptResult mismatch = a.accept(reset("DP-R2", 4, 131072));
    expect("reset: offset not equal to the authorized offset -> REJECTED", mismatch,
        Disposition.REJECTED, false, 3);

    AcceptResult afterBaseline = a.accept(base("DP-3", 5)
        .setDownloadedBytes(300000).setResumeOffset(262144).build());
    expect("reset: monotonic accumulation resumes from the new baseline", afterBaseline,
        Disposition.CURRENT, true, 5);

    // zero offset is always a legal reset baseline, even with no grant
    DownloadAcceptance fresh = new DownloadAcceptance();
    fresh.accept(base("DP-Z1", 1).setDownloadedBytes(9000).setResumeOffset(9000).build());
    AcceptResult zeroReset = fresh.accept(reset("DP-Z2", 2, 0));
    expect("reset: offset 0 is always a legal new baseline", zeroReset,
        Disposition.CURRENT, true, 2);
    check("reset: zero baseline recorded", fresh.current(1).downloadedBytes == 0
        && fresh.current(1).resumeOffset == 0);
    AcceptResult fromZero = fresh.accept(base("DP-Z3", 3).setDownloadedBytes(1000).build());
    expect("reset: accumulation restarts from 0", fromZero, Disposition.CURRENT, true, 3);
  }

  /** ETag / packageRevision object boundary. */
  private static void objectBoundary() {
    DownloadAcceptance a = new DownloadAcceptance();
    a.accept(base("DP-1", 1).build());
    a.accept(base("DP-2", 2).setDownloadedBytes(5000).build());

    AcceptResult etagJump = a.accept(base("DP-3", 3).setDownloadedBytes(6000).setEtag("etag-2").build());
    expect("boundary: non RESET_OFFSET ETag mutation -> REJECTED", etagJump,
        Disposition.REJECTED, false, 2);

    AcceptResult revisionJump = a.accept(base("DP-4", 4).setDownloadedBytes(6000)
        .setPackageRevision("REV-2").build());
    expect("boundary: non RESET_OFFSET packageRevision mutation -> REJECTED", revisionJump,
        Disposition.REJECTED, false, 2);

    AcceptResult newObject = a.accept(reset("DP-5", 5, 0).toBuilder().setEtag("etag-2").build());
    expect("boundary: ETag change with offset=0 RESET_OFFSET establishes new object", newObject,
        Disposition.CURRENT, true, 5);
    check("boundary: snapshot adopts the new ETag", a.current(1).etag.equals("etag-2"));

    AcceptResult staleEtag = a.accept(base("DP-6", 6).setDownloadedBytes(100).setEtag("etag-1").build());
    expect("boundary: stale ETag after boundary change -> REJECTED", staleEtag,
        Disposition.REJECTED, false, 5);

    // without RESET_OFFSET the only other legal route is a new downloadAttemptNo
    DownloadAcceptance b = new DownloadAcceptance();
    b.accept(base("DP-1", 1).build());
    AcceptResult newAttempt = b.accept(base("DP-2", 1).setDownloadAttemptNo(2)
        .setEtag("etag-2").build());
    expect("boundary: new downloadAttemptNo with new ETag -> CURRENT", newAttempt,
        Disposition.CURRENT, true, 1);
  }

  /** COMPLETED only means object bytes finished; it must not touch install state. */
  private static void completionBoundary() {
    DownloadAcceptance a = new DownloadAcceptance();
    a.accept(base("DP-1", 1).build());

    AcceptResult premature = a.accept(base("DP-2", 2)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_COMPLETED)
        .setDownloadedBytes(TOTAL - 1).build());
    expect("completion: COMPLETED with downloaded_bytes < total_bytes -> REJECTED",
        premature, Disposition.REJECTED, false, 1);

    AcceptResult completed = a.accept(base("DP-3", 3)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_COMPLETED)
        .setDownloadedBytes(TOTAL).build());
    expect("completion: COMPLETED with downloaded_bytes == total_bytes -> CURRENT",
        completed, Disposition.CURRENT, true, 3);
    check("completion: no Execution created by COMPLETED", !a.executionCreated);
    check("completion: READY_TO_INSTALL not advanced by COMPLETED", !a.readyToInstall);
    check("completion: cloud percentage is derived, not carried on the wire",
        !Download.DownloadProgressReport.getDescriptor().getFields().stream()
            .anyMatch(f -> f.getName().equals("progress_percent")));
    check("completion: no deny_code field on the response",
        !Download.DownloadProgressResponse.getDescriptor().getFields().stream()
            .anyMatch(f -> f.getName().equals("deny_code")));
  }

  /** occurredAtMs == 0 means unknown; negative is illegal; never backfilled. */
  private static void timeFields() {
    DownloadAcceptance a = new DownloadAcceptance();
    AcceptResult unknownTime = a.accept(base("DP-1", 1).setOccurredAtMs(0).build());
    expect("time: occurredAtMs=0 is accepted as unknown", unknownTime,
        Disposition.CURRENT, true, 1);
    check("time: unknown time is not backfilled by the cloud", a.lastOccurredAtMs == 0);

    AcceptResult negative = a.accept(base("DP-2", 2).setOccurredAtMs(-1).build());
    expect("time: negative occurredAtMs -> REJECTED", negative, Disposition.REJECTED, false, 1);

    AcceptResult known = a.accept(base("DP-3", 3).setOccurredAtMs(T0 + 5000).build());
    expect("time: positive occurredAtMs preserved", known, Disposition.CURRENT, true, 3);
    check("time: occurredAtMs stored verbatim", a.lastOccurredAtMs == T0 + 5000);
  }

  /** Basic legality (§6.1). */
  private static void legality() {
    DownloadAcceptance a = new DownloadAcceptance();
    expect("legality: empty progress_id -> REJECTED", a.accept(base("", 1).build()),
        Disposition.REJECTED, false, 0);
    expect("legality: empty vehicle_task_id -> REJECTED",
        a.accept(base("DP-1", 1).setVehicleTaskId("").build()), Disposition.REJECTED, false, 0);
    expect("legality: empty package_id -> REJECTED",
        a.accept(base("DP-2", 1).setPackageId("").build()), Disposition.REJECTED, false, 0);
    expect("legality: empty package_revision -> REJECTED",
        a.accept(base("DP-3", 1).setPackageRevision("").build()), Disposition.REJECTED, false, 0);
    expect("legality: download_attempt_no = 0 -> REJECTED",
        a.accept(base("DP-4", 1).setDownloadAttemptNo(0).build()), Disposition.REJECTED, false, 0);
    expect("legality: progress_seq = 0 -> REJECTED",
        a.accept(base("DP-5", 0).build()), Disposition.REJECTED, false, 0);
    expect("legality: total_bytes = 0 -> REJECTED",
        a.accept(base("DP-6", 1).setTotalBytes(0).build()), Disposition.REJECTED, false, 0);
    expect("legality: downloaded_bytes > total_bytes -> REJECTED",
        a.accept(base("DP-7", 1).setDownloadedBytes(TOTAL + 1).build()),
        Disposition.REJECTED, false, 0);
    expect("legality: resume_offset > downloaded_bytes -> REJECTED",
        a.accept(base("DP-8", 1).setDownloadedBytes(10).setResumeOffset(11).build()),
        Disposition.REJECTED, false, 0);
    expect("legality: eventDigest.algorithm != SHA-256 -> REJECTED",
        a.accept(base("DP-9", 1).setEventDigest(Types.Digest.newBuilder()
            .setAlgorithm("SHA-1").setValueHex(digest("x").getValueHex()).build()).build()),
        Disposition.REJECTED, false, 0);
    expect("legality: eventDigest.value_hex must be 64 lowercase hex -> REJECTED",
        a.accept(base("DP-10", 1).setEventDigest(Types.Digest.newBuilder()
            .setAlgorithm("SHA-256").setValueHex("ABC").build()).build()),
        Disposition.REJECTED, false, 0);
    check("legality: no snapshot created by rejected reports",
        a.snapshotByAttempt.isEmpty() && a.history.isEmpty());
  }

  /** UNSPECIFIED / unknown DownloadState fail-closed (never UNSPECIFIED/PROGRESS). */
  private static void unknownState() throws Exception {
    DownloadAcceptance a = new DownloadAcceptance();
    expect("unknown state: UNSPECIFIED -> REJECTED",
        a.accept(base("DP-1", 1)
            .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_UNSPECIFIED).build()),
        Disposition.REJECTED, false, 0);

    Download.DownloadProgressReport unknown = base("DP-2", 2).setDownloadStateValue(99).build();
    byte[] wire = unknown.toByteArray();
    Download.DownloadProgressReport parsed = Download.DownloadProgressReport.parseFrom(wire);
    check("unknown state: wire keeps the unknown enum value 99", parsed.getDownloadStateValue() == 99);
    check("unknown state: accessor is UNRECOGNIZED (not UNSPECIFIED/PROGRESS)",
        parsed.getDownloadState() == Download.DownloadState.UNRECOGNIZED);
    AcceptResult r = a.accept(parsed);
    expect("unknown state: business layer REJECTs the unknown enum", r,
        Disposition.REJECTED, false, 0);

    Download.DownloadProgressReport withUnknownField = base("DP-3", 3)
        .setUnknownFields(com.google.protobuf.UnknownFieldSet.newBuilder()
            .addField(999, com.google.protobuf.UnknownFieldSet.Field.newBuilder()
                .addVarint(7L).build())
            .build())
        .build();
    AcceptResult uf = a.accept(Download.DownloadProgressReport.parseFrom(withUnknownField.toByteArray()));
    expect("unknown field: wire retention does not block legal acceptance", uf,
        Disposition.CURRENT, true, 3);
  }

  /** Vehicle-side sampling obligation: 10s OR totalBytes*5%, whichever first. */
  private static void sampling() {
    check("sampling: 10s elapsed triggers a PROGRESS report",
        DownloadAcceptance.shouldReportProgress(T0, 0, T0 + 10000, 100, TOTAL));
    check("sampling: 9999ms and <5% growth does not trigger",
        !DownloadAcceptance.shouldReportProgress(T0, 0, T0 + 9999, TOTAL / 50, TOTAL));
    check("sampling: exactly 5% growth triggers before 10s",
        DownloadAcceptance.shouldReportProgress(T0, 0, T0 + 1000, 50000, 1000000));
    check("sampling: exactly 10s triggers regardless of bytes",
        DownloadAcceptance.shouldReportProgress(T0, 1000, T0 + 10000, 1000, TOTAL));
    check("sampling: first report after last PROGRESS uses both rules",
        !DownloadAcceptance.shouldReportProgress(T0, 1000, T0 + 5000, 1000 + (TOTAL / 20) - 1, TOTAL));
  }

  // ===========================================================================
  // Reference acceptance model (deterministic, in-memory, no clock, no I/O)
  // ===========================================================================

  enum Disposition {
    CURRENT, LATE_OBSERVATION, DUPLICATE, CONFLICT, REJECTED;

    Download.DownloadProgressDisposition toProto() {
      switch (this) {
        case CURRENT: return Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_CURRENT;
        case LATE_OBSERVATION:
          return Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_LATE_OBSERVATION;
        case DUPLICATE:
          return Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_DUPLICATE;
        case CONFLICT:
          return Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_CONFLICT;
        default:
          return Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_REJECTED;
      }
    }
  }

  static final class AcceptResult {
    final Disposition disposition;
    final boolean accepted;
    final long latestAcceptedProgressSeq;
    final String denyReason;
    final boolean appendedHistory;
    final boolean advancedSnapshot;

    AcceptResult(Disposition disposition, boolean accepted, long latestAcceptedProgressSeq,
        String denyReason, boolean appendedHistory, boolean advancedSnapshot) {
      this.disposition = disposition;
      this.accepted = accepted;
      this.latestAcceptedProgressSeq = latestAcceptedProgressSeq;
      this.denyReason = denyReason;
      this.appendedHistory = appendedHistory;
      this.advancedSnapshot = advancedSnapshot;
    }
  }

  static final class Snapshot {
    long seq;
    long downloadedBytes;
    long resumeOffset;
    String etag;
    String packageRevision;
  }

  static final class FirstResult {
    String digestHex;
    AcceptResult result;
  }

  static final class Grant {
    final String packageRevision;
    final String etag;
    final long authorizedOffset;
    final boolean resumeAllowed;

    Grant(String packageRevision, String etag, long authorizedOffset, boolean resumeAllowed) {
      this.packageRevision = packageRevision;
      this.etag = etag;
      this.authorizedOffset = authorizedOffset;
      this.resumeAllowed = resumeAllowed;
    }
  }

  /**
   * Cloud acceptance reference state machine for one (vehicle_task, package) scope.
   * See CR-011 §6.2/§6.3/§6.4.
   */
  static final class DownloadAcceptance {
    final Map<String, Snapshot> snapshotByAttempt = new HashMap<>();
    final Map<String, FirstResult> firstByProgressId = new HashMap<>();
    final Map<String, String> progressIdBySecondKey = new HashMap<>();
    final List<String> history = new ArrayList<>();
    Grant grant;

    // install-boundary observability (must stay untouched by download progress)
    boolean executionCreated = false;
    boolean readyToInstall = false;
    long executionEventWatermark = 0;
    long lastOccurredAtMs = -1;

    /** Vehicle-side sampling obligation: 10s since last PROGRESS or +5% of total. */
    static boolean shouldReportProgress(long lastReportMs, long lastReportBytes,
        long nowMs, long downloadedBytes, long totalBytes) {
      if (nowMs - lastReportMs >= 10000L) {
        return true;
      }
      return (downloadedBytes - lastReportBytes) * 100L >= totalBytes * 5L;
    }

    /** Current snapshot of one download attempt (ETag/revision boundary scope). */
    Snapshot current(int downloadAttemptNo) {
      return snapshotByAttempt.get(attemptKey("VT-CR011", "PKG-CR011", downloadAttemptNo));
    }

    AcceptResult accept(Download.DownloadProgressReport r) {
      String attemptKey = attemptKey(r.getVehicleTaskId(), r.getPackageId(), r.getDownloadAttemptNo());
      Snapshot current = snapshotByAttempt.get(attemptKey);
      String invalid = validate(r);
      if (invalid != null) {
        return record(r, new AcceptResult(Disposition.REJECTED, false, latestSeq(current),
            invalid, false, false));
      }

      FirstResult first = firstByProgressId.get(r.getProgressId());
      if (first != null) {
        if (!first.digestHex.equals(r.getEventDigest().getValueHex())) {
          return new AcceptResult(Disposition.CONFLICT, false, latestSeq(current),
              "DIGEST_CONFLICT", false, false);
        }
        // replay: accepted -> DUPLICATE, rejected/conflict -> original outcome
        if (first.result.disposition == Disposition.REJECTED
            || first.result.disposition == Disposition.CONFLICT) {
          return first.result;
        }
        return new AcceptResult(Disposition.DUPLICATE, first.result.accepted,
            first.result.latestAcceptedProgressSeq, null, false, false);
      }

      String secondKey = secondKey(r);
      String owner = progressIdBySecondKey.get(secondKey);
      if (owner != null && !owner.equals(r.getProgressId())) {
        return record(r, new AcceptResult(Disposition.CONFLICT, false, latestSeq(current),
            "SECOND_KEY_CONFLICT", false, false));
      }

      boolean reset = r.getDownloadState() == Download.DownloadState.DOWNLOAD_STATE_RESET_OFFSET;
      if (reset) {
        if (r.getResumeOffset() > 0) {
          boolean authorized = grant != null && grant.resumeAllowed
              && grant.packageRevision.equals(r.getPackageRevision())
              && grant.etag.equals(r.getEtag())
              && grant.authorizedOffset == r.getResumeOffset();
          if (!authorized) {
            return record(r, new AcceptResult(Disposition.REJECTED, false, latestSeq(current),
                "RESET_OFFSET_UNAUTHORIZED", false, false));
          }
        }
      } else if (current != null) {
        boolean etagChanged = !current.etag.equals(r.getEtag());
        boolean revisionChanged = !current.packageRevision.equals(r.getPackageRevision());
        if (etagChanged || revisionChanged) {
          return record(r, new AcceptResult(Disposition.REJECTED, false, latestSeq(current),
              "OBJECT_BOUNDARY_CHANGED", false, false));
        }
        if (r.getProgressSeq() > current.seq
            && (r.getDownloadedBytes() < current.downloadedBytes
                || r.getResumeOffset() < current.resumeOffset)) {
          return record(r, new AcceptResult(Disposition.REJECTED, false, latestSeq(current),
              "BYTES_REGRESSION", false, false));
        }
      }

      lastOccurredAtMs = r.getOccurredAtMs();
      history.add(r.getProgressId());
      progressIdBySecondKey.put(secondKey, r.getProgressId());

      if (current == null || r.getProgressSeq() > current.seq) {
        Snapshot s = new Snapshot();
        s.seq = r.getProgressSeq();
        s.downloadedBytes = r.getDownloadedBytes();
        s.resumeOffset = r.getResumeOffset();
        s.etag = r.getEtag();
        s.packageRevision = r.getPackageRevision();
        snapshotByAttempt.put(attemptKey, s);
        return record(r, new AcceptResult(Disposition.CURRENT, true, s.seq, null, true, true));
      }
      // older but legal: immutable late observation, never becomes current
      return record(r, new AcceptResult(Disposition.LATE_OBSERVATION, true, current.seq, null, true, false));
    }

    private AcceptResult record(Download.DownloadProgressReport r, AcceptResult result) {
      FirstResult first = new FirstResult();
      first.digestHex = r.getEventDigest().getValueHex();
      first.result = result;
      firstByProgressId.putIfAbsent(r.getProgressId(), first);
      if (r.getOccurredAtMs() >= 0) {
        lastOccurredAtMs = r.getOccurredAtMs();
      }
      return result;
    }

    private String secondKey(Download.DownloadProgressReport r) {
      return r.getVehicleTaskId() + "|" + r.getPackageId() + "|"
          + r.getDownloadAttemptNo() + "|" + r.getProgressSeq();
    }

    private static String attemptKey(String vehicleTaskId, String packageId, int attemptNo) {
      return vehicleTaskId + "|" + packageId + "|" + attemptNo;
    }

    private static long latestSeq(Snapshot current) {
      return current == null ? 0 : current.seq;
    }

    private static String validate(Download.DownloadProgressReport r) {
      if (r.getProgressId().isEmpty()) return "PROGRESS_ID_MISSING";
      if (r.getVehicleTaskId().isEmpty()) return "VEHICLE_TASK_ID_MISSING";
      if (r.getPackageId().isEmpty()) return "PACKAGE_ID_MISSING";
      if (r.getPackageRevision().isEmpty()) return "PACKAGE_REVISION_MISSING";
      if (r.getDownloadAttemptNo() < 1) return "DOWNLOAD_ATTEMPT_NO_INVALID";
      if (r.getProgressSeq() < 1) return "PROGRESS_SEQ_INVALID";
      if (r.getTotalBytes() <= 0) return "TOTAL_BYTES_INVALID";
      if (r.getDownloadedBytes() > r.getTotalBytes()) return "DOWNLOADED_BYTES_INVALID";
      if (r.getResumeOffset() > r.getDownloadedBytes()) return "RESUME_OFFSET_INVALID";
      if (r.getOccurredAtMs() < 0) return "OCCURRED_AT_INVALID";
      if (r.getDownloadState() == Download.DownloadState.DOWNLOAD_STATE_UNSPECIFIED
          || r.getDownloadState() == Download.DownloadState.UNRECOGNIZED) {
        return "DOWNLOAD_STATE_UNSUPPORTED";
      }
      if (!r.getEventDigest().getAlgorithm().equals("SHA-256")) return "DIGEST_ALGORITHM_UNSUPPORTED";
      if (!r.getEventDigest().getValueHex().matches("[0-9a-f]{64}")) return "DIGEST_VALUE_INVALID";
      if (r.getDownloadState() == Download.DownloadState.DOWNLOAD_STATE_COMPLETED
          && r.getDownloadedBytes() != r.getTotalBytes()) {
        return "COMPLETED_BYTES_MISMATCH";
      }
      if (r.getDownloadState() == Download.DownloadState.DOWNLOAD_STATE_RESET_OFFSET
          && r.getDownloadedBytes() != r.getResumeOffset()) {
        return "RESET_OFFSET_BASELINE_MISMATCH";
      }
      return null;
    }
  }

  // ===========================================================================
  // helpers
  // ===========================================================================

  private static Download.DownloadProgressReport.Builder base(String progressId, long seq) {
    return Download.DownloadProgressReport.newBuilder()
        .setProgressId(progressId)
        .setVehicleTaskId("VT-CR011")
        .setPackageId("PKG-CR011")
        .setPackageRevision("REV-1")
        .setDownloadAttemptNo(1)
        .setProgressSeq(seq)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_PROGRESS)
        .setDownloadedBytes(0)
        .setTotalBytes(TOTAL)
        .setResumeOffset(0)
        .setOccurredAtMs(T0)
        .setEventDigest(digest(progressId))
        .setEtag("etag-1");
  }

  private static Download.DownloadProgressReport reset(String progressId, long seq, long offset) {
    return base(progressId, seq)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_RESET_OFFSET)
        .setDownloadedBytes(offset)
        .setResumeOffset(offset)
        .build();
  }

  private static Types.Digest digest(String content) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] h = md.digest(content.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(64);
      for (byte b : h) {
        sb.append(Character.forDigit((b >> 4) & 0xF, 16));
        sb.append(Character.forDigit(b & 0xF, 16));
      }
      return Types.Digest.newBuilder().setAlgorithm("SHA-256").setValueHex(sb.toString()).build();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static void expect(String label, AcceptResult r, Disposition disposition,
      boolean accepted, long latestSeq) {
    check(label + " [disposition=" + r.disposition + " accepted=" + r.accepted
            + " latest=" + r.latestAcceptedProgressSeq
            + (r.denyReason == null ? "" : " deny=" + r.denyReason) + "]",
        r.disposition == disposition && r.accepted == accepted
            && r.latestAcceptedProgressSeq == latestSeq);
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
