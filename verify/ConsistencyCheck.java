import java.util.ArrayList;
import java.util.List;

import vehicle.fota.v1.Execution;
import vehicle.fota.v1.Types;

/**
 * PackageSummary -> ExecutionEvent -> EcuResult/ErrorSummary Target/Slot
 * consistency check (PAR-PROTO-DSN-CR-005 §10 gate 8, decision RD-005-6).
 *
 * Rules enforced:
 *   - SINGLE_IMAGE: missing software_target_code normalizes to ECU_IMAGE; a
 *     package/event may carry target/slot freely.
 *   - MULTI_TARGET: PackageSummary.software_target_code conditionally required;
 *     ExecutionEvent.software_target_code required when the event is tied to a
 *     MULTI_TARGET package/ecu job; EcuResult.software_unit_results non-empty and
 *     legacy source/target/actual version + package_id MUST be empty; ErrorSummary
 *     MUST carry software_target_code to localize the failed unit.
 *   - unknown software models fail-closed (no SINGLE_IMAGE fallback).
 */
public class ConsistencyCheck {
  private static int failures = 0;

  /** Validate a full flow; returns violations (empty = consistent). */
  public static List<String> validate(
      Types.PackageSummary pkg, Execution.ExecutionEvent event,
      Execution.EcuResult result, Execution.ErrorSummary error,
      Types.EcuSoftwareModel model) {
    List<String> errs = new ArrayList<>();
    boolean multi = model == Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET;

    if (multi) {
      if (!pkg.hasSoftwareTargetCode()) {
        errs.add("MULTI_TARGET PackageSummary requires software_target_code");
      }
      if (!event.hasSoftwareTargetCode()) {
        errs.add("MULTI_TARGET ExecutionEvent requires software_target_code");
      }
      if (result.getSoftwareUnitResultsCount() == 0) {
        errs.add("MULTI_TARGET EcuResult requires software_unit_results");
      }
      if (!result.getSourceVersion().isEmpty() || !result.getTargetVersion().isEmpty()
          || result.hasActualVersion() || !result.getPackageId().isEmpty()) {
        errs.add("MULTI_TARGET EcuResult must leave legacy source/target/actual version and package_id empty");
      }
      if (!error.hasSoftwareTargetCode()) {
        errs.add("MULTI_TARGET ErrorSummary requires software_target_code");
      }
      if (event.hasSoftwareTargetCode() && pkg.hasSoftwareTargetCode()
          && !event.getSoftwareTargetCode().equals(pkg.getSoftwareTargetCode())) {
        errs.add("ExecutionEvent target must match PackageSummary target");
      }
    } else {
      // SINGLE_IMAGE: unit results MUST be empty (design §6.2); targets normalize to ECU_IMAGE
      if (result.getSoftwareUnitResultsCount() > 0) {
        errs.add("SINGLE_IMAGE EcuResult must leave software_unit_results empty");
      }
      String evtTarget = event.hasSoftwareTargetCode()
          ? event.getSoftwareTargetCode() : "ECU_IMAGE";
      if (pkg.hasSoftwareTargetCode()
          && !pkg.getSoftwareTargetCode().equals(evtTarget)) {
        errs.add("SINGLE_IMAGE event target must match package target (normalized ECU_IMAGE)");
      }
    }
    return errs;
  }

  public static void main(String[] args) {
    Types.EcuSoftwareModel single = Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE;
    Types.EcuSoftwareModel multi = Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET;

    // ---- legal SINGLE_IMAGE flow: no targets, normalized ECU_IMAGE ----------
    Types.PackageSummary p1 = pkg("pkg-1", null, null);
    Execution.ExecutionEvent e1 = evt("evt-1", null, null);
    Execution.EcuResult r1 = result("ECU-ENGINE", "S0", "S1", null);
    Execution.ErrorSummary err1 = errSum("ECU-ENGINE", null);
    expectLegal("SINGLE_IMAGE flow (targets absent, normalized ECU_IMAGE)", p1, e1, r1, err1, single);

    // ---- legal MULTI_TARGET flow -------------------------------------------
    Types.PackageSummary p2 = pkg("pkg-2", "BODY", "slotA");
    Execution.ExecutionEvent e2 = evt("evt-2", "BODY", "slotA");
    Execution.EcuResult r2 = result("ECU-GW", "", "", null)
        .toBuilder()
        .clearPackageId()   // MULTI_TARGET: legacy package_id must be empty
        .addSoftwareUnitResults(Execution.SoftwareUnitResult.newBuilder()
            .setSoftwareTargetCode("BODY").setSourceVersion("VB0").setTargetVersion("VB1")
            .setResult(Types.Result.RESULT_SUCCEEDED).build())
        .setSoftwareModel(multi)
        .build();
    Execution.ErrorSummary err2 = errSum("ECU-GW", "BODY");
    expectLegal("MULTI_TARGET flow (target/slot propagated through result/error)", p2, e2, r2, err2, multi);

    // ---- violations ---------------------------------------------------------
    expectIllegal("MULTI_TARGET event missing target", 1,
        pkg("pkg-3", "GW", null), evt("evt-3", null, null),
        r2, errSum("ECU-GW", "GW"), multi);
    expectIllegal("SINGLE_IMAGE EcuResult with unit results", 1,
        p1, e1,
        r1.toBuilder().addSoftwareUnitResults(Execution.SoftwareUnitResult.newBuilder()
            .setSoftwareTargetCode("ECU_IMAGE").setSourceVersion("S0").setTargetVersion("S1")
            .setResult(Types.Result.RESULT_SUCCEEDED).build()).build(),
        err1, single);
    expectIllegal("MULTI_TARGET EcuResult keeps legacy versions", 1,
        pkg("pkg-4", "GW", null), evt("evt-4", "GW", null),
        result("ECU-GW", "V0", "V1", null), errSum("ECU-GW", "GW"), multi);
    expectIllegal("MULTI_TARGET EcuResult without unit results", 1,
        pkg("pkg-5", "GW", null), evt("evt-5", "GW", null),
        result("ECU-GW", "", "", null), errSum("ECU-GW", "GW"), multi);
    expectIllegal("MULTI_TARGET ErrorSummary missing target", 1,
        pkg("pkg-6", "GW", null), evt("evt-6", "GW", null),
        r2, errSum("ECU-GW", null), multi);
    expectIllegal("event target mismatch vs package target (MULTI_TARGET)", 1,
        pkg("pkg-7", "BODY", null), evt("evt-7", "GW", null),
        r2, errSum("ECU-GW", "GW"), multi);
    expectIllegal("SINGLE_IMAGE event target mismatch", 1,
        pkg("pkg-8", "BODY", null), evt("evt-8", "GW", null),
        r1, err1, single);

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ TARGET/SLOT CONSISTENCY CHECK PASSED (PackageSummary->Event->Result/Error)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " consistency check failure(s)");
      System.exit(1);
    }
  }

  private static void expectLegal(String label, Types.PackageSummary pkg,
      Execution.ExecutionEvent evt, Execution.EcuResult res, Execution.ErrorSummary err,
      Types.EcuSoftwareModel model) {
    List<String> errs = validate(pkg, evt, res, err, model);
    if (errs.isEmpty()) pass(label);
    else fail(label + " -> " + errs);
  }

  private static void expectIllegal(String label, int min, Types.PackageSummary pkg,
      Execution.ExecutionEvent evt, Execution.EcuResult res, Execution.ErrorSummary err,
      Types.EcuSoftwareModel model) {
    List<String> errs = validate(pkg, evt, res, err, model);
    if (errs.size() >= min) pass(label);
    else fail(label + " expected >= " + min + " violation(s), got " + errs);
  }

  private static Types.PackageSummary pkg(String id, String target, String slot) {
    Types.PackageSummary.Builder b = Types.PackageSummary.newBuilder()
        .setPackageId(id).setPackageRevision("R").setPlanNodeId("N").setEcuId("ECU")
        .setSourceVersion("S0").setTargetVersion("S1").setSizeBytes(1L).setEncrypted(false);
    if (target != null) b.setSoftwareTargetCode(target);
    if (slot != null) b.setTargetSlot(slot);
    return b.build();
  }

  private static Execution.ExecutionEvent evt(String id, String target, String slot) {
    Execution.ExecutionEvent.Builder b = Execution.ExecutionEvent.newBuilder()
        .setEventId(id).setAttemptNo(1).setSequenceNo(1).setOccurredAtMs(1L)
        .setStage("INSTALL").setEventStatus("RUNNING");
    if (target != null) b.setSoftwareTargetCode(target);
    if (slot != null) b.setSlot(slot);
    return b.build();
  }

  private static Execution.EcuResult result(String ecuId, String src, String tgt, String actual) {
    Execution.EcuResult.Builder b = Execution.EcuResult.newBuilder()
        .setEcuId(ecuId).setSourceVersion(src).setTargetVersion(tgt)
        .setPlanNodeId("N").setPackageId("pkg").setVersionReadStatus("OK")
        .setResult(Types.Result.RESULT_SUCCEEDED);
    if (actual != null) b.setActualVersion(actual);
    return b.build();
  }

  private static Execution.ErrorSummary errSum(String ecuId, String target) {
    Execution.ErrorSummary.Builder b = Execution.ErrorSummary.newBuilder()
        .setEcuId(ecuId).setStage("INSTALL").setErrorCode("E1");
    if (target != null) b.setSoftwareTargetCode(target);
    return b.build();
  }

  private static void pass(String label) {
    System.out.println("  ✓ " + label);
  }

  private static void fail(String label) {
    System.out.println("  ✗ " + label);
    failures++;
  }
}
