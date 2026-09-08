import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import vehicle.fota.v1.Types;

/**
 * EcuVersion legal-combination matrix + conflict negatives
 * (PAR-PROTO-DSN-CR-005 §3.4/§3.5/§10.2, CI gate 10.2).
 *
 * Legal combos (design §3.4):
 *   UNSPECIFIED : legacy PN/version non-empty, software_units EMPTY (legacy only,
 *                 normalized to SINGLE_IMAGE; compatible exception for legacy producers)
 *   SINGLE_IMAGE: legacy PN/version non-empty, software_units EMPTY (uses fields 3/5/6/7)
 *   MULTI_TARGET: legacy PN/version/slot/active ALL empty, software_units 1..N
 *                 (>=1 unit; whether >=2 distinct targets are required is a business
 *                 capability decision, NOT inferred from array length — design §3.5)
 *
 * Conflicts (reject): MULTI_TARGET with any legacy software field; UNSPECIFIED carrying
 * units (no guessing); SINGLE_IMAGE carrying units (single image uses only legacy
 * fields 3/5/6/7); active=false without slot; duplicate target/slot; dual active; zero
 * active in a multi-slot group; empty target/PN/version.
 */
public class EcuVersionComboCheck {
  private static int failures = 0;

  /** Validates one EcuVersion; returns violations (empty = legal). */
  public static List<String> validate(Types.EcuVersion e) {
    List<String> errs = new ArrayList<>();
    Types.EcuSoftwareModel model = e.getSoftwareModel();
    boolean legacyNonEmpty = !e.getSoftwarePartNumber().isEmpty() && !e.getSwVersion().isEmpty();
    boolean legacySoftwareSet = !e.getSoftwarePartNumber().isEmpty() || !e.getSwVersion().isEmpty();
    List<Types.SoftwareUnitVersion> units = e.getSoftwareUnitsList();

    switch (model) {
      case ECU_SOFTWARE_MODEL_UNSPECIFIED:
        if (!legacyNonEmpty) errs.add("UNSPECIFIED requires legacy software_part_number + sw_version");
        if (!units.isEmpty()) errs.add("UNSPECIFIED must not carry software_units (no guessing)");
        break;

      case ECU_SOFTWARE_MODEL_SINGLE_IMAGE:
        if (!legacyNonEmpty) errs.add("SINGLE_IMAGE requires legacy software_part_number + sw_version");
        if (!units.isEmpty()) {
          errs.add("SINGLE_IMAGE must not carry software_units (single image uses legacy fields 3/5/6/7 only)");
        }
        if (e.hasActive() && !e.getActive() && !e.hasSlot()) {
          errs.add("active=false requires slot");
        }
        break;

      case ECU_SOFTWARE_MODEL_MULTI_TARGET:
        if (legacySoftwareSet || e.hasSlot() || e.hasActive()) {
          errs.add("MULTI_TARGET must leave legacy software/slot/active empty");
        }
        if (units.isEmpty()) errs.add("MULTI_TARGET requires at least one software unit");
        // distinct-target count is a business capability decision, not a proto rule
        break;

      default:
        errs.add("unknown software_model");
    }

    // ---- unit-level constraints (design §3.5 / §10.2) ------------------------
    if (!units.isEmpty()) {
      Set<String> seen = new LinkedHashSet<>();
      for (Types.SoftwareUnitVersion u : units) {
        if (u.getSoftwareTargetCode().isEmpty()) errs.add("unit software_target_code must be non-empty");
        if (u.getSoftwarePartNumber().isEmpty()) errs.add("unit software_part_number must be non-empty");
        if (u.getSwVersion().isEmpty()) errs.add("unit sw_version must be non-empty");
        String key = u.getSoftwareTargetCode() + "\u0000" + (u.hasSlot() ? u.getSlot() : "");
        if (!seen.add(key)) {
          errs.add("duplicate (target, slot): " + u.getSoftwareTargetCode()
              + (u.hasSlot() ? "/" + u.getSlot() : ""));
        }
        if (u.hasActive() && !u.getActive() && !u.hasSlot()) {
          errs.add("unit active=false requires slot (target=" + u.getSoftwareTargetCode() + ")");
        }
      }
      // multi-slot target groups must have exactly one active=true (design §3.5)
      Set<String> targets = new LinkedHashSet<>();
      for (Types.SoftwareUnitVersion u : units) targets.add(u.getSoftwareTargetCode());
      for (String t : targets) {
        List<Types.SoftwareUnitVersion> group = new ArrayList<>();
        boolean multiSlot = false;
        for (Types.SoftwareUnitVersion u : units) {
          if (u.getSoftwareTargetCode().equals(t)) {
            group.add(u);
            if (u.hasSlot()) multiSlot = true;
          }
        }
        if (multiSlot && group.size() >= 2) {
          int activeCount = 0;
          for (Types.SoftwareUnitVersion u : group) {
            if (u.hasSlot() && !u.hasActive()) {
              errs.add("target " + t + " multi-slot unit requires explicit active presence");
            }
            if (u.hasActive() && u.getActive()) activeCount++;
          }
          if (activeCount != 1) {
            errs.add("target " + t + " must have exactly one active=true (got " + activeCount + ")");
          }
        }
      }
    }
    return errs;
  }

  public static void main(String[] args) {
    // ---- legal positives (design §10.2) --------------------------------------
    expectLegal("legacy UNSPECIFIED (fields 1..5 only)",
        ecu(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_UNSPECIFIED, "SW-1", "S1", null, null));
    expectLegal("explicit SINGLE_IMAGE (fields 1..5)",
        ecu(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE, "SW-1", "S1", null, null));
    expectLegal("SINGLE_IMAGE + slot (fields 3/5/6/7)",
        ecu(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE, "SW-1", "S1", "slotA", true));
    expectLegal("MULTI_TARGET three distinct targets",
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("BODY", "PN-B", "VB", null, true),
            unit("GW", "PN-G", "VG", null, true),
            unit("HPC", "PN-H", "VH", null, true)));
    expectLegal("MULTI_TARGET single distinct target (capability-driven)",
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("BODY", "PN-B", "VB", null, true)));
    expectLegal("MULTI_TARGET + A/B dual slot (same target, one active)",
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("ECU_IMAGE", "SW-1", "S1", "slotA", true),
            unit("ECU_IMAGE", "SW-0", "S0", "slotB", false)));

    // ---- mixed ECU in one list (design §3.1 / §10.2) -------------------------
    List<Types.EcuVersion> mixed = new ArrayList<>();
    mixed.add(ecu(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE, "SW-1", "S1", null, null));
    mixed.add(ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
        unit("BODY", "PN-B", "VB", null, true),
        unit("GW", "PN-G", "VG", null, true)));
    expectLegal("mixed ECU list (SINGLE_IMAGE + MULTI_TARGET)", mixed);

    // ---- conflict negatives (design §10.2) -----------------------------------
    expectIllegal("MULTI_TARGET carries legacy software", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "SW-LEGACY", "S9", null,
            unit("BODY", "PN-B", "VB", null, true),
            unit("GW", "PN-G", "VG", null, true)));
    expectIllegal("MULTI_TARGET carries legacy slot", 1,
        ecuSlot(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", "slotA", true));
    expectIllegal("MULTI_TARGET carries legacy active", 1,
        ecuSlot(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null, false));
    expectIllegal("MULTI_TARGET without units", 1,
        ecu(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null, null));
    expectIllegal("UNSPECIFIED carries units", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_UNSPECIFIED, "SW-1", "S1", null,
            unit("ECU_IMAGE", "SW-1", "S1", null, true)));
    expectIllegal("SINGLE_IMAGE carries units", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE, "SW-1", "S1", null,
            unit("ECU_IMAGE", "SW-1", "S1", null, true)));
    expectIllegal("SINGLE_IMAGE legacy missing", 1,
        ecu(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE, "", "", null, null));
    expectIllegal("active=false without slot (EcuVersion)", 1,
        ecuSlot(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE, "SW-1", "S1", null, false));
    expectIllegal("duplicate (target, slot)", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("BODY", "PN-B", "VB", "slotA", true),
            unit("BODY", "PN-B2", "VB2", "slotA", false)));
    expectIllegal("dual active (multi-slot)", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("ECU_IMAGE", "SW-1", "S1", "slotA", true),
            unit("ECU_IMAGE", "SW-0", "S0", "slotB", true)));
    expectIllegal("zero active (multi-slot)", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("ECU_IMAGE", "SW-1", "S1", "slotA", false),
            unit("ECU_IMAGE", "SW-0", "S0", "slotB", false)));
    expectIllegal("multi-slot missing active", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("ECU_IMAGE", "SW-1", "S1", "slotA", true),
            unit("ECU_IMAGE", "SW-0", "S0", "slotB", null)));
    expectIllegal("empty target", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("", "PN-B", "VB", null, true)));
    expectIllegal("empty unit PN/version", 1,
        ecuWithUnit(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET, "", "", null,
            unit("BODY", "", "VB", null, true)));

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ ECU VERSION COMBO CHECK PASSED (legal matrix + conflict negatives + mixed ECU)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " combo check failure(s)");
      System.exit(1);
    }
  }

  private static void expectLegal(String label, Types.EcuVersion e) {
    List<String> errs = validate(e);
    if (errs.isEmpty()) {
      pass(label);
    } else {
      fail(label + " -> " + errs);
    }
  }

  private static void expectLegal(String label, List<Types.EcuVersion> list) {
    List<String> all = new ArrayList<>();
    for (Types.EcuVersion e : list) all.addAll(validate(e));
    if (all.isEmpty()) {
      pass(label);
    } else {
      fail(label + " -> " + all);
    }
  }

  private static void expectIllegal(String label, int minErrors, Types.EcuVersion e) {
    List<String> errs = validate(e);
    if (errs.size() >= minErrors) {
      pass(label);
    } else {
      fail(label + " expected >= " + minErrors + " violation(s), got " + errs);
    }
  }

  // ---- builders ------------------------------------------------------------
  private static Types.EcuVersion ecu(Types.EcuSoftwareModel model, String pn, String ver,
      String slot, Boolean active) {
    Types.EcuVersion.Builder b = Types.EcuVersion.newBuilder()
        .setEcuId("ECU-X").setHardwarePartNumber("HW-1").setHwVersion("H1")
        .setSoftwarePartNumber(pn).setSwVersion(ver)
        .setSoftwareModel(model);
    if (slot != null) b.setSlot(slot);
    if (active != null) b.setActive(active);
    return b.build();
  }

  private static Types.EcuVersion ecuSlot(Types.EcuSoftwareModel model, String pn, String ver,
      String slot, Boolean active) {
    return ecu(model, pn, ver, slot, active);
  }

  private static Types.EcuVersion ecuWithUnit(Types.EcuSoftwareModel model, String pn, String ver,
      String slot, Types.SoftwareUnitVersion... units) {
    Types.EcuVersion.Builder b = Types.EcuVersion.newBuilder()
        .setEcuId("ECU-X").setHardwarePartNumber("HW-1").setHwVersion("H1")
        .setSoftwarePartNumber(pn).setSwVersion(ver)
        .setSoftwareModel(model);
    if (slot != null) b.setSlot(slot);
    for (Types.SoftwareUnitVersion u : units) b.addSoftwareUnits(u);
    return b.build();
  }

  private static Types.SoftwareUnitVersion unit(String target, String pn, String ver,
      String slot, Boolean active) {
    Types.SoftwareUnitVersion.Builder b = Types.SoftwareUnitVersion.newBuilder()
        .setSoftwareTargetCode(target).setSoftwarePartNumber(pn).setSwVersion(ver);
    if (slot != null) b.setSlot(slot);
    if (active != null) b.setActive(active);
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
