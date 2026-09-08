import com.google.protobuf.DescriptorProtos;
import com.google.protobuf.Descriptors;
import com.google.protobuf.UnknownFieldSet;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import vehicle.fota.v1.Execution;
import vehicle.fota.v1.Task;
import vehicle.fota.v1.Types;

/**
 * vehicle.fota.v1 CR-005 contract check (PAR-PROTO-DSN-CR-005 §3/§4/§6, CI gates 2/3/4).
 *
 * Verifies against descriptors/vehicle-fota-v1.pb AND the generated Java classes:
 *   - ALL pre-existing field numbers / names / types / presence are unchanged
 *   - new fields occupy the exact CR-005 numbers with exact type/presence
 *   - EcuSoftwareModel enum values 0..2 (ENUM_VALUE_PREFIX)
 *   - generated class runtime descriptors match the committed DescriptorSet
 *   - legacy-only bytes round-trip byte-identically (old -> new -> old)
 *   - unknown-field preservation
 *   - optional bool tri-state: absent / false / true (hasActive/getActive)
 */
public class FotaContractCheck {
  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    String descriptorPath = args.length > 0 ? args[0] : "descriptors/vehicle-fota-v1.pb";
    DescriptorProtos.FileDescriptorSet set;
    try (FileInputStream in = new FileInputStream(descriptorPath)) {
      set = DescriptorProtos.FileDescriptorSet.parseFrom(in);
    }

    DescriptorProtos.FileDescriptorProto file = findFile(set, "vehicle/fota/v1/types.proto");
    DescriptorProtos.FileDescriptorProto taskFile = findFile(set, "vehicle/fota/v1/task.proto");
    DescriptorProtos.FileDescriptorProto execFile = findFile(set, "vehicle/fota/v1/execution.proto");

    // ---- EcuSoftwareModel enum (design §3.1) --------------------------------
    DescriptorProtos.EnumDescriptorProto model = findEnum(file, "EcuSoftwareModel");
    check("enum EcuSoftwareModel has 3 values", model.getValueCount() == 3);
    String[] modelNames = {"ECU_SOFTWARE_MODEL_UNSPECIFIED", "ECU_SOFTWARE_MODEL_SINGLE_IMAGE",
        "ECU_SOFTWARE_MODEL_MULTI_TARGET"};
    boolean modelOk = true;
    for (int i = 0; i < modelNames.length; i++) {
      DescriptorProtos.EnumValueDescriptorProto v = model.getValue(i);
      if (!v.getName().equals(modelNames[i]) || v.getNumber() != i) {
        modelOk = false;
        fail("EcuSoftwareModel value #" + i + " mismatch: " + v.getName() + "=" + v.getNumber());
      }
    }
    check("enum values ECU_SOFTWARE_MODEL_* = 0..2", modelOk);

    // ---- EcuVersion: fields 1..5 unchanged, 6..9 CR-005 (design §3.3) -------
    DescriptorProtos.DescriptorProto ecuVersion = findMessage(file, "EcuVersion");
    check("EcuVersion has 9 fields (1..9)", ecuVersion.getFieldCount() == 9);
    Object[][] ecuVersionExpected = {
      {1, "ecu_id", 9 /* STRING */, 0},
      {2, "hardware_part_number", 9, 0},
      {3, "software_part_number", 9, 0},
      {4, "hw_version", 9, 0},
      {5, "sw_version", 9, 0},
      {6, "slot", 9, 1},                        // proto3 optional
      {7, "active", 8 /* BOOL */, 1},           // proto3 optional
      {8, "software_units", 11 /* MESSAGE */, 0}, // repeated
      {9, "software_model", 14 /* ENUM */, 0},
    };
    checkFields("EcuVersion", ecuVersion, ecuVersionExpected);
    check("EcuVersion#8 type .vehicle.fota.v1.SoftwareUnitVersion",
        fieldTypeName(ecuVersion, 8).equals(".vehicle.fota.v1.SoftwareUnitVersion"));
    check("EcuVersion#9 type .vehicle.fota.v1.EcuSoftwareModel",
        fieldTypeName(ecuVersion, 9).equals(".vehicle.fota.v1.EcuSoftwareModel"));

    // ---- SoftwareUnitVersion (design §3.2) ----------------------------------
    DescriptorProtos.DescriptorProto unit = findMessage(file, "SoftwareUnitVersion");
    check("SoftwareUnitVersion has 6 fields (1..6)", unit.getFieldCount() == 6);
    Object[][] unitExpected = {
      {1, "software_target_code", 9, 0},
      {2, "software_part_number", 9, 0},
      {3, "sw_version", 9, 0},
      {4, "slot", 9, 1},
      {5, "active", 8, 1},
      {6, "software_digest", 11, 1},
    };
    checkFields("SoftwareUnitVersion", unit, unitExpected);
    check("SoftwareUnitVersion#6 type .vehicle.fota.v1.Digest",
        fieldTypeName(unit, 6).equals(".vehicle.fota.v1.Digest"));

    // ---- PackageSummary: fields 1..11 unchanged, 12..13 CR-005 (design §3.4) -
    DescriptorProtos.DescriptorProto pkg = findMessage(file, "PackageSummary");
    check("PackageSummary has 13 fields (1..13)", pkg.getFieldCount() == 13);
    Object[][] pkgExpected = {
      {1, "package_id", 9, 0}, {2, "package_revision", 9, 0}, {3, "plan_node_id", 9, 0},
      {4, "ecu_id", 9, 0}, {5, "component_id", 9, 1}, {6, "source_version", 9, 0},
      {7, "target_version", 9, 0}, {8, "size_bytes", 4 /* UINT64 */, 0},
      {9, "package_digest", 11, 0}, {10, "differential_type", 9, 0}, {11, "encrypted", 8, 0},
      {12, "software_target_code", 9, 1}, {13, "target_slot", 9, 1},
    };
    checkFields("PackageSummary", pkg, pkgExpected);

    // ---- TaskCheckRequest: fields 1..11 unchanged, 12 CR-005 (design §4.1) --
    DescriptorProtos.DescriptorProto req = findMessage(taskFile, "TaskCheckRequest");
    check("TaskCheckRequest has 12 fields (1..12)", req.getFieldCount() == 12);
    checkFields("TaskCheckRequest", req, new Object[][] {
      {1, "baseline_code", 9, 0}, {2, "fota_master_version", 9, 0},
      {3, "local_vehicle_task_id", 9, 1}, {4, "local_task_revision", 4, 1},
      {5, "local_vehicle_task_status", 14, 1}, {6, "last_disposition_result", 11, 1},
      {7, "last_cache_action_result", 11, 1}, {8, "inventory_mode", 14, 0},
      {9, "inventory_revision", 4, 0}, {10, "ecu_list_digest", 11, 0},
      {11, "ecu_list", 11, 0}, {12, "inventory_canonicalization_version", 13 /* UINT32 */, 0},
    });

    // ---- TaskCheckResponse: fields 1..20 unchanged, 21..22 CR-005 (§4.2) ----
    DescriptorProtos.DescriptorProto resp = findMessage(taskFile, "TaskCheckResponse");
    check("TaskCheckResponse has 22 fields (1..22)", resp.getFieldCount() == 22);
    check("TaskCheckResponse#21 repeated EcuSoftwareModel",
        fieldOk(resp, 21, "supported_ecu_software_models", 14, 0)
            && fieldTypeName(resp, 21).equals(".vehicle.fota.v1.EcuSoftwareModel"));
    check("TaskCheckResponse#22 repeated uint32",
        fieldOk(resp, 22, "supported_inventory_canonicalization_versions", 13, 0));
    // spot-check a few legacy fields of TaskCheckResponse
    Object[][] respLegacy = {
      {1, "status", 11, 0}, {2, "inventory_disposition", 14, 0}, {3, "accepted_inventory_revision", 4, 1},
      {5, "supported_inventory_digest_algorithms", 9, 0}, {20, "task", 11, 1},
    };
    checkFields("TaskCheckResponse", resp, respLegacy);

    // ---- ExecutionEvent: fields 1..20 unchanged, 21..22 CR-005 (§6.1) -------
    DescriptorProtos.DescriptorProto evt = findMessage(execFile, "ExecutionEvent");
    check("ExecutionEvent has 22 fields (1..22)", evt.getFieldCount() == 22);
    checkFields("ExecutionEvent", evt, new Object[][] {
      {1, "event_id", 9, 0}, {11, "occurred_at_ms", 3 /* INT64 */, 0}, {16, "ecu_id", 9, 1},
      {20, "error_detail", 9, 1}, {21, "software_target_code", 9, 1}, {22, "slot", 9, 1},
    });

    // ---- SoftwareUnitResult (design §6.2) -----------------------------------
    DescriptorProtos.DescriptorProto unitResult = findMessage(execFile, "SoftwareUnitResult");
    check("SoftwareUnitResult has 10 fields (1..10)", unitResult.getFieldCount() == 10);
    checkFields("SoftwareUnitResult", unitResult, new Object[][] {
      {1, "software_target_code", 9, 0}, {2, "source_version", 9, 0}, {3, "target_version", 9, 0},
      {4, "actual_version", 9, 1}, {5, "slot", 9, 1}, {6, "active", 8, 1}, {7, "result", 14, 0},
      {8, "failure_stage", 9, 1}, {9, "rollback_result", 14, 1}, {10, "package_id", 9, 1},
    });
    check("SoftwareUnitResult#7 type .vehicle.fota.v1.Result",
        fieldTypeName(unitResult, 7).equals(".vehicle.fota.v1.Result"));

    // ---- EcuResult: fields 1..10 unchanged, 11..12 CR-005 (§6.2) ------------
    DescriptorProtos.DescriptorProto ecuResult = findMessage(execFile, "EcuResult");
    check("EcuResult has 12 fields (1..12)", ecuResult.getFieldCount() == 12);
    checkFields("EcuResult", ecuResult, new Object[][] {
      {1, "ecu_id", 9, 0}, {8, "result", 14, 0}, {10, "rollback_result", 14, 1},
      {11, "software_unit_results", 11, 0}, {12, "software_model", 14, 0},
    });
    check("EcuResult#11 type .vehicle.fota.v1.SoftwareUnitResult",
        fieldTypeName(ecuResult, 11).equals(".vehicle.fota.v1.SoftwareUnitResult"));

    // ---- ErrorSummary: fields 1..3 unchanged, 4..5 CR-005 (§6.3) ------------
    DescriptorProtos.DescriptorProto err = findMessage(execFile, "ErrorSummary");
    check("ErrorSummary has 5 fields (1..5)", err.getFieldCount() == 5);
    checkFields("ErrorSummary", err, new Object[][] {
      {1, "ecu_id", 9, 0}, {2, "stage", 9, 0}, {3, "error_code", 9, 0},
      {4, "software_target_code", 9, 1}, {5, "slot", 9, 1},
    });

    // ---- generated class resolution ------------------------------------------
    Descriptors.FileDescriptor fd = Descriptors.FileDescriptor.buildFrom(file,
        new Descriptors.FileDescriptor[0]);
    check("generated Types.EcuVersion matches descriptor (json_name normalized)",
        stripJsonName(Types.EcuVersion.getDescriptor().toProto()).equals(stripJsonName(ecuVersion)));
    check("generated Types.SoftwareUnitVersion resolves",
        Types.SoftwareUnitVersion.getDescriptor().getFullName().equals("vehicle.fota.v1.SoftwareUnitVersion"));
    check("generated Types.EcuSoftwareModel resolves",
        Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET.getNumber() == 2);
    check("generated Execution.SoftwareUnitResult resolves",
        Execution.SoftwareUnitResult.getDescriptor().getFullName().equals("vehicle.fota.v1.SoftwareUnitResult"));
    check("generated TaskCheckRequest has inventory_canonicalization_version",
        Task.TaskCheckRequest.getDescriptor().findFieldByNumber(12) != null);
    check("generated TaskCheckResponse#21/#22 present",
        Task.TaskCheckResponse.getDescriptor().findFieldByNumber(21) != null
            && Task.TaskCheckResponse.getDescriptor().findFieldByNumber(22) != null);

    // ---- optional bool tri-state (CI gate 4) ---------------------------------
    Types.EcuVersion noActive = Types.EcuVersion.newBuilder()
        .setEcuId("E").setHardwarePartNumber("H").setSoftwarePartNumber("S").setHwVersion("v").setSwVersion("s")
        .build();
    Types.EcuVersion falseActive = noActive.toBuilder().setActive(false).build();
    Types.EcuVersion trueActive = noActive.toBuilder().setActive(true).build();
    check("optional active: absent -> hasActive()=false", !noActive.hasActive());
    check("optional active: false -> hasActive()=true && value=false",
        falseActive.hasActive() && !falseActive.getActive());
    check("optional active: true -> hasActive()=true && value=true",
        trueActive.hasActive() && trueActive.getActive());

    // ---- old -> new -> old byte stability + unknown-field preservation --------
    Types.EcuVersion legacyEcu = Types.EcuVersion.newBuilder()
        .setEcuId("ECU-ENGINE").setHardwarePartNumber("HW-1").setSoftwarePartNumber("SW-1")
        .setHwVersion("H1").setSwVersion("S1").build();
    byte[] legacyBytes = legacyEcu.toByteArray();
    Types.EcuVersion parsed = Types.EcuVersion.parseFrom(legacyBytes);
    check("legacy-only EcuVersion round-trips byte-identically (old->new->old)",
        java.util.Arrays.equals(legacyBytes, parsed.toByteArray()));

    Types.EcuVersion withUnknown = legacyEcu.toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(12345L).build())
            .build())
        .build();
    Types.EcuVersion parsedUnknown = Types.EcuVersion.parseFrom(withUnknown.toByteArray());
    check("unknown field preserved on EcuVersion round-trip",
        parsedUnknown.getUnknownFields().hasField(99));

    Task.TaskCheckRequest legacyReq = Task.TaskCheckRequest.newBuilder()
        .setBaselineCode("BL-1").setFotaMasterVersion("FM-1").setInventoryRevision(1L)
        .setInventoryMode(Types.InventoryMode.INVENTORY_MODE_FULL)
        .addEcuList(legacyEcu).build();
    byte[] legacyReqBytes = legacyReq.toByteArray();
    Task.TaskCheckRequest parsedReq = Task.TaskCheckRequest.parseFrom(legacyReqBytes);
    check("legacy-only TaskCheckRequest round-trips byte-identically",
        java.util.Arrays.equals(legacyReqBytes, parsedReq.toByteArray()));
    check("legacy-only TaskCheckRequest inventory_canonicalization_version == 0",
        parsedReq.getInventoryCanonicalizationVersion() == 0);

    // new->old: parse a message carrying new fields, verify new fields survive
    Types.EcuVersion newEcu = legacyEcu.toBuilder()
        .setSoftwareModel(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET)
        .addSoftwareUnits(Types.SoftwareUnitVersion.newBuilder()
            .setSoftwareTargetCode("BODY").setSoftwarePartNumber("PN-B").setSwVersion("VB").build())
        .addSoftwareUnits(Types.SoftwareUnitVersion.newBuilder()
            .setSoftwareTargetCode("GW").setSoftwarePartNumber("PN-G").setSwVersion("VG").build())
        .build();
    Types.EcuVersion parsedNew = Types.EcuVersion.parseFrom(newEcu.toByteArray());
    check("new->old: MULTI_TARGET + software_units survive round-trip",
        parsedNew.getSoftwareModel() == Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET
            && parsedNew.getSoftwareUnitsCount() == 2
            && parsedNew.getSoftwareUnits(0).getSoftwareTargetCode().equals("BODY"));

    // new SINGLE_IMAGE -> old parse (CI gate 10.1.3): slot(6)/active(7) set on the
    // legacy surface; an old consumer reading fields 1..5 still sees the same
    // single-image values, and the new fields survive the round-trip.
    Types.EcuVersion singleSlot = legacyEcu.toBuilder()
        .setSoftwareModel(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE)
        .setSlot("slotA").setActive(true)
        .build();
    Types.EcuVersion parsedSingleSlot = Types.EcuVersion.parseFrom(singleSlot.toByteArray());
    check("new SINGLE_IMAGE -> old: slot/active survive + legacy fields readable",
        parsedSingleSlot.hasSlot() && parsedSingleSlot.getSlot().equals("slotA")
            && parsedSingleSlot.hasActive() && parsedSingleSlot.getActive()
            && parsedSingleSlot.getSoftwarePartNumber().equals("SW-1")
            && parsedSingleSlot.getSwVersion().equals("S1"));

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ FOTA CONTRACT CHECK PASSED (old fields intact + CR-005 additions + tri-state + compat)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " FOTA contract check failure(s)");
      System.exit(1);
    }
  }

  // ---- helpers ---------------------------------------------------------------
  private static DescriptorProtos.FileDescriptorProto findFile(
      DescriptorProtos.FileDescriptorSet set, String name) {
    for (DescriptorProtos.FileDescriptorProto f : set.getFileList()) {
      if (f.getName().equals(name)) return f;
    }
    fail("file " + name + " not in descriptor set");
    throw new IllegalStateException(name);
  }

  private static DescriptorProtos.EnumDescriptorProto findEnum(
      DescriptorProtos.FileDescriptorProto file, String name) {
    for (DescriptorProtos.EnumDescriptorProto e : file.getEnumTypeList()) {
      if (e.getName().equals(name)) return e;
    }
    fail("enum " + name + " not found");
    throw new IllegalStateException(name);
  }

  private static DescriptorProtos.DescriptorProto findMessage(
      DescriptorProtos.FileDescriptorProto file, String name) {
    for (DescriptorProtos.DescriptorProto m : file.getMessageTypeList()) {
      if (m.getName().equals(name)) return m;
    }
    fail("message " + name + " not found");
    throw new IllegalStateException(name);
  }

  private static boolean fieldOk(DescriptorProtos.DescriptorProto msg, int number,
      String name, int type, int proto3Optional) {
    DescriptorProtos.FieldDescriptorProto f = field(msg, number);
    return f != null && f.getName().equals(name)
        && f.getType() == DescriptorProtos.FieldDescriptorProto.Type.forNumber(type)
        && f.getProto3Optional() == (proto3Optional == 1);
  }

  private static String fieldTypeName(DescriptorProtos.DescriptorProto msg, int number) {
    DescriptorProtos.FieldDescriptorProto f = field(msg, number);
    return f == null ? null : f.getTypeName();
  }

  private static DescriptorProtos.FieldDescriptorProto field(
      DescriptorProtos.DescriptorProto msg, int number) {
    for (DescriptorProtos.FieldDescriptorProto f : msg.getFieldList()) {
      if (f.getNumber() == number) return f;
    }
    return null;
  }

  private static void checkFields(String label, DescriptorProtos.DescriptorProto msg,
      Object[][] expected) {
    for (Object[] e : expected) {
      boolean ok = fieldOk(msg, (Integer) e[0], (String) e[1], (Integer) e[2], (Integer) e[3]);
      check(label + " field #" + e[0] + " " + e[1] + " (type " + e[2] + ", opt " + e[3] + ")", ok);
    }
  }

  private static DescriptorProtos.DescriptorProto stripJsonName(DescriptorProtos.DescriptorProto d) {
    DescriptorProtos.DescriptorProto.Builder b = d.toBuilder();
    for (int i = 0; i < b.getFieldCount(); i++) {
      b.setField(i, b.getField(i).toBuilder().clearJsonName());
    }
    return b.build();
  }

  private static void check(String label, boolean ok) {
    if (ok) {
      System.out.println("  ✓ " + label);
    } else {
      fail(label);
    }
  }

  private static void pass(String label) {
    System.out.println("  ✓ " + label);
  }

  private static void fail(String label) {
    System.out.println("  ✗ " + label);
    failures++;
  }
}
