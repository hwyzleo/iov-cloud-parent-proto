import com.google.protobuf.DescriptorProtos;
import com.google.protobuf.Descriptors;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import vagw.v1.Delivery;

/**
 * VAGW contract check (PAR-PROTO-DSN-CR-003 §9 acceptance #1/#3 / §6 gate 3).
 *
 * Validates against the committed normalized DescriptorSet
 * (descriptors/vagw-delivery-v1.pb) and the generated Java classes:
 *   - file vagw/v1/delivery.proto, package vagw.v1, message GatewayDeliveryStatus
 *   - field numbers 1..9 with exact names/types (wire stability)
 *   - optional presence (proto3_optional) on fields 2 and 8
 *   - enum Outcome values 0..3 with exact names incl. ENUM_VALUE_PREFIX
 *   - generated Java outer class vagw.v1.Delivery + message + enum resolution
 *   - unknown-field and unknown-enum preservation round-trip (byte stability)
 */
public class VagwContractCheck {
  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    String descriptorPath = args.length > 0 ? args[0] : "descriptors/vagw-delivery-v1.pb";

    // ---- Descriptor-level contract -------------------------------------------------
    DescriptorProtos.FileDescriptorSet set;
    try (FileInputStream in = new FileInputStream(descriptorPath)) {
      set = DescriptorProtos.FileDescriptorSet.parseFrom(in);
    }
    if (set.getFileCount() != 1 || !set.getFile(0).getName().equals("vagw/v1/delivery.proto")) {
      fail("descriptor must contain exactly vagw/v1/delivery.proto");
    } else {
      pass("descriptor contains vagw/v1/delivery.proto");
    }
    DescriptorProtos.FileDescriptorProto file = set.getFile(0);
    check("package is vagw.v1", file.getPackage().equals("vagw.v1"));
    if (file.getMessageTypeCount() != 1
        || !file.getMessageType(0).getName().equals("GatewayDeliveryStatus")) {
      fail("message GatewayDeliveryStatus not found");
    } else {
      pass("message GatewayDeliveryStatus found");
    }

    DescriptorProtos.DescriptorProto msg = file.getMessageType(0);
    check("message has 9 fields (1..9)", msg.getFieldCount() == 9);

    Map<Integer, DescriptorProtos.FieldDescriptorProto> byNumber = new HashMap<>();
    for (DescriptorProtos.FieldDescriptorProto f : msg.getFieldList()) {
      byNumber.put(f.getNumber(), f);
    }
    int[][] expected = {
      {1, DescriptorProtos.FieldDescriptorProto.Type.TYPE_STRING_VALUE, 0},
      {2, DescriptorProtos.FieldDescriptorProto.Type.TYPE_STRING_VALUE, 1}, // proto3_optional
      {3, DescriptorProtos.FieldDescriptorProto.Type.TYPE_STRING_VALUE, 0},
      {4, DescriptorProtos.FieldDescriptorProto.Type.TYPE_STRING_VALUE, 0},
      {5, DescriptorProtos.FieldDescriptorProto.Type.TYPE_ENUM_VALUE, 0},
      {6, DescriptorProtos.FieldDescriptorProto.Type.TYPE_STRING_VALUE, 0},
      {7, DescriptorProtos.FieldDescriptorProto.Type.TYPE_BOOL_VALUE, 0},
      {8, DescriptorProtos.FieldDescriptorProto.Type.TYPE_INT64_VALUE, 1},  // proto3_optional
      {9, DescriptorProtos.FieldDescriptorProto.Type.TYPE_INT64_VALUE, 0},
    };
    String[] expectedNames = {"original_message_id", "correlation_id", "vin", "stage",
        "outcome", "reason", "retryable", "retry_after_ms", "occurred_at_ms"};
    boolean fieldsOk = true;
    for (int i = 0; i < expected.length; i++) {
      DescriptorProtos.FieldDescriptorProto f = byNumber.get(expected[i][0]);
      if (f == null) {
        fieldsOk = false;
        fail("field #" + expected[i][0] + " missing");
        continue;
      }
      boolean ok = f.getName().equals(expectedNames[i])
          && f.getType() == DescriptorProtos.FieldDescriptorProto.Type.forNumber(expected[i][1])
          && f.getProto3Optional() == (expected[i][2] == 1);
      if (!ok) {
        fieldsOk = false;
        fail("field #" + expected[i][0] + " " + expectedNames[i]
            + " mismatch (type/name/optional)");
      }
    }
    check("field numbers 1..9, names, types and optional presence", fieldsOk);
    DescriptorProtos.FieldDescriptorProto outcome = byNumber.get(5);
    check("field #5 outcome references .vagw.v1.Outcome",
        outcome != null && outcome.getTypeName().equals(".vagw.v1.Outcome"));

    if (file.getEnumTypeCount() != 1 || !file.getEnumType(0).getName().equals("Outcome")) {
      fail("enum Outcome not found");
    } else {
      pass("enum Outcome found");
    }
    DescriptorProtos.EnumDescriptorProto outcomeEnum = file.getEnumType(0);
    check("enum Outcome has 4 values (0..3)", outcomeEnum.getValueCount() == 4);
    String[] expectedEnum = {"OUTCOME_UNSPECIFIED", "OUTCOME_ACCEPTED", "OUTCOME_REJECTED", "OUTCOME_UNKNOWN"};
    boolean enumOk = true;
    for (int i = 0; i < expectedEnum.length; i++) {
      DescriptorProtos.EnumValueDescriptorProto v = outcomeEnum.getValue(i);
      if (!v.getName().equals(expectedEnum[i]) || v.getNumber() != i) {
        enumOk = false;
        fail("enum value #" + i + " mismatch: got " + v.getName() + "=" + v.getNumber());
      }
    }
    check("enum values OUTCOME_* = 0..3 (ENUM_VALUE_PREFIX)", enumOk);

    // ---- Generated Java class resolution -------------------------------------------
    Descriptors.FileDescriptor fd = Descriptors.FileDescriptor.buildFrom(file,
        new Descriptors.FileDescriptor[0]);
    Descriptors.Descriptor gds = fd.findMessageTypeByName("GatewayDeliveryStatus");
    Descriptors.EnumDescriptor oc = fd.findEnumTypeByName("Outcome");
    // Structural equality: the generated class's runtime descriptor must match the
    // committed DescriptorSet (message proto + enum proto) exactly. json_name is a
    // derived JSON mapping (present in protoc CLI descriptor sets, absent from the
    // embedded descriptor in generated Java) — normalized out of the comparison.
    Descriptors.Descriptor gen = Delivery.GatewayDeliveryStatus.getDescriptor();
    check("generated class vagw.v1.Delivery resolves",
        Delivery.class.getSimpleName().equals("Delivery")
            && gen.getFile().getPackage().equals("vagw.v1")
            && stripJsonName(gen.toProto()).equals(stripJsonName(msg)));
    Descriptors.EnumDescriptor genEnum = Delivery.Outcome.getDescriptor();
    check("generated enum resolves",
        genEnum.getFullName().equals("vagw.v1.Outcome")
            && genEnum.toProto().equals(outcomeEnum));

    // ---- Unknown-field / unknown-enum preservation round-trip -----------------------
    Delivery.GatewayDeliveryStatus base = Delivery.GatewayDeliveryStatus.newBuilder()
        .setOriginalMessageId("msg-x").setVin("VIN-X").setStage("S")
        .setOutcome(Delivery.Outcome.OUTCOME_ACCEPTED).setReason("R")
        .setRetryable(false).setOccurredAtMs(1L).build();
    Delivery.GatewayDeliveryStatus unknownField = base.toBuilder()
        .setUnknownFields(com.google.protobuf.UnknownFieldSet.newBuilder()
            .addField(99, com.google.protobuf.UnknownFieldSet.Field.newBuilder().addVarint(7L).build())
            .build())
        .build();
    Delivery.GatewayDeliveryStatus parsedUnknownField =
        Delivery.GatewayDeliveryStatus.parseFrom(unknownField.toByteArray());
    check("unknown field preserved on round-trip",
        parsedUnknownField.getUnknownFields().hasField(99));

    Delivery.GatewayDeliveryStatus unknownEnum = base.toBuilder().setOutcomeValue(999).build();
    Delivery.GatewayDeliveryStatus parsedUnknownEnum =
        Delivery.GatewayDeliveryStatus.parseFrom(unknownEnum.toByteArray());
    check("unknown enum preserved on round-trip",
        parsedUnknownEnum.getOutcomeValue() == 999);

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ VAGW CONTRACT CHECK PASSED (descriptor + generated class + compat)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " VAGW CONTRACT CHECK failure(s)");
      System.exit(1);
    }
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

  private static DescriptorProtos.DescriptorProto stripJsonName(DescriptorProtos.DescriptorProto d) {
    DescriptorProtos.DescriptorProto.Builder b = d.toBuilder();
    for (int i = 0; i < b.getFieldCount(); i++) {
      b.setField(i, b.getField(i).toBuilder().clearJsonName());
    }
    return b.build();
  }

  private static void fail(String label) {
    System.out.println("  ✗ " + label);
    failures++;
  }
}
