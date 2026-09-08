import com.google.protobuf.DescriptorProtos;

import net.hwyz.iov.cloud.proto.vmd.swinv.v1.SoftwareInventoryProto;
import net.hwyz.iov.cloud.proto.vmd.swinv.v1.SoftwareInventoryReport;

/**
 * swinv deprecation check (PAR-PROTO-DSN-CR-005 §8/§9, CI gate 10.4).
 *
 * iov.vmd.swinv.v1.SoftwareInventoryReport is deprecated-only:
 *   - file-level + message-level deprecated options set
 *   - ALL legacy fields/enums unchanged (numbers/names/types/values)
 *   - generated class carries @Deprecated
 *   - OTA->VMD cloud event is NOT part of PAR-PROTO (no proto-ota module, no
 *     Cloud Event Registry, no Maven artifact); this repo never checks that
 *     schema — its contract test lives in the IOV-OTA/VMD repos (§10.4).
 */
public class SwinvContractCheck {
  private static int failures = 0;

  public static void main(String[] args) {
    DescriptorProtos.FileDescriptorProto swinvProto = null;
    try {
      swinvProto = SoftwareInventoryProto.getDescriptor().toProto();
    } catch (Throwable t) {
      fail("generated SoftwareInventoryProto.getDescriptor() failed: " + t);
    }
    if (swinvProto != null) {
      check("swinv file-level deprecated option set", swinvProto.getOptions().getDeprecated());
      DescriptorProtos.DescriptorProto report = findMessage(swinvProto, "SoftwareInventoryReport");
      check("swinv message-level deprecated option set", report.getOptions().getDeprecated());
      checkFields("SoftwareInventoryReport (fields unchanged)", report, new Object[][] {
        {1, "manifest_version", 4, 0}, {2, "collected_at", 3, 0}, {3, "reason", 14, 0},
        {4, "full_snapshot", 8, 0}, {5, "items", 11, 0},
      });
      DescriptorProtos.DescriptorProto item = findMessage(swinvProto, "SoftwareItem");
      checkFields("SoftwareItem (fields unchanged)", item, new Object[][] {
        {1, "vehicle_node_code", 9, 0}, {2, "software_target_code", 9, 0},
        {3, "software_part_no", 9, 0}, {4, "software_version", 9, 0},
        {5, "slot", 9, 0}, {6, "digest", 9, 0}, {7, "change_type", 14, 0},
      });
      DescriptorProtos.EnumDescriptorProto reason = findEnum(swinvProto, "ReportReason");
      check("ReportReason unchanged (6 values 0..5)",
          reason.getValueCount() == 6 && reason.getValue(5).getNumber() == 5);
      DescriptorProtos.EnumDescriptorProto change = findEnum(swinvProto, "ChangeType");
      check("ChangeType unchanged (6 values 0..5)",
          change.getValueCount() == 6 && change.getValue(5).getNumber() == 5);
      check("generated SoftwareInventoryReport class is deprecated",
          SoftwareInventoryReport.class.isAnnotationPresent(Deprecated.class));
    }

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ SWINV DEPRECATION CHECK PASSED (deprecated options + fields unchanged)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " swinv check failure(s)");
      System.exit(1);
    }
  }

  private static DescriptorProtos.DescriptorProto findMessage(
      DescriptorProtos.FileDescriptorProto file, String name) {
    for (DescriptorProtos.DescriptorProto m : file.getMessageTypeList()) {
      if (m.getName().equals(name)) return m;
    }
    fail("message " + name + " not found");
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

  private static boolean fieldOk(DescriptorProtos.DescriptorProto msg, int number,
      String name, int type, int proto3Optional) {
    for (DescriptorProtos.FieldDescriptorProto f : msg.getFieldList()) {
      if (f.getNumber() == number) {
        return f.getName().equals(name)
            && f.getType() == DescriptorProtos.FieldDescriptorProto.Type.forNumber(type)
            && f.getProto3Optional() == (proto3Optional == 1);
      }
    }
    return false;
  }

  private static void checkFields(String label, DescriptorProtos.DescriptorProto msg,
      Object[][] expected) {
    for (Object[] e : expected) {
      boolean ok = fieldOk(msg, (Integer) e[0], (String) e[1], (Integer) e[2], (Integer) e[3]);
      check(label + " field #" + e[0] + " " + e[1] + " (type " + e[2] + ", opt " + e[3] + ")", ok);
    }
  }

  private static void check(String label, boolean ok) {
    if (ok) {
      System.out.println("  ✓ " + label);
    } else {
      fail(label);
    }
  }

  private static void fail(String label) {
    System.out.println("  ✗ " + label);
    failures++;
  }
}
