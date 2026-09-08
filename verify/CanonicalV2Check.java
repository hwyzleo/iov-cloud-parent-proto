import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import vehicle.fota.v1.Types;

/**
 * canonicalization-v2 test-vector verification (PAR-PROTO-DSN-CR-005 §5.3, CI gate 6).
 *
 * Loads the committed normative bundle verify/inventory-canonical-v2/vectors.yaml,
 * recomputes canonical_body / digest_input / SHA-256 from each vector's input and
 * asserts they match the committed hex. Also asserts the cross-vector invariants:
 *   - legacy and equivalent structured SINGLE_IMAGE -> same digest (v02==v03)
 *   - input order permutation -> same digest (v05==v07)
 *   - NFC composed/decomposed equivalence (v08==v09)
 *   - active absent normalizes to true; false differs (v12==v14, v12!=v13)
 *   - slot absent/present produce distinct digests (v10!=v11)
 *   - VIN/revision/collectedAt/acceptedAt are never digest inputs (v03==v15)
 */
public class CanonicalV2Check {
  private static final Path BUNDLE = Paths.get("verify/inventory-canonical-v2/vectors.yaml");
  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    List<Vector> vectors = parse(Files.readAllLines(BUNDLE));
    Map<String, String> digestById = new HashMap<>();
    for (Vector v : vectors) {
      List<Types.EcuVersion> ecus = v.toEcus();
      CanonicalV2.CanonicalResult r = CanonicalV2.canonicalizeFromProto(ecus);
      digestById.put(v.id, r.digestHex);
      check("vector " + v.id + " canonical_body.hex", hex(r.canonicalBody).equals(v.bodyHex));
      check("vector " + v.id + " digest_input.hex", hex(r.digestInput).equals(v.inputHex));
      check("vector " + v.id + " expected_digest.hex", r.digestHex.equals(v.expectedDigest));
      System.out.println("      " + v.id + ": " + v.expectedDigest);
    }

    // ---- cross-vector invariants -------------------------------------------
    check("legacy SINGLE_IMAGE == structured equivalent (v02==v03)",
        digestById.get("v02_legacy_single_image").equals(digestById.get("v03_structured_equivalent")));
    check("input order permutation unchanged (v05==v07)",
        digestById.get("v05_mixed_ecu").equals(digestById.get("v07_permutation")));
    check("NFC composed == decomposed (v08==v09)",
        digestById.get("v08_nfc_composed").equals(digestById.get("v09_nfc_decomposed")));
    check("active absent == active true (v12==v14)",
        digestById.get("v12_active_absent").equals(digestById.get("v14_active_true")));
    check("active false differs (v12!=v13)",
        !digestById.get("v12_active_absent").equals(digestById.get("v13_active_false")));
    check("slot absent != slot present (v10!=v11)",
        !digestById.get("v10_slot_absent").equals(digestById.get("v11_slot_present")));
    check("metadata (VIN/revision/timestamps) never enters digest (v03==v15)",
        digestById.get("v03_structured_equivalent").equals(digestById.get("v15_metadata_irrelevant")));

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ CANONICAL V2 CHECK PASSED (" + vectors.size() + " vectors + invariants)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " canonical-v2 check failure(s)");
      System.exit(1);
    }
  }

  // ---- minimal line-based parser for the generator's fixed YAML shape ------
  private static List<Vector> parse(List<String> lines) {
    List<Vector> out = new ArrayList<>();
    Vector cur = null;
    Types.EcuVersion.Builder ecu = null;
    Types.SoftwareUnitVersion.Builder unit = null;
    for (String line : lines) {
      String t = line.trim();
      if (t.startsWith("- id:")) {
        if (cur != null) {
          if (ecu != null) {
            if (unit != null) { ecu.addSoftwareUnits(unit.build()); unit = null; }
            cur.ecuBuilders.add(ecu);
            ecu = null;
          }
          out.add(cur);
        }
        cur = new Vector(t.substring("- id:".length()).trim());
      } else if (cur == null) {
        continue;
      } else if (t.startsWith("canonical_body_hex:")) {
        cur.bodyHex = unquote(t.substring("canonical_body_hex:".length()).trim());
      } else if (t.startsWith("digest_input_hex:")) {
        cur.inputHex = unquote(t.substring("digest_input_hex:".length()).trim());
      } else if (t.startsWith("expected_digest_hex:")) {
        cur.expectedDigest = unquote(t.substring("expected_digest_hex:".length()).trim());
      } else if (t.startsWith("input_ecus:")) {
        ecu = null;
        unit = null;
        cur.ecuBuilders = new ArrayList<>();
      } else if (t.startsWith("- ecu_id:")) {
        if (ecu != null) {
          if (unit != null) { ecu.addSoftwareUnits(unit.build()); unit = null; }
          cur.ecuBuilders.add(ecu);
        }
        ecu = Types.EcuVersion.newBuilder()
            .setEcuId(unquote(t.substring("- ecu_id:".length()).trim()))
            .setHardwarePartNumber("").setHwVersion("").setSoftwarePartNumber("").setSwVersion("");
      } else if (t.startsWith("hardware_part_number:") && ecu != null && unit == null) {
        ecu.setHardwarePartNumber(unquote(t.substring("hardware_part_number:".length()).trim()));
      } else if (t.startsWith("hw_version:") && ecu != null && unit == null) {
        ecu.setHwVersion(unquote(t.substring("hw_version:".length()).trim()));
      } else if (t.startsWith("software_model:") && ecu != null && unit == null) {
        ecu.setSoftwareModel(Types.EcuSoftwareModel.valueOf(t.substring("software_model:".length()).trim()));
      } else if (t.startsWith("legacy:") && ecu != null && unit == null) {
        Matcher m = Pattern.compile("legacy:\\s*\\{(.*)\\}").matcher(line);
        if (m.find()) {
          Map<String, String> kv = parseKv(m.group(1));
          ecu.setSoftwarePartNumber(str(kv, "software_part_number"));
          ecu.setSwVersion(str(kv, "sw_version"));
          String slot = str(kv, "slot");
          if (!slot.equals("null")) ecu.setSlot(slot);
          String active = str(kv, "active");
          if (!active.equals("null")) ecu.setActive(Boolean.parseBoolean(active));
        }
      } else if (t.equals("units:")) {
        unit = null;
      } else if (t.startsWith("- target:") && ecu != null) {
        if (unit != null) { ecu.addSoftwareUnits(unit.build()); }
        unit = Types.SoftwareUnitVersion.newBuilder()
            .setSoftwareTargetCode(unquote(t.substring("- target:".length()).trim()));
      } else if (unit != null && t.startsWith("part_number:")) {
        unit.setSoftwarePartNumber(unquote(t.substring("part_number:".length()).trim()));
      } else if (unit != null && t.startsWith("version:")) {
        unit.setSwVersion(unquote(t.substring("version:".length()).trim()));
      } else if (unit != null && t.startsWith("slot:")) {
        String v = unquote(t.substring("slot:".length()).trim());
        if (!v.equals("null")) unit.setSlot(v);
      } else if (unit != null && t.startsWith("active:")) {
        String v = t.substring("active:".length()).trim();
        if (!v.equals("null")) unit.setActive(Boolean.parseBoolean(v));
      }
    }
    if (ecu != null) {
      if (unit != null) ecu.addSoftwareUnits(unit.build());
      if (cur != null) cur.ecuBuilders.add(ecu);
    }
    if (cur != null) out.add(cur);
    return out;
  }

  private static Map<String, String> parseKv(String s) {
    Map<String, String> map = new HashMap<>();
    for (String part : s.split(",\\s*")) {
      int i = part.indexOf(':');
      if (i < 0) continue;
      map.put(part.substring(0, i).trim(), unquote(part.substring(i + 1).trim()));
    }
    return map;
  }

  private static String str(Map<String, String> kv, String key) {
    return kv.getOrDefault(key, "null");
  }

  private static String unquote(String s) {
    if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
      return s.substring(1, s.length() - 1);
    }
    return s;
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString();
  }

  private static void check(String label, boolean ok) {
    if (ok) {
      System.out.println("  ✓ " + label);
    } else {
      System.out.println("  ✗ " + label);
      failures++;
    }
  }

  private static final class Vector {
    final String id;
    String bodyHex, inputHex, expectedDigest;
    List<Types.EcuVersion.Builder> ecuBuilders = new ArrayList<>();
    Vector(String id) {
      this.id = id;
    }

    List<Types.EcuVersion> toEcus() {
      List<Types.EcuVersion> out = new ArrayList<>();
      for (Types.EcuVersion.Builder b : ecuBuilders) out.add(b.build());
      return out;
    }
  }
}
