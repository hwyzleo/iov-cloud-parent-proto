import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import vehicle.fota.v1.Types;

/**
 * canonicalization-v2 reference implementation (PAR-PROTO-DSN-CR-005 §5.2).
 *
 * Custom deterministic TLV (NOT protobuf serialization bytes). Producers and
 * consumers must not customize field order, wire kind, string comparison or
 * domain framing. Exact rules:
 *
 *   record = uint8(canonical_field_id) || uint8(wire_kind)
 *            || uint32_be(payload_length) || payload[payload_length]
 *   wire kinds: 0x01=UTF8_STRING 0x02=BOOL 0x06=MESSAGE
 *   optional absent  -> whole record not encoded
 *   repeated MESSAGE -> same field id, one record per element, no index/count
 *   UTF8_STRING      -> Unicode NFC, no BOM UTF-8 (no trim / no case folding)
 *   BOOL             -> length 1, 0x00=false 0x01=true
 *   sort: ECU by ecu_id; Unit by target -> slot_presence(absent first)
 *         -> slot -> part_number -> version (NFC UTF-8 unsigned bytewise)
 *   digest_input = UTF8(domain) || 0x00 || canonical_body
 *   digest       = SHA-256(digest_input), value_hex = 64 lowercase hex
 *
 * Digest covers only ECU hardware + normalized software units. It does NOT
 * cover VIN / inventory_revision / collectedAt / acceptedAt / envelope fields,
 * and raw software_model is normalized away (legacy and equivalent structured
 * SINGLE_IMAGE yield the same digest).
 */
public final class CanonicalV2 {
  public static final String DOMAIN = "vehicle.fota.v1.inventory.canonical.v2";
  public static final String ALGORITHM = "SHA-256";
  private static final byte[] DOMAIN_BYTES = DOMAIN.getBytes(StandardCharsets.UTF_8);

  private static final int WIRE_UTF8 = 0x01;
  private static final int WIRE_BOOL = 0x02;
  private static final int WIRE_MESSAGE = 0x06;

  private CanonicalV2() {}

  // ---- normalized input model (already business-validated) ------------------
  public static final class DigestInput {
    public String algorithm;
    public String valueHex;
    public DigestInput(String algorithm, String valueHex) {
      this.algorithm = algorithm;
      this.valueHex = valueHex;
    }
  }

  public static final class UnitInput {
    public String target;
    public String partNumber;
    public String version;
    public String slot;              // null = absent
    public Boolean active;           // null = absent (normalized per rules)
    public DigestInput digest;       // null = absent
  }

  public static final class EcuInput {
    public String ecuId;
    public String hardwarePartNumber;
    public String hwVersion;
    public List<UnitInput> units = new ArrayList<>();
  }

  public static final class CanonicalResult {
    public final byte[] canonicalBody;
    public final byte[] digestInput;
    public final String digestHex;
    CanonicalResult(byte[] body, byte[] input, String hex) {
      this.canonicalBody = body;
      this.digestInput = input;
      this.digestHex = hex;
    }
  }

  // ---- entry points ---------------------------------------------------------
  /** Canonicalize from raw proto EcuVersion list (legacy + structured mixed). */
  public static CanonicalResult canonicalizeFromProto(List<Types.EcuVersion> ecus) {
    List<EcuInput> in = new ArrayList<>();
    for (Types.EcuVersion e : ecus) {
      if (e.hasActive() && !e.getActive() && !e.hasSlot()) {
        // design §3.5: active=false + slot absent is illegal on the EcuVersion
        // SINGLE_IMAGE legacy surface.
        throw new InvalidCanonicalInput(
            "EcuVersion active=false requires slot (ecu_id=" + e.getEcuId() + ")");
      }
      EcuInput ecu = new EcuInput();
      ecu.ecuId = e.getEcuId();
      ecu.hardwarePartNumber = e.getHardwarePartNumber();
      ecu.hwVersion = e.getHwVersion();
      for (Types.SoftwareUnitVersion u : e.getSoftwareUnitsList()) {
        UnitInput ui = new UnitInput();
        ui.target = u.getSoftwareTargetCode();
        ui.partNumber = u.getSoftwarePartNumber();
        ui.version = u.getSwVersion();
        ui.slot = u.hasSlot() ? u.getSlot() : null;
        ui.active = u.hasActive() ? Boolean.valueOf(u.getActive()) : null;
        if (u.hasSoftwareDigest()) {
          ui.digest = new DigestInput(u.getSoftwareDigest().getAlgorithm(),
              u.getSoftwareDigest().getValueHex());
        }
        ecu.units.add(ui);
      }
      if (ecu.units.isEmpty() && e.getSoftwarePartNumber().length() > 0) {
        // legacy single-image surface -> one ECU_IMAGE unit (design §5.1)
        UnitInput ui = new UnitInput();
        ui.target = "ECU_IMAGE";
        ui.partNumber = e.getSoftwarePartNumber();
        ui.version = e.getSwVersion();
        ui.slot = e.hasSlot() ? e.getSlot() : null;
        ui.active = e.hasActive() ? Boolean.valueOf(e.getActive()) : null;
        ecu.units.add(ui);
      }
      in.add(ecu);
    }
    return canonicalize(in);
  }

  /** Canonicalize normalized model input. */
  public static CanonicalResult canonicalize(List<EcuInput> ecus) {
    // ---- normalize each unit: resolve active (design §5.1 / §3.2) ----------
    // active absent + no slot   -> true (single no-slot unit / legacy default)
    // active absent + slot      -> true UNLESS the target is a multi-slot group
    //                             (>=2 units sharing the target with slots), in
    //                             which case explicit presence is required.
    for (EcuInput ecu : ecus) {
      Map<String, Integer> slotCountByTarget = new java.util.HashMap<>();
      for (UnitInput u : ecu.units) {
        if (u.slot != null) {
          slotCountByTarget.merge(u.target, 1, Integer::sum);
        }
      }
      for (UnitInput u : ecu.units) {
        if (u.active == null) {
          boolean multiSlot = u.slot != null
              && slotCountByTarget.getOrDefault(u.target, 0) >= 2;
          if (multiSlot) {
            throw new InvalidCanonicalInput(
                "multi-slot unit requires explicit active presence (target=" + u.target + ")");
          }
          u.active = Boolean.TRUE;
        }
      }
    }

    // ---- business validation (design §3.5 / §10.2 negatives) ----------------
    for (EcuInput ecu : ecus) {
      // ecu_id + software_target_code + slot uniqueness
      Set<String> seen = new java.util.HashSet<>();
      for (UnitInput u : ecu.units) {
        String key = u.target + "\u0000" + (u.slot == null ? "" : u.slot);
        if (!seen.add(key)) {
          throw new InvalidCanonicalInput(
              "duplicate (target, slot) in ecu " + ecu.ecuId + ": " + u.target
                  + (u.slot == null ? "" : "/" + u.slot));
        }
      }
      // multi-slot target groups: exactly one active=true (design §3.5)
      Map<String, List<UnitInput>> byTarget = new java.util.HashMap<>();
      for (UnitInput u : ecu.units) {
        byTarget.computeIfAbsent(u.target, k -> new ArrayList<>()).add(u);
      }
      for (Map.Entry<String, List<UnitInput>> e : byTarget.entrySet()) {
        List<UnitInput> group = e.getValue();
        boolean multiSlot = false;
        for (UnitInput u : group) {
          if (u.slot != null) multiSlot = true;
        }
        if (multiSlot && group.size() >= 2) {
          int activeCount = 0;
          for (UnitInput u : group) {
            if (u.active) activeCount++;
          }
          if (activeCount != 1) {
            throw new InvalidCanonicalInput(
                "target " + e.getKey() + " in ecu " + ecu.ecuId
                    + " must have exactly one active=true (got " + activeCount + ")");
          }
        }
      }
    }

    // ---- validation (design §5.2.4: reject invalid identifiers/empty slot) ---
    for (EcuInput ecu : ecus) {
      validateIdentifier("ecu_id", ecu.ecuId);
      validateIdentifier("hardware_part_number", ecu.hardwarePartNumber);
      validateIdentifier("hw_version", ecu.hwVersion);
      for (UnitInput u : ecu.units) {
        validateIdentifier("software_target_code", u.target);
        validateIdentifier("software_part_number", u.partNumber);
        validateIdentifier("sw_version", u.version);
        if (u.slot != null && u.slot.isEmpty()) {
          throw new InvalidCanonicalInput("slot present but empty (target=" + u.target + ")");
        }
      }
    }

    // ---- NFC normalize all string fields ------------------------------------
    for (EcuInput ecu : ecus) {
      ecu.ecuId = nfc(ecu.ecuId);
      ecu.hardwarePartNumber = nfc(ecu.hardwarePartNumber);
      ecu.hwVersion = nfc(ecu.hwVersion);
      for (UnitInput u : ecu.units) {
        u.target = nfc(u.target);
        u.partNumber = nfc(u.partNumber);
        u.version = nfc(u.version);
        if (u.slot != null) u.slot = nfc(u.slot);
        if (u.digest != null) {
          u.digest.algorithm = nfc(u.digest.algorithm);
          u.digest.valueHex = nfc(u.digest.valueHex);
        }
      }
    }

    // ---- stable sorts (NFC UTF-8 unsigned bytewise) -------------------------
    ecus.sort(Comparator.comparing(e -> utf8(e.ecuId), CanonicalV2::compareBytes));
    for (EcuInput ecu : ecus) {
      ecu.units.sort(CanonicalV2::compareUnits);
    }

    // ---- encode canonical body: CanonicalInventoryBody.ecus (id 1, MESSAGE) --
    ByteSink body = new ByteSink();
    for (EcuInput ecu : ecus) {
      body.record(1, WIRE_MESSAGE, encodeEcu(ecu));
    }
    byte[] canonicalBody = body.toByteArray();

    // ---- digest (design §5.2.5) ---------------------------------------------
    ByteSink input = new ByteSink();
    input.raw(DOMAIN_BYTES);
    input.raw(new byte[] {0x00});
    input.raw(canonicalBody);
    byte[] digestInput = input.toByteArray();
    byte[] digestBytes = sha256(digestInput);
    return new CanonicalResult(canonicalBody, digestInput, lowercaseHex(digestBytes));
  }

  // ---- encoding ------------------------------------------------------------
  private static byte[] encodeEcu(EcuInput ecu) {
    ByteSink s = new ByteSink();
    s.record(1, WIRE_UTF8, utf8(ecu.ecuId));
    s.record(2, WIRE_UTF8, utf8(ecu.hardwarePartNumber));
    s.record(3, WIRE_UTF8, utf8(ecu.hwVersion));
    for (UnitInput u : ecu.units) {
      s.record(4, WIRE_MESSAGE, encodeUnit(u));
    }
    return s.toByteArray();
  }

  private static byte[] encodeUnit(UnitInput u) {
    ByteSink s = new ByteSink();
    s.record(1, WIRE_UTF8, utf8(u.target));
    s.record(2, WIRE_UTF8, utf8(u.partNumber));
    s.record(3, WIRE_UTF8, utf8(u.version));
    if (u.slot != null) {
      s.record(4, WIRE_UTF8, utf8(u.slot));
    }
    s.record(5, WIRE_BOOL, new byte[] {(byte) (u.active ? 0x01 : 0x00)});
    if (u.digest != null) {
      ByteSink d = new ByteSink();
      d.record(1, WIRE_UTF8, utf8(u.digest.algorithm));
      d.record(2, WIRE_UTF8, utf8(u.digest.valueHex));
      s.record(6, WIRE_MESSAGE, d.toByteArray());
    }
    return s.toByteArray();
  }

  private static final class ByteSink {
    private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

    void raw(byte[] b) {
      out.write(b, 0, b.length);
    }

    void record(int fieldId, int wireKind, byte[] payload) {
      out.write(fieldId & 0xFF);
      out.write(wireKind & 0xFF);
      out.write((payload.length >>> 24) & 0xFF);
      out.write((payload.length >>> 16) & 0xFF);
      out.write((payload.length >>> 8) & 0xFF);
      out.write(payload.length & 0xFF);
      raw(payload);
    }

    byte[] toByteArray() {
      return out.toByteArray();
    }
  }

  // ---- helpers -------------------------------------------------------------
  private static void validateIdentifier(String name, String v) {
    if (v == null || v.isEmpty()) {
      throw new InvalidCanonicalInput(name + " must be non-empty");
    }
    String n = nfc(v);
    if (!n.equals(n.trim())) {
      throw new InvalidCanonicalInput(name + " has leading/trailing whitespace (not canonical form)");
    }
  }

  private static String nfc(String s) {
    return Normalizer.normalize(s, Normalizer.Form.NFC);
  }

  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static int compareUnits(UnitInput a, UnitInput b) {
    int c = compareBytes(utf8(nfc(a.target)), utf8(nfc(b.target)));
    if (c != 0) return c;
    c = Integer.compare(a.slot != null ? 1 : 0, b.slot != null ? 1 : 0); // absent first
    if (c != 0) return c;
    if (a.slot != null && b.slot != null) {
      c = compareBytes(utf8(nfc(a.slot)), utf8(nfc(b.slot)));
      if (c != 0) return c;
    }
    c = compareBytes(utf8(nfc(a.partNumber)), utf8(nfc(b.partNumber)));
    if (c != 0) return c;
    return compareBytes(utf8(nfc(a.version)), utf8(nfc(b.version)));
  }

  /** Unsigned bytewise lexicographic comparison (design §5.2.4). */
  static int compareBytes(byte[] a, byte[] b) {
    int n = Math.min(a.length, b.length);
    for (int i = 0; i < n; i++) {
      int x = a[i] & 0xFF;
      int y = b[i] & 0xFF;
      if (x != y) return Integer.compare(x, y);
    }
    return Integer.compare(a.length, b.length);
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String lowercaseHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString();
  }

  public static final class InvalidCanonicalInput extends RuntimeException {
    public InvalidCanonicalInput(String msg) {
      super(msg);
    }
  }
}
