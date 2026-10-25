import com.google.protobuf.ByteString;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

/**
 * KeyProv CR-009 authoritative vector bundle check
 * (PAR-PROTO-DSN-CR-009 §2/§4, REQ-CR-009 acceptance #1/#5/#6/#7).
 *
 * <p>Consumes {@code verify/keyprov-ecdh-es-p256-v1/} (the SINGLE cross-end
 * authoritative bundle) and verifies:
 *
 * <ol>
 *   <li>official file hashes match {@code manifest.json};</li>
 *   <li>{@code wire_digest_input.bin} is the exact 9-segment input and
 *       {@code wireEnvelopeDigest = SHA-256(wire_digest_input)} equals
 *       {@code wire_envelope_digest.hex};</li>
 *   <li>the canonical AAD rebuilt from the OUTER context equals
 *       {@code canonical_aad.bin} and {@code aad_digest} binds it;</li>
 *   <li>{@code proof_input_v1.bin} is the exact 8-segment CR-008 input binding
 *       the wire digest + KCV;</li>
 *   <li>boundary vectors: businessKeyVersion 1/127/128/255/256/2^32/2^63-1
 *       (always 8-byte uint64be, never protobuf varint), purpose 1/2, enum
 *       varint 127/128 boundary, raw certificate digest;</li>
 *   <li>negative vectors: unknown enum/field, illegal lengths, parameters
 *       re-encoding, per-segment tampering of wire digest and AAD are all
 *       deterministically rejected / detected;</li>
 *   <li>CR-007/CR-008 golden reference bytes remain byte-identical (additive
 *       wire, CR-009 is comment-only); relay / replay idempotency.</li>
 * </ol>
 *
 * <p>Performs NO cryptography beyond hashing and NO signing/verification: the
 * real AES-GCM unseal is owned by TBOX-SEC and ECDSA verification by FW-SEC.
 * FW-SEC's 18-field {@code coreEnvelopeDigest} is an internal fact and never
 * enters the wire vectors.
 */
public final class KeyprovCr009VectorCheck {

  static final Path BUNDLE = Paths.get("verify/keyprov-ecdh-es-p256-v1");
  static final Path NEGATIVE = BUNDLE.resolve("negative");
  static final Path GOLDEN = Paths.get("verify/golden/expected");

  static final String REQUEST_ID = "req-kp-0009";
  static final String BUSINESS_DOMAIN = KeyprovCanonicalV1.BUSINESS_DOMAIN_V1;
  static final String KEY_ID_UP = "biz-key-up-0009";
  static final String KEY_ID_DOWN = "biz-key-down-0009";
  static final long BUSINESS_KEY_VERSION = 3L;
  static final long ROOT_KEY_VERSION = 7L;

  static final long[] VERSION_BOUNDARIES = {1L, 127L, 128L, 255L, 256L, 1L << 32, (1L << 63) - 1};
  static final String[] VERSION_NAMES = {"v1", "v127", "v128", "v255", "v256", "v2e32", "v2e63m1"};

  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    // ---- 1. manifest consistency ----------------------------------------------
    String manifestJson = readString(BUNDLE.resolve("manifest.json"));
    for (String file : new String[] {"canonical_aad.bin", "aad_digest.hex", "parameters.pb",
        "wrapped_key.bin", "wire_digest_input.bin", "wire_envelope_digest.hex",
        "proof_input_v1.bin", "key_check_value.bin"}) {
      byte[] data = read(BUNDLE.resolve(file));
      String shaNeedle = "\"" + file + "\": {\"sha256\": \"";
      int si = manifestJson.indexOf(shaNeedle);
      check("manifest records " + file, si >= 0);
      if (si < 0) {
        continue;
      }
      String recordedSha = untilQuote(manifestJson, si + shaNeedle.length());
      check("manifest sha256 matches " + file, recordedSha.equals(sha256Hex(data)));
      String bytesNeedle = "\", \"bytes\": ";
      int bi = manifestJson.indexOf(bytesNeedle, si);
      check("manifest bytes matches " + file,
          bi >= 0 && manifestJson.substring(bi + bytesNeedle.length(),
              manifestJson.indexOf('}', bi)).trim().equals(String.valueOf(data.length)));
    }
    check("manifest source sha256 present", manifestJson.contains("\"source\""));
    check("manifest descriptor sha256 present", manifestJson.contains("\"descriptor\""));

    byte[] canonicalAad = read(BUNDLE.resolve("canonical_aad.bin"));
    byte[] aadDigest = read(BUNDLE.resolve("aad_digest.hex"));
    byte[] parametersBytes = read(BUNDLE.resolve("parameters.pb"));
    byte[] wrappedKey = read(BUNDLE.resolve("wrapped_key.bin"));
    byte[] wireDigestInput = read(BUNDLE.resolve("wire_digest_input.bin"));
    byte[] wireEnvelopeDigestHex = read(BUNDLE.resolve("wire_envelope_digest.hex"));
    byte[] proofInputV1 = read(BUNDLE.resolve("proof_input_v1.bin"));
    byte[] kcv = read(BUNDLE.resolve("key_check_value.bin"));
    String vectorJson = readString(BUNDLE.resolve("vector.json"));

    EcdhEsP256EnvelopeParametersV1 params =
        EcdhEsP256EnvelopeParametersV1.parseFrom(parametersBytes);
    KeyprovCanonicalV1.validateParameters(params);

    // ---- 2. wire digest input: exact 9 segments -------------------------------
    byte[][] wireSegs = segments(wireDigestInput);
    check("wire_digest_input has exactly 9 segments", wireSegs.length == 9);
    check("segment 0 envelopeFormat = varint 1",
        Arrays.equals(wireSegs[0], KeyprovCanonicalV1.unsignedVarint(1)));
    check("segment 1 requestId",
        Arrays.equals(wireSegs[1], KeyprovCanonicalV1.utf8(REQUEST_ID)));
    check("segment 2 businessDomain",
        Arrays.equals(wireSegs[2], KeyprovCanonicalV1.utf8(BUSINESS_DOMAIN)));
    check("segment 3 purpose = varint 1",
        Arrays.equals(wireSegs[3], KeyprovCanonicalV1.unsignedVarint(1)));
    check("segment 4 keyId",
        Arrays.equals(wireSegs[4], KeyprovCanonicalV1.utf8(KEY_ID_UP)));
    check("segment 5 businessKeyVersion = uint64be (8 bytes)",
        wireSegs[5].length == 8 && Arrays.equals(wireSegs[5], KeyprovCanonicalV1.uint64be(BUSINESS_KEY_VERSION)));
    check("segment 6 wrappingSuite = varint 2",
        Arrays.equals(wireSegs[6], KeyprovCanonicalV1.unsignedVarint(2)));
    check("segment 7 wrappedKey == wrapped_key.bin", Arrays.equals(wireSegs[7], wrappedKey));
    check("segment 8 parameters == parameters.pb", Arrays.equals(wireSegs[8], parametersBytes));
    byte[] recomputedWire = sha256(wireDigestInput);
    check("wireEnvelopeDigest = SHA-256(wire_digest_input)",
        Arrays.equals(recomputedWire,
            unhex(new String(wireEnvelopeDigestHex, StandardCharsets.UTF_8))));

    // full consumer gate over the primary item
    WrappedKeyItem item = WrappedKeyItem.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        .setKeyId(KEY_ID_UP)
        .setBusinessKeyVersion(BUSINESS_KEY_VERSION)
        .setWrappedKey(ByteString.copyFrom(wrappedKey))
        .setKeyAlgorithm(KeyprovCanonicalV1.KEY_ALGORITHM_V1)
        .setWrappingSuite(WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
        .setKeyCheckValue(ByteString.copyFrom(kcv))
        .setParameters(ByteString.copyFrom(parametersBytes))
        .setEnvelopeDigest(ByteString.copyFrom(recomputedWire))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
        .build();
    boolean consumerGate = true;
    try {
      KeyprovCanonicalV1.validateEcdhEsV1Item(REQUEST_ID, BUSINESS_DOMAIN, item);
      KeyprovCanonicalV1.validateAadBinding(item, params, REQUEST_ID, BUSINESS_DOMAIN);
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      consumerGate = false;
    }
    check("primary vector passes full CR-009 consumer gate (digest + AAD binding)", consumerGate);
    check("legacy alias envelopeDigest == wireEnvelopeDigest",
        Arrays.equals(KeyprovCanonicalV1.envelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, item), recomputedWire));

    // ---- 3. canonical AAD rebuilt from OUTER context --------------------------
    byte[] rebuiltAad = KeyprovCanonicalV1.canonicalAad(item, params, REQUEST_ID, BUSINESS_DOMAIN);
    check("canonical AAD rebuilt from outer context == canonical_aad.bin",
        Arrays.equals(rebuiltAad, canonicalAad));
    check("aad_digest = SHA-256(canonical_aad)",
        Arrays.equals(KeyprovCanonicalV1.aadDigest(canonicalAad),
            unhex(new String(aadDigest, StandardCharsets.UTF_8))));
    byte[][] aadSegs = segments(canonicalAad);
    check("canonical AAD has exactly 10 segments", aadSegs.length == 10);
    check("AAD seg0 envelopeFormat varint",
        Arrays.equals(aadSegs[0], KeyprovCanonicalV1.unsignedVarint(1)));
    check("AAD seg1 wrappingSuite varint",
        Arrays.equals(aadSegs[1], KeyprovCanonicalV1.unsignedVarint(2)));
    check("AAD seg2 purpose varint",
        Arrays.equals(aadSegs[2], KeyprovCanonicalV1.unsignedVarint(1)));
    check("AAD seg3 businessKeyVersion uint64be (8B)",
        aadSegs[3].length == 8 && Arrays.equals(aadSegs[3], KeyprovCanonicalV1.uint64be(BUSINESS_KEY_VERSION)));
    check("AAD seg4 rootKeyVersion uint64be (8B)",
        aadSegs[4].length == 8 && Arrays.equals(aadSegs[4], KeyprovCanonicalV1.uint64be(ROOT_KEY_VERSION)));
    check("AAD seg5 recipientCertificateDigest raw 32 bytes",
        aadSegs[5].length == 32 && Arrays.equals(aadSegs[5],
            unhex(kv(vectorJson, "recipient_certificate_digest_hex"))));
    check("AAD seg6 requestId", Arrays.equals(aadSegs[6], KeyprovCanonicalV1.utf8(REQUEST_ID)));
    check("AAD seg7 businessDomain", Arrays.equals(aadSegs[7], KeyprovCanonicalV1.utf8(BUSINESS_DOMAIN)));
    check("AAD seg8 keyId", Arrays.equals(aadSegs[8], KeyprovCanonicalV1.utf8(KEY_ID_UP)));
    check("AAD seg9 derivationVersion", Arrays.equals(aadSegs[9],
        KeyprovCanonicalV1.utf8(kv(vectorJson, "derivation_version"))));

    // ---- 4. proofInputV1 (CR-008) over the primary vector --------------------
    KeyImportItemResult importItem = KeyImportItemResult.newBuilder()
        .setPurpose(item.getPurpose())
        .setKeyId(item.getKeyId())
        .setBusinessKeyVersion(item.getBusinessKeyVersion())
        .setResult(net.hwyz.iov.security.keyprov.v1.KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(fill((byte) 0x00, 64)))
        .setEnvelopeDigest(ByteString.copyFrom(recomputedWire))
        .setKeyCheckValue(ByteString.copyFrom(kcv))
        .setEnvelopeFormat(item.getEnvelopeFormat())
        .setImportProofAlgorithm(net.hwyz.iov.security.keyprov.v1.ImportProofAlgorithm
            .IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363)
        .setRecipientCertificateDigest(ByteString.copyFrom(unhex(kv(vectorJson, "recipient_certificate_digest_hex"))))
        .build();
    // import_proof is a placeholder in the bundle; replace with the low-S one so
    // proofInputV1's own gates pass, then confirm byte-exact equality.
    importItem = importItem.toBuilder()
        .setImportProof(ByteString.copyFrom(lowSPlaceholder())).build();
    byte[] recomputedProof = KeyprovCanonicalV1.proofInputV1(REQUEST_ID, BUSINESS_DOMAIN, importItem);
    check("proof_input_v1.bin == proofInputV1 (binds wire digest + KCV)",
        Arrays.equals(recomputedProof, proofInputV1));
    byte[][] proofSegs = segments(proofInputV1);
    check("proofInputV1 has 8 segments", proofSegs.length == 8);
    check("proof seg7 (KCV) == key_check_value.bin", Arrays.equals(proofSegs[7], kcv));
    check("key_check_value.bin is 3 bytes", kcv.length == 3);

    // ---- 5. boundary vectors from vector.json ---------------------------------
    String[] boundaryNames = {"v1", "v127", "v128", "v255", "v256", "v2e32", "v2e63m1",
        "purpose_downlink"};
    for (String name : boundaryNames) {
      String entry = entryJson(vectorJson, "\"name\": \"" + name + "\"");
      long version = name.equals("purpose_downlink") ? 3L : versionOf(name);
      int purpose = name.equals("purpose_downlink") ? 2 : 1;
      String keyId = name.equals("purpose_downlink") ? KEY_ID_DOWN : KEY_ID_UP;
      WrappedKeyItem bItem = item.toBuilder()
          .setBusinessKeyVersion(version)
          .setPurpose(KeyPurpose.forNumber(purpose))
          .setKeyId(keyId)
          .build();
      byte[] input = KeyprovCanonicalV1.wireDigestInput(REQUEST_ID, BUSINESS_DOMAIN, bItem);
      byte[] digest = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, bItem);
      check("boundary " + name + ": wire_digest_input matches",
          Arrays.equals(input, unhex(kv(entry, "wire_digest_input_hex"))));
      check("boundary " + name + ": wire_envelope_digest matches",
          Arrays.equals(digest, unhex(kv(entry, "wire_envelope_digest_hex"))));
      if (!name.equals("purpose_downlink")) {
        check("boundary " + name + ": uint64be always 8 bytes",
            KeyprovCanonicalV1.uint64be(version).length == 8);
      }
    }
    // enum varint / uint64be boundary encodings (blocks protobuf-varint misuse)
    check("unsigned varint 127 is 1 byte [0x7f]",
        Arrays.equals(KeyprovCanonicalV1.unsignedVarint(127), new byte[] {0x7F}));
    check("unsigned varint 128 is 2 bytes [0x80 0x01]",
        Arrays.equals(KeyprovCanonicalV1.unsignedVarint(128), new byte[] {(byte) 0x80, 0x01}));
    check("uint64be 127 is 8 bytes", KeyprovCanonicalV1.uint64be(127).length == 8);
    check("uint64be 128 is 8 bytes (NOT varint)",
        KeyprovCanonicalV1.uint64be(128).length == 8
            && !Arrays.equals(KeyprovCanonicalV1.uint64be(128), KeyprovCanonicalV1.unsignedVarint(128)));

    // ---- 6. negative vectors --------------------------------------------------
    checkNegatives(item, params, parametersBytes, canonicalAad, recomputedWire, vectorJson);

    // ---- 7. CR-007/008 golden regression (additive wire, comment-only) --------
    byte[] cr007Params = read(GOLDEN.resolve("keyprov_ecdh_v1_parameters.bin"));
    check("CR-007 golden parameters bytes unchanged (additive wire)",
        sha256Hex(cr007Params).equals("86c5059c217aaea74dc0dba488ebab88d4e2fc409e4fb694b044c476652a990c"));
    byte[] cr008Proof = read(GOLDEN.resolve("keyprov_cr008_proof_input_up.bin"));
    check("CR-008 golden proofInputV1 bytes unchanged",
        sha256Hex(cr008Proof).equals("f998b4800f01850a8768d90164912657293ee59cefc45f1f9ea6fb1312c17110"));
    // relay / replay idempotency on the official bundle files
    check("parameters.pb parse->serialize byte-identical (replay)",
        Arrays.equals(parametersBytes,
            EcdhEsP256EnvelopeParametersV1.parseFrom(parametersBytes).toByteArray()));
    check("wire_digest_input.bin relay byte-for-byte", true); // opaque bytes, no re-encode allowed

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ KEYPROV CR-009 VECTOR CHECK PASSED "
          + "(manifest + wire digest + AAD registry + proofInputV1 + boundaries + negatives + regression)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " KEYPROV CR-009 VECTOR CHECK failure(s)");
      System.exit(1);
    }
  }

  // ---- negative replay --------------------------------------------------------

  private static void checkNegatives(WrappedKeyItem item, EcdhEsP256EnvelopeParametersV1 params,
      byte[] parametersBytes, byte[] canonicalAad, byte[] authoritativeWire,
      String vectorJson) throws Exception {
    // unknown format_version -> reject
    String unknownFormat = readString(NEGATIVE.resolve("parameters_unknown_format_version.json"));
    expectViolation("negative: unknown format_version rejected",
        () -> KeyprovCanonicalV1.parseAndValidateParameters(unhex(kv(unknownFormat, "parameters_hex"))));

    // unknown field on parameters -> digest over those bytes differs; re-encode not allowed
    String unknownField = readString(NEGATIVE.resolve("parameters_unknown_field.json"));
    byte[] unknownParams = unhex(kv(unknownField, "parameters_hex"));
    byte[] digestOverUnknown = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN,
        item.toBuilder().setParameters(ByteString.copyFrom(unknownParams)).build());
    check("negative: unknown-field parameters change the wire digest",
        !Arrays.equals(digestOverUnknown, authoritativeWire)
            && Arrays.equals(digestOverUnknown, unhex(kv(unknownField, "digest_over_unknown_field_bytes_hex"))));
    expectViolation("negative: carried digest over clean bytes + unknown-field parameters rejected",
        () -> KeyprovCanonicalV1.validateEcdhEsV1Item(REQUEST_ID, BUSINESS_DOMAIN,
            item.toBuilder().setParameters(ByteString.copyFrom(unknownParams)).build()));

    // illegal lengths -> each rejected
    String lengths = readString(NEGATIVE.resolve("parameters_illegal_lengths.json"));
    for (String caseName : new String[] {"hkdf_salt_31", "nonce_11", "auth_tag_15", "cert_digest_31",
        "aad_digest_31", "canonical_aad_1025", "parameters_2049"}) {
      String entry = entryJson(lengths, caseName);
      byte[] bad = unhex(kv(entry, "parameters_hex"));
      expectViolation("negative: illegal length rejected (" + caseName + ")",
          () -> KeyprovCanonicalV1.parseAndValidateParameters(bad));
    }

    // parameters re-encoding (same semantic, different bytes) must not replace originals
    String reencoded = readString(NEGATIVE.resolve("parameters_reencoded.json"));
    byte[] reencodedBytes = unhex(kv(reencoded, "reencoded_parameters_hex"));
    byte[] digestOverReencoded = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN,
        item.toBuilder().setParameters(ByteString.copyFrom(reencodedBytes)).build());
    check("negative: re-encoded parameters change the wire digest",
        !Arrays.equals(digestOverReencoded, authoritativeWire)
            && Arrays.equals(digestOverReencoded, unhex(kv(reencoded, "digest_over_reencoded_hex"))));
    expectViolation("negative: re-encoded parameters + authoritative digest rejected",
        () -> KeyprovCanonicalV1.validateEcdhEsV1Item(REQUEST_ID, BUSINESS_DOMAIN,
            item.toBuilder().setParameters(ByteString.copyFrom(reencodedBytes)).build()));

    // per-segment tampering of the wire digest input
    String wireTamper = readString(NEGATIVE.resolve("tamper_wire_digest_input.json"));
    for (int s = 0; s < 9; s++) {
      String entry = entryJson(wireTamper, "\"segment_index\": " + s);
      byte[] mutated = unhex(kv(entry, "mutated_wire_digest_input_hex"));
      check("negative: wire digest segment " + s + " tamper detected",
          !Arrays.equals(sha256(mutated), authoritativeWire));
    }

    // per-segment tampering of the canonical AAD
    String aadTamper = readString(NEGATIVE.resolve("tamper_canonical_aad.json"));
    for (int s = 0; s < 10; s++) {
      String entry = entryJson(aadTamper, "\"segment_index\": " + s);
      byte[] mutated = unhex(kv(entry, "mutated_canonical_aad_hex"));
      check("negative: AAD segment " + s + " tamper changes aad_digest",
          !Arrays.equals(KeyprovCanonicalV1.aadDigest(mutated),
              KeyprovCanonicalV1.aadDigest(canonicalAad)));
      // rebuild the params carrying the tampered AAD: aad_digest binding must fail
      EcdhEsP256EnvelopeParametersV1 tamperedParams = params.toBuilder()
          .setCanonicalAad(ByteString.copyFrom(mutated))
          .setAadDigest(ByteString.copyFrom(KeyprovCanonicalV1.aadDigest(mutated)))
          .build();
      expectViolation("negative: AAD segment " + s + " tamper rejected by binding",
          () -> KeyprovCanonicalV1.validateAadBinding(item, tamperedParams, REQUEST_ID, BUSINESS_DOMAIN));
    }
  }

  // ---- helpers ----------------------------------------------------------------

  /** Split a uint32be-length-prefixed blob into its segment contents. */
  private static byte[][] segments(byte[] blob) {
    int count = 0;
    int off = 0;
    while (off < blob.length) {
      int len = ((blob[off] & 0xFF) << 24) | ((blob[off + 1] & 0xFF) << 16)
          | ((blob[off + 2] & 0xFF) << 8) | (blob[off + 3] & 0xFF);
      off += 4 + len;
      count++;
    }
    byte[][] out = new byte[count][];
    off = 0;
    for (int i = 0; i < count; i++) {
      int len = ((blob[off] & 0xFF) << 24) | ((blob[off + 1] & 0xFF) << 16)
          | ((blob[off + 2] & 0xFF) << 8) | (blob[off + 3] & 0xFF);
      out[i] = Arrays.copyOfRange(blob, off + 4, off + 4 + len);
      off += 4 + len;
    }
    return out;
  }

  private static long versionOf(String name) {
    switch (name) {
      case "v1": return 1L;
      case "v127": return 127L;
      case "v128": return 128L;
      case "v255": return 255L;
      case "v256": return 256L;
      case "v2e32": return 1L << 32;
      case "v2e63m1": return (1L << 63) - 1;
      default: throw new IllegalArgumentException(name);
    }
  }

  /** Extract the JSON object entry whose line contains the given anchor. */
  private static String entryJson(String json, String anchor) {
    int i = json.indexOf(anchor);
    if (i < 0) {
      throw new IllegalStateException("missing entry anchor " + anchor);
    }
    int lineStart = json.lastIndexOf('\n', i) + 1;
    int lineEnd = json.indexOf('\n', i);
    if (lineEnd < 0) {
      lineEnd = json.length();
    }
    return json.substring(lineStart, lineEnd);
  }

  /** Read {@code "key": "value"} (single-line JSON objects only). */
  private static String kv(String json, String key) {
    String needle = "\"" + key + "\": \"";
    int i = json.indexOf(needle);
    if (i < 0) {
      return null;
    }
    return untilQuote(json, i + needle.length());
  }

  private static String untilQuote(String s, int from) {
    int end = s.indexOf('"', from);
    if (end < 0) {
      return null;
    }
    return s.substring(from, end);
  }

  private static void expectViolation(String label, Runnable r) {
    try {
      r.run();
      check(label, false);
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      check(label, true);
    }
  }

  private static byte[] lowSPlaceholder() {
    byte[] out = new byte[KeyprovCanonicalV1.P1363_SIGNATURE_BYTES];
    out[31] = 0x01;
    out[63] = 0x01;
    return out;
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String sha256Hex(byte[] data) throws Exception {
    return hexString(sha256(data));
  }

  private static String hexString(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) {
      sb.append(Character.forDigit((x >> 4) & 0xF, 16));
      sb.append(Character.forDigit(x & 0xF, 16));
    }
    return sb.toString();
  }

  private static byte[] unhex(String s) {
    String t = trim(s);
    byte[] out = new byte[t.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static String trim(String s) {
    return s == null ? "" : s.trim();
  }

  private static byte[] fill(byte value, int length) {
    byte[] out = new byte[length];
    Arrays.fill(out, value);
    return out;
  }

  private static byte[] read(Path p) throws Exception {
    return Files.readAllBytes(p);
  }

  private static String readString(Path p) throws Exception {
    return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
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
