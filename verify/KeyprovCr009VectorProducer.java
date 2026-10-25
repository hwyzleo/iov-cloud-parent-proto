import com.google.protobuf.ByteString;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.ImportProofAlgorithm;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

/**
 * KeyProv CR-009 authoritative vector bundle producer
 * (PAR-PROTO-DSN-CR-009 §2/§4, REQ-CR-009 REQ-009-4).
 *
 * <p>Produces the SINGLE cross-end authoritative vector bundle
 * {@code verify/keyprov-ecdh-es-p256-v1/} consumed byte-exactly by VMD Java,
 * TBOX-SEC C++ and VEH-PROTO generated C++. It freezes:
 *
 * <ul>
 *   <li>the 9-field {@code wireDigestInput} + {@code wireEnvelopeDigest}
 *       (WIRE_PROFILE = PAR_PROTO_KEYPROV_ECDH_ES_P256_V1);
 *   <li>the 10-segment canonical AAD + {@code aadDigest}
 *       (AAD_PROFILE = PAR_PROTO_KEYPROV_AAD_V1);
 *   <li>deterministic {@code parameters.pb}, wrapped key, KCV and
 *       {@code proofInputV1};
 *   <li>boundary vectors (businessKeyVersion 1/127/128/255/256/2^32/2^63-1,
 *       purpose 1/2, enum varint boundaries, raw certificate digest);
 *   <li>negative vectors (unknown enum/field, illegal lengths, parameters
 *       re-encoding, per-segment tampering).
 * </ul>
 *
 * <p>All semantic inputs are FIXED constants so the bundle is reproducible.
 * Every official file hash is recorded in {@code manifest.json} and mirrored in
 * {@code provenance/vehicle-proto-baseline.yaml} (cr009_extension). The producer
 * fail-fasts on its own output: no official vector may violate the CR-009 gates.
 *
 * <p>Scope: PAR-PROTO performs NO cryptography beyond hashing and NO signing /
 * verification. The proof bytes are a deterministic P1363 low-S placeholder
 * (r=1, s=1) pinning the wire contract only; real signing is TBOX-SEC and real
 * ECDSA verification FW-SEC. FW-SEC's 18-field {@code coreEnvelopeDigest} is an
 * internal fact and never enters this bundle.
 */
public final class KeyprovCr009VectorProducer {

  static final String BUNDLE = "verify/keyprov-ecdh-es-p256-v1";
  static final String NEGATIVE = BUNDLE + "/negative";

  static final String REQUEST_ID = "req-kp-0009";
  static final String BUSINESS_DOMAIN = KeyprovCanonicalV1.BUSINESS_DOMAIN_V1; // "V2C_COMM"
  static final String OPERATION_ID = "op-kp-0009";
  static final String DERIVATION_VERSION = "openiov|v2c|v1";
  static final String KEY_ID_UP = "biz-key-up-0009";
  static final String KEY_ID_DOWN = "biz-key-down-0009";
  static final long BUSINESS_KEY_VERSION = 3L;
  static final long ROOT_KEY_VERSION = 7L;
  static final long T0 = 1_760_000_000_000L;
  static final long T_EXPIRE = 1_760_000_600_000L;

  // Fixed P-256 generator point G (valid SEC1 uncompressed point, same as CR-007).
  static final byte[] EPHEMERAL_PUBLIC_KEY = unhex(
      "04"
      + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

  static final byte[] CERT_DIGEST = fill((byte) 0x61, KeyprovCanonicalV1.DIGEST_BYTES);
  static final byte[] WRAPPED_KEY = fill((byte) 0x71, 64);
  static final byte[] HKDF_SALT = fill((byte) 0x21, KeyprovCanonicalV1.HKDF_SALT_BYTES);
  static final byte[] NONCE = fill((byte) 0x31, KeyprovCanonicalV1.NONCE_BYTES);
  static final byte[] AUTH_TAG = fill((byte) 0x41, KeyprovCanonicalV1.AUTH_TAG_BYTES);
  // Business keys are test vectors only: KCV derivation rule demonstration.
  static final byte[] UP_BUSINESS_KEY = fill((byte) 0x81, 32);
  static final byte[] DOWN_BUSINESS_KEY = fill((byte) 0x91, 32);

  public static void main(String[] args) throws Exception {
    Path bundleDir = Paths.get(BUNDLE);
    Path negativeDir = Paths.get(NEGATIVE);
    Files.createDirectories(bundleDir);
    Files.createDirectories(negativeDir);

    byte[] upKcv = KeyprovCanonicalV1.keyCheckValue(UP_BUSINESS_KEY);
    byte[] downKcv = KeyprovCanonicalV1.keyCheckValue(DOWN_BUSINESS_KEY);

    // ---- primary vector item + parameters (AAD from registry, not arbitrary) --
    WrappedKeyItem itemSkeleton = WrappedKeyItem.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        .setKeyId(KEY_ID_UP)
        .setBusinessKeyVersion(BUSINESS_KEY_VERSION)
        .setWrappedKey(ByteString.copyFrom(WRAPPED_KEY))
        .setKeyAlgorithm(KeyprovCanonicalV1.KEY_ALGORITHM_V1)
        .setWrappingSuite(WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
        .setValidFromMs(T0)
        .setValidToMs(T_EXPIRE)
        .setKeyCheckValue(ByteString.copyFrom(upKcv))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
        .build();
    EcdhEsP256EnvelopeParametersV1.Builder paramsBuilder = EcdhEsP256EnvelopeParametersV1.newBuilder()
        .setFormatVersion(KeyprovCanonicalV1.FORMAT_VERSION_V1)
        .setServerEphemeralPublicKey(ByteString.copyFrom(EPHEMERAL_PUBLIC_KEY))
        .setHkdfSalt(ByteString.copyFrom(HKDF_SALT))
        .setHkdfContextVersion(KeyprovCanonicalV1.HKDF_CONTEXT_VERSION_V1)
        .setNonce(ByteString.copyFrom(NONCE))
        .setAuthenticationTag(ByteString.copyFrom(AUTH_TAG))
        .setRootKeyVersion(ROOT_KEY_VERSION)
        .setDerivationVersion(DERIVATION_VERSION)
        .setRecipientCertificateDigest(ByteString.copyFrom(CERT_DIGEST))
        .setOperationId(OPERATION_ID);
    // canonical AAD is built from OUTER context fields (registry), never from the
    // carried canonical_aad itself.
    byte[] canonicalAad = KeyprovCanonicalV1.canonicalAad(
        itemSkeleton, paramsBuilder.build(), REQUEST_ID, BUSINESS_DOMAIN);
    EcdhEsP256EnvelopeParametersV1 params = paramsBuilder
        .setCanonicalAad(ByteString.copyFrom(canonicalAad))
        .setAadDigest(ByteString.copyFrom(KeyprovCanonicalV1.aadDigest(canonicalAad)))
        .build();
    KeyprovCanonicalV1.validateParameters(params);      // fail-fast
    byte[] parametersBytes = KeyprovCanonicalV1.deterministicParameters(params);

    WrappedKeyItem item = itemSkeleton.toBuilder()
        .setParameters(ByteString.copyFrom(parametersBytes))
        .setEnvelopeDigest(ByteString.copyFrom(
            KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, itemSkeleton.toBuilder()
                .setParameters(ByteString.copyFrom(parametersBytes)).build())))
        .build();
    // fail-fast: the primary vector must satisfy the full CR-009 consumer gate.
    KeyprovCanonicalV1.validateEcdhEsV1Item(REQUEST_ID, BUSINESS_DOMAIN, item);
    KeyprovCanonicalV1.validateAadBinding(item, params, REQUEST_ID, BUSINESS_DOMAIN);

    byte[] aadDigest = KeyprovCanonicalV1.aadDigest(canonicalAad);
    byte[] wireDigestInput = KeyprovCanonicalV1.wireDigestInput(REQUEST_ID, BUSINESS_DOMAIN, item);
    byte[] wireEnvelopeDigest = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, item);

    // ---- CR-008 proofInputV1 over the primary vector -------------------------
    KeyImportItemResult importItem = KeyImportItemResult.newBuilder()
        .setPurpose(item.getPurpose())
        .setKeyId(item.getKeyId())
        .setBusinessKeyVersion(item.getBusinessKeyVersion())
        .setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(lowSPlaceholder()))
        .setEnvelopeDigest(item.getEnvelopeDigest())
        .setKeyCheckValue(item.getKeyCheckValue())
        .setEnvelopeFormat(item.getEnvelopeFormat())
        .setImportProofAlgorithm(ImportProofAlgorithm.IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363)
        .setRecipientCertificateDigest(ByteString.copyFrom(CERT_DIGEST))
        .build();
    KeyprovCanonicalV1.validateCr008SuccessItem(importItem, CERT_DIGEST); // fail-fast
    byte[] proofInputV1 = KeyprovCanonicalV1.proofInputV1(REQUEST_ID, BUSINESS_DOMAIN, importItem);

    // ---- official files (10 including manifest) ------------------------------
    Map<String, byte[]> official = new LinkedHashMap<>();
    official.put("canonical_aad.bin", canonicalAad);
    official.put("aad_digest.hex", hexLine(aadDigest));
    official.put("parameters.pb", parametersBytes);
    official.put("wrapped_key.bin", WRAPPED_KEY);
    official.put("wire_digest_input.bin", wireDigestInput);
    official.put("wire_envelope_digest.hex", hexLine(wireEnvelopeDigest));
    official.put("proof_input_v1.bin", proofInputV1);
    official.put("key_check_value.bin", upKcv);
    for (Map.Entry<String, byte[]> e : official.entrySet()) {
      write(bundleDir.resolve(e.getKey()), e.getValue());
    }

    // ---- vector.json (semantic inputs + boundary vectors) --------------------
    StringBuilder boundary = new StringBuilder();
    long[] versions = {1L, 127L, 128L, 255L, 256L, 1L << 32, (1L << 63) - 1};
    String[] vNames = {"v1", "v127", "v128", "v255", "v256", "v2e32", "v2e63m1"};
    for (int i = 0; i < versions.length; i++) {
      WrappedKeyItem vItem = item.toBuilder().setBusinessKeyVersion(versions[i]).build();
      byte[] in = KeyprovCanonicalV1.wireDigestInput(REQUEST_ID, BUSINESS_DOMAIN, vItem);
      byte[] dg = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, vItem);
      if (i > 0) {
        boundary.append(",\n");
      }
      boundary.append("    {\"name\": \"").append(vNames[i]).append("\", \"purpose\": 1, \"business_key_version\": ")
          .append(versions[i]).append(", \"wire_digest_input_hex\": \"")
          .append(hexString(in)).append("\", \"wire_envelope_digest_hex\": \"")
          .append(hexString(dg)).append("\"}");
    }
    WrappedKeyItem downItem = item.toBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId(KEY_ID_DOWN)
        .setKeyCheckValue(ByteString.copyFrom(downKcv))
        .setEnvelopeDigest(ByteString.copyFrom(
            KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN,
                item.toBuilder().setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
                    .setKeyId(KEY_ID_DOWN).setKeyCheckValue(ByteString.copyFrom(downKcv)).build())))
        .build();
    byte[] downInput = KeyprovCanonicalV1.wireDigestInput(REQUEST_ID, BUSINESS_DOMAIN, downItem);
    byte[] downDigest = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, downItem);

    String vectorJson = "{\n"
        + "  \"profile\": {\n"
        + "    \"wire\": \"" + KeyprovCanonicalV1.WIRE_PROFILE + "\",\n"
        + "    \"aad\": \"" + KeyprovCanonicalV1.AAD_PROFILE + "\",\n"
        + "    \"wire_segments\": 9,\n"
        + "    \"aad_segments\": 10,\n"
        + "    \"wire_field_order\": [\"envelopeFormat\",\"requestId\",\"businessDomain\",\"purpose\",\"keyId\",\"businessKeyVersion\",\"wrappingSuite\",\"wrappedKey\",\"parameters\"],\n"
        + "    \"aad_field_order\": [\"envelopeFormat\",\"wrappingSuite\",\"purpose\",\"businessKeyVersion\",\"rootKeyVersion\",\"recipientCertificateDigest\",\"requestId\",\"businessDomain\",\"keyId\",\"derivationVersion\"]\n"
        + "  },\n"
        + "  \"primary\": {\n"
        + "    \"request_id\": \"" + REQUEST_ID + "\",\n"
        + "    \"business_domain\": \"" + BUSINESS_DOMAIN + "\",\n"
        + "    \"key_id\": \"" + KEY_ID_UP + "\",\n"
        + "    \"purpose\": 1,\n"
        + "    \"business_key_version\": " + BUSINESS_KEY_VERSION + ",\n"
        + "    \"envelope_format\": 1,\n"
        + "    \"wrapping_suite\": 2,\n"
        + "    \"root_key_version\": " + ROOT_KEY_VERSION + ",\n"
        + "    \"derivation_version\": \"" + DERIVATION_VERSION + "\",\n"
        + "    \"operation_id\": \"" + OPERATION_ID + "\",\n"
        + "    \"recipient_certificate_digest_hex\": \"" + hexString(CERT_DIGEST) + "\",\n"
        + "    \"recipient_certificate_digest_note\": \"enters canonical AAD as raw 32 bytes, never hex/text\",\n"
        + "    \"files\": {\n"
        + "      \"canonical_aad\": \"canonical_aad.bin\",\n"
        + "      \"aad_digest\": \"aad_digest.hex\",\n"
        + "      \"parameters\": \"parameters.pb\",\n"
        + "      \"wrapped_key\": \"wrapped_key.bin\",\n"
        + "      \"wire_digest_input\": \"wire_digest_input.bin\",\n"
        + "      \"wire_envelope_digest\": \"wire_envelope_digest.hex\",\n"
        + "      \"proof_input_v1\": \"proof_input_v1.bin\",\n"
        + "      \"key_check_value\": \"key_check_value.bin\"\n"
        + "    }\n"
        + "  },\n"
        + "  \"boundary_vectors\": [\n"
        + boundary.toString()
        + ",\n    {\"name\": \"purpose_downlink\", \"purpose\": 2, \"business_key_version\": 3, \"wire_digest_input_hex\": \""
        + hexString(downInput) + "\", \"wire_envelope_digest_hex\": \"" + hexString(downDigest) + "\"}\n"
        + "  ],\n"
        + "  \"varint_boundary\": {\n"
        + "    \"unsigned_varint_127_hex\": \"" + hexString(KeyprovCanonicalV1.unsignedVarint(127)) + "\",\n"
        + "    \"unsigned_varint_128_hex\": \"" + hexString(KeyprovCanonicalV1.unsignedVarint(128)) + "\",\n"
        + "    \"uint64be_127_hex\": \"" + hexString(KeyprovCanonicalV1.uint64be(127)) + "\",\n"
        + "    \"uint64be_128_hex\": \"" + hexString(KeyprovCanonicalV1.uint64be(128)) + "\",\n"
        + "    \"note\": \"127 encodes as 1-byte varint / 8-byte uint64be; 128 encodes as 2-byte varint and STILL 8-byte uint64be (blocks protobuf-varint misuse)\"\n"
        + "  }\n"
        + "}\n";
    write(bundleDir.resolve("vector.json"), vectorJson.getBytes(StandardCharsets.UTF_8));

    // ---- negative vectors (unknown enum/field, illegal lengths, re-encode, tamper) -
    writeNegative(negativeDir, item, parametersBytes, canonicalAad, wireDigestInput,
        wireEnvelopeDigest, params);

    // ---- manifest.json -------------------------------------------------------
    StringBuilder files = new StringBuilder();
    int i = 0;
    for (Map.Entry<String, byte[]> e : official.entrySet()) {
      if (i++ > 0) {
        files.append(",\n");
      }
      files.append("    \"").append(e.getKey()).append("\": {\"sha256\": \"")
          .append(sha256Hex(e.getValue())).append("\", \"bytes\": ").append(e.getValue().length).append("}");
    }
    String manifest = "{\n"
        + "  \"release\": {\"cr\": \"PAR-PROTO-DSN-CR-009\", \"protocol_version\": \"keyprov-v1\"},\n"
        + "  \"profile\": {\"wire\": \"" + KeyprovCanonicalV1.WIRE_PROFILE + "\", \"aad\": \""
        + KeyprovCanonicalV1.AAD_PROFILE + "\"},\n"
        + "  \"toolchain\": {\"protoc\": \"3.25.5\", \"protobuf-java\": \"3.25.5\", \"buf\": \"1.72.0\", \"maven\": \"3.9.14\", \"jdk\": \"17\"},\n"
        + "  \"source\": {\"file\": \"iov-cloud-proto-keyprov/src/main/proto/security/keyprov/v1/key_provisioning.proto\", \"sha256\": \""
        + sha256Hex(read(Paths.get("iov-cloud-proto-keyprov/src/main/proto/security/keyprov/v1/key_provisioning.proto"))) + "\"},\n"
        + "  \"descriptor\": {\"file\": \"descriptors/security-keyprov-v1.pb\", \"sha256\": \""
        + sha256Hex(read(Paths.get("descriptors/security-keyprov-v1.pb"))) + "\"},\n"
        + "  \"files\": {\n" + files.toString() + "\n  },\n"
        + "  \"negative_vectors\": \"negative/\"\n"
        + "}\n";
    write(bundleDir.resolve("manifest.json"), manifest.getBytes(StandardCharsets.UTF_8));

    System.out.println("[java] keyprov CR-009 vector bundle written to " + BUNDLE + ":");
    System.out.println("  canonical_aad:         " + canonicalAad.length + " bytes");
    System.out.println("  aad_digest:            " + aadDigest.length + " bytes");
    System.out.println("  parameters:            " + parametersBytes.length + " bytes");
    System.out.println("  wrapped_key:           " + WRAPPED_KEY.length + " bytes");
    System.out.println("  wire_digest_input:     " + wireDigestInput.length + " bytes");
    System.out.println("  wire_envelope_digest:  " + wireEnvelopeDigest.length + " bytes");
    System.out.println("  proof_input_v1:        " + proofInputV1.length + " bytes");
    System.out.println("  key_check_value:       " + upKcv.length + " bytes");
    System.out.println("  boundary_vectors:      8 (versions 1..2^63-1, purpose 1/2)");
    System.out.println("  negative vectors:      " + NEGATIVE + "/");
  }

  // ---- negative vector writers ----------------------------------------------

  private static void writeNegative(Path negativeDir, WrappedKeyItem item, byte[] parametersBytes,
      byte[] canonicalAad, byte[] wireDigestInput, byte[] wireEnvelopeDigest,
      EcdhEsP256EnvelopeParametersV1 params) throws Exception {
    // 1) unknown format_version (unknown enum) -> reject
    byte[] unknownFormat = params.toBuilder().setFormatVersion(777).build().toByteArray();
    writeJson(negativeDir.resolve("parameters_unknown_format_version.json"),
        "{\"scenario\": \"unknown format_version (777)\", \"expected\": \"reject format_version\", \"parameters_hex\": \""
        + hexString(unknownFormat) + "\"}\n");

    // 2) unknown field appended to parameters -> wire digest must use ORIGINAL bytes
    byte[] unknownFieldParams = concat(parametersBytes,
        KeyprovCanonicalV1.unsignedVarint(99L << 3), // field 99, wire type varint
        KeyprovCanonicalV1.unsignedVarint(12345L));    byte[] digestOverUnknown = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN,
        item.toBuilder().setParameters(ByteString.copyFrom(unknownFieldParams)).build());
    writeJson(negativeDir.resolve("parameters_unknown_field.json"),
        "{\"scenario\": \"unknown field 99 appended to parameters\", \"expected\": \"digest over re-encoded/unknown-field bytes differs; original deterministic bytes are authoritative\", \"parameters_hex\": \""
        + hexString(unknownFieldParams) + "\", \"authoritative_wire_envelope_digest_hex\": \""
        + hexString(wireEnvelopeDigest) + "\", \"digest_over_unknown_field_bytes_hex\": \""
        + hexString(digestOverUnknown) + "\"}\n");

    // 3) illegal lengths -> reject each
    StringBuilder cases = new StringBuilder();
    addLengthCase(cases, "hkdf_salt_31", params.toBuilder()
        .setHkdfSalt(ByteString.copyFrom(fill((byte) 0x21, 31))).build().toByteArray());
    addLengthCase(cases, "nonce_11", params.toBuilder()
        .setNonce(ByteString.copyFrom(fill((byte) 0x31, 11))).build().toByteArray());
    addLengthCase(cases, "auth_tag_15", params.toBuilder()
        .setAuthenticationTag(ByteString.copyFrom(fill((byte) 0x41, 15))).build().toByteArray());
    addLengthCase(cases, "cert_digest_31", params.toBuilder()
        .setRecipientCertificateDigest(ByteString.copyFrom(fill((byte) 0x61, 31))).build().toByteArray());
    addLengthCase(cases, "aad_digest_31", params.toBuilder()
        .setAadDigest(ByteString.copyFrom(fill((byte) 0x11, 31))).build().toByteArray());
    addLengthCase(cases, "canonical_aad_1025", params.toBuilder()
        .setCanonicalAad(ByteString.copyFrom(fill((byte) 0x51, 1025))).build().toByteArray());
    addLengthCase(cases, "parameters_2049", concat(parametersBytes, fill((byte) 0x00, 1)));
    writeJson(negativeDir.resolve("parameters_illegal_lengths.json"),
        "{\"scenario\": \"illegal lengths rejected (normative v1 table)\", \"cases\": [" + cases + "]}\n");

    // 4) parameters re-encoding (same semantic message, non-deterministic byte
    //    order) must NOT replace the original deterministic bytes
    byte[] reencoded = reencodeDescending(params);
    byte[] digestOverReencoded = KeyprovCanonicalV1.wireEnvelopeDigest(REQUEST_ID, BUSINESS_DOMAIN,
        item.toBuilder().setParameters(ByteString.copyFrom(reencoded)).build());
    writeJson(negativeDir.resolve("parameters_reencoded.json"),
        "{\"scenario\": \"same semantic parameters re-encoded with non-deterministic field order\", \"expected\": \"digest differs from authoritative; consumers must use original deterministic bytes\", \"original_parameters_hex\": \""
        + hexString(parametersBytes) + "\", \"reencoded_parameters_hex\": \"" + hexString(reencoded) + "\", \"authoritative_wire_envelope_digest_hex\": \""
        + hexString(wireEnvelopeDigest) + "\", \"digest_over_reencoded_hex\": \"" + hexString(digestOverReencoded) + "\"}\n");

    // 5) per-segment tampering of wireDigestInput (9 segments)
    StringBuilder wireTamper = new StringBuilder();
    String[] wireNames = {"envelopeFormat", "requestId", "businessDomain", "purpose", "keyId",
        "businessKeyVersion", "wrappingSuite", "wrappedKey", "parameters"};
    for (int s = 0; s < wireNames.length; s++) {
      byte[] mutated = mutateSegment(wireDigestInput, s);
      if (s > 0) {
        wireTamper.append(",\n");
      }
      wireTamper.append("    {\"segment_index\": ").append(s).append(", \"segment\": \"")
          .append(wireNames[s]).append("\", \"mutated_wire_digest_input_hex\": \"")
          .append(hexString(mutated)).append("\"}");
    }
    writeJson(negativeDir.resolve("tamper_wire_digest_input.json"),
        "{\"scenario\": \"single-byte tamper per wire digest segment\", \"expected\": \"any mutated input recomputes to a different wireEnvelopeDigest (rejected)\", \"authoritative_wire_envelope_digest_hex\": \""
        + hexString(wireEnvelopeDigest) + "\", \"cases\": [\n" + wireTamper + "\n]}\n");

    // 6) per-segment tampering of canonical AAD (10 segments)
    StringBuilder aadTamper = new StringBuilder();
    String[] aadNames = {"envelopeFormat", "wrappingSuite", "purpose", "businessKeyVersion",
        "rootKeyVersion", "recipientCertificateDigest", "requestId", "businessDomain", "keyId",
        "derivationVersion"};
    for (int s = 0; s < aadNames.length; s++) {
      byte[] mutated = mutateSegment(canonicalAad, s);
      if (s > 0) {
        aadTamper.append(",\n");
      }
      aadTamper.append("    {\"segment_index\": ").append(s).append(", \"segment\": \"")
          .append(aadNames[s]).append("\", \"mutated_canonical_aad_hex\": \"")
          .append(hexString(mutated)).append("\", \"mutated_aad_digest_hex\": \"")
          .append(hexString(KeyprovCanonicalV1.aadDigest(mutated))).append("\"}");
    }
    writeJson(negativeDir.resolve("tamper_canonical_aad.json"),
        "{\"scenario\": \"single-byte tamper per canonical AAD segment\", \"expected\": \"rebuilt AAD differs -> aad_digest mismatch -> reject\", \"authoritative_canonical_aad_hex\": \""
        + hexString(canonicalAad) + "\", \"authoritative_aad_digest_hex\": \""
        + hexString(KeyprovCanonicalV1.aadDigest(canonicalAad)) + "\", \"cases\": [\n" + aadTamper + "\n]}\n");
  }

  private static void addLengthCase(StringBuilder sb, String name, byte[] parametersHex) {
    if (sb.length() > 0) {
      sb.append(", ");
    }
    sb.append("{\"name\": \"").append(name).append("\", \"parameters_hex\": \"")
        .append(hexString(parametersHex)).append("\"}");
  }

  // ---- helpers --------------------------------------------------------------

  /** Re-serialize the same semantic message with DESCENDING field order (non-deterministic bytes). */
  private static byte[] reencodeDescending(EcdhEsP256EnvelopeParametersV1 p) {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    // descending: 12 operation_id, 11 cert digest, 10 derivation, 9 root_key, 8 aad_digest,
    // 7 canonical_aad, 6 auth_tag, 5 nonce, 4 context, 3 salt, 2 epk, 1 format_version
    writeStringField(out, 12, p.getOperationId());
    writeBytesField(out, 11, p.getRecipientCertificateDigest().toByteArray());
    writeStringField(out, 10, p.getDerivationVersion());
    writeVarintField(out, 9, p.getRootKeyVersion());
    writeBytesField(out, 8, p.getAadDigest().toByteArray());
    writeBytesField(out, 7, p.getCanonicalAad().toByteArray());
    writeBytesField(out, 6, p.getAuthenticationTag().toByteArray());
    writeBytesField(out, 5, p.getNonce().toByteArray());
    writeStringField(out, 4, p.getHkdfContextVersion());
    writeBytesField(out, 3, p.getHkdfSalt().toByteArray());
    writeBytesField(out, 2, p.getServerEphemeralPublicKey().toByteArray());
    writeVarintField(out, 1, p.getFormatVersion());
    return out.toByteArray();
  }

  private static void writeVarintField(java.io.ByteArrayOutputStream out, int fieldNo, long value) {
    out.writeBytes(KeyprovCanonicalV1.unsignedVarint((fieldNo << 3)));
    out.writeBytes(KeyprovCanonicalV1.unsignedVarint(value));
  }

  private static void writeBytesField(java.io.ByteArrayOutputStream out, int fieldNo, byte[] value) {
    out.writeBytes(KeyprovCanonicalV1.unsignedVarint((fieldNo << 3) | 2));
    out.writeBytes(KeyprovCanonicalV1.unsignedVarint(value.length));
    out.writeBytes(value);
  }

  private static void writeStringField(java.io.ByteArrayOutputStream out, int fieldNo, String value) {
    writeBytesField(out, fieldNo, value.getBytes(StandardCharsets.UTF_8));
  }

  /** Locate the start of segment {@code index} content and flip its first byte. */
  private static byte[] mutateSegment(byte[] blob, int index) {
    byte[] out = Arrays.copyOf(blob, blob.length);
    int off = 0;
    for (int i = 0; i <= index; i++) {
      int len = ((blob[off] & 0xFF) << 24) | ((blob[off + 1] & 0xFF) << 16)
          | ((blob[off + 2] & 0xFF) << 8) | (blob[off + 3] & 0xFF);
      off += 4;
      if (i == index) {
        if (len == 0) {
          throw new IllegalStateException("cannot tamper an empty segment: " + index);
        }
        out[off] ^= 0x01;
        return out;
      }
      off += len;
    }
    throw new IllegalStateException("segment index out of range: " + index);
  }

  private static byte[] lowSPlaceholder() {
    byte[] out = new byte[KeyprovCanonicalV1.P1363_SIGNATURE_BYTES];
    out[31] = 0x01;
    out[63] = 0x01;
    return out;
  }

  private static byte[] hexLine(byte[] b) {
    return (hexString(b) + "\n").getBytes(StandardCharsets.UTF_8);
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
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static byte[] fill(byte value, int length) {
    byte[] out = new byte[length];
    Arrays.fill(out, value);
    return out;
  }

  private static byte[] concat(byte[]... parts) {
    int total = 0;
    for (byte[] p : parts) {
      total += p.length;
    }
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  private static byte[] read(Path p) throws Exception {
    return Files.readAllBytes(p);
  }

  private static String sha256Hex(byte[] data) throws Exception {
    return hexString(MessageDigest.getInstance("SHA-256").digest(data));
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }

  private static void writeJson(Path p, String json) throws Exception {
    write(p, json.getBytes(StandardCharsets.UTF_8));
  }
}
