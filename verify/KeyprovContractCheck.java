import com.google.protobuf.ByteString;
import com.google.protobuf.DescriptorProtos;
import com.google.protobuf.Descriptors;
import com.google.protobuf.UnknownFieldSet;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;
import net.hwyz.iov.security.keyprov.v1.ProtocolError;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

/**
 * KeyProv contract check (PAR-PROTO-DSN-CR-006 §2/§4/§7, CR-007 §3/§4/§5/§6/§7,
 * REQ US-013..US-020 / REQ-CR-007 acceptance #1..#7).
 *
 * Validates the committed normalized DescriptorSet
 * (descriptors/security-keyprov-v1.pb) and the generated Java classes:
 *   - file security/keyprov/v1/key_provisioning.proto, package security.keyprov.v1
 *   - 6 enums with exact prefixed values (buffer/STANDARD ENUM_VALUE_PREFIX clean)
 *   - 13 messages with exact field numbers / names / types / repetition
 *   - no redefinition of VehicleMessageEnvelope (Envelope is provided by proto-vehicle-common)
 *   - generated Java class resolution (net.hwyz.iov.security.keyprov.v1.*)
 *   - unknown-field / unknown-enum preservation + fail-closed lookup (forNumber == null)
 *   - normative §4.3 size/count limits + §4.4 semantic gates encoded as portable
 *     constants shared with the vehicle-side C++ contract-check
 *   - CR-007 §6.1 capability negotiation, §6.2 response gates, §6.3 ACK binding,
 *     §7 envelope v1 exact lengths / P-256 point / suite-format allowlist
 *   - §5 sensitivity classification static scan
 */
public class KeyprovContractCheck {

  // ---- Normative limits (PAR-PROTO-DSN-CR-006 §4.3) -------------------------
  // These constants are the wire contract shared by Java and C++ contract checks.
  static final int MAX_PAYLOAD_BYTES = 16384;
  static final int MAX_ID_BYTES = 128;            // request_id / idempotency_key / key_id / code / action / proof_algorithm
  static final int MAX_DOMAIN_BYTES = 64;         // business_domain / key_algorithm / certificate_profile
  static final int MAX_REPEATED = 8;              // purposes / items / current_versions / supported_wrapping_suites / supported_envelope_formats
  static final int MAX_DIGEST_BYTES = 64;         // certificate_digest / device_identity_digest / operation_id
  static final int MAX_WRAPPED_KEY_BYTES = 4096;
  static final int MAX_PARAMETERS_BYTES = 2048;
  static final int MAX_IMPORT_PROOF_BYTES = 1024;
  static final int MAX_ERROR_MESSAGE_BYTES = 256;
  static final String PROTOCOL_VERSION = "keyprov-v1"; // opaque Envelope allowlist value

  // ---- CR-007 envelope v1 exact lengths (PAR-PROTO-DSN-CR-007 §7) -----------
  static final int EPH_PUBKEY_BYTES = 65;
  static final int HKDF_SALT_BYTES = 32;
  static final int NONCE_BYTES = 12;
  static final int AUTH_TAG_BYTES = 16;
  static final int DIGEST_BYTES = 32;             // aad_digest / envelope_digest / recipient_certificate_digest
  static final int KCV_BYTES = 3;
  static final int MAX_CANONICAL_AAD_BYTES = 1024;
  static final int FORMAT_VERSION_V1 = 1;

  // Fixed P-256 generator point G (valid on-curve SEC1 uncompressed) for the
  // positive control; negative controls derive from it deterministically.
  static final byte[] P256_G_UNCOMPRESSED = hex(
      "04"
      + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    String descriptorPath = args.length > 0 ? args[0] : "descriptors/security-keyprov-v1.pb";

    DescriptorProtos.FileDescriptorSet set;
    try (FileInputStream in = new FileInputStream(descriptorPath)) {
      set = DescriptorProtos.FileDescriptorSet.parseFrom(in);
    }
    if (set.getFileCount() != 1
        || !set.getFile(0).getName().equals("security/keyprov/v1/key_provisioning.proto")) {
      fail("descriptor must contain exactly security/keyprov/v1/key_provisioning.proto");
      System.exit(1);
    }
    pass("descriptor contains security/keyprov/v1/key_provisioning.proto");
    DescriptorProtos.FileDescriptorProto file = set.getFile(0);
    check("package is security.keyprov.v1", file.getPackage().equals("security.keyprov.v1"));

    // ---- No Envelope redefinition / no import (Envelope owned by common) ------
    check("key_provisioning.proto has no imports (Envelope is outer wrapper)", file.getDependencyCount() == 0);
    boolean envelopeClash = false;
    for (DescriptorProtos.DescriptorProto m : file.getMessageTypeList()) {
      if (m.getName().equals("VehicleMessageEnvelope") || m.getName().equals("Envelope")) {
        envelopeClash = true;
      }
    }
    check("no VehicleMessageEnvelope redefinition", !envelopeClash);

    // ---- Enums (exact values, prefix-clean) ----------------------------------
    Map<String, String[]> expectedEnums = new LinkedHashMap<>();
    expectedEnums.put("KeyPurpose", new String[] {
        "KEY_PURPOSE_UNSPECIFIED", "KEY_PURPOSE_UPLINK_AEAD", "KEY_PURPOSE_DOWNLINK_AEAD"});
    expectedEnums.put("KeyProvisioningResult", new String[] {
        "KEY_PROVISIONING_RESULT_UNSPECIFIED", "KEY_PROVISIONING_RESULT_SUCCEEDED",
        "KEY_PROVISIONING_RESULT_RETRYABLE_FAILURE", "KEY_PROVISIONING_RESULT_REJECTED",
        "KEY_PROVISIONING_RESULT_CONFLICT", "KEY_PROVISIONING_RESULT_EXPIRED"});
    expectedEnums.put("KeyImportResult", new String[] {
        "KEY_IMPORT_RESULT_UNSPECIFIED", "KEY_IMPORT_RESULT_IMPORTED",
        "KEY_IMPORT_RESULT_FAILED", "KEY_IMPORT_RESULT_UNKNOWN"});
    expectedEnums.put("KeyProvisioningStatus", new String[] {
        "KEY_PROVISIONING_STATUS_UNSPECIFIED", "KEY_PROVISIONING_STATUS_REQUESTED",
        "KEY_PROVISIONING_STATUS_ISSUED", "KEY_PROVISIONING_STATUS_ACK_PENDING",
        "KEY_PROVISIONING_STATUS_ACTIVE", "KEY_PROVISIONING_STATUS_FAILED",
        "KEY_PROVISIONING_STATUS_UNKNOWN"});
    expectedEnums.put("WrappingSuite", new String[] {
        "WRAPPING_SUITE_UNSPECIFIED", "WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM",
        "WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM"});
    expectedEnums.put("KeyEnvelopeFormat", new String[] {
        "KEY_ENVELOPE_FORMAT_UNSPECIFIED", "KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1"});

    check("file declares 6 enums", file.getEnumTypeCount() == expectedEnums.size());
    Set<String> seenEnums = new HashSet<>();
    for (DescriptorProtos.EnumDescriptorProto e : file.getEnumTypeList()) {
      String[] expected = expectedEnums.get(e.getName());
      if (expected == null) {
        fail("unexpected enum " + e.getName());
        continue;
      }
      seenEnums.add(e.getName());
      boolean ok = e.getValueCount() == expected.length;
      for (int i = 0; i < e.getValueCount() && ok; i++) {
        ok = e.getValue(i).getNumber() == i && e.getValue(i).getName().equals(expected[i]);
      }
      check("enum " + e.getName() + " values 0.." + (expected.length - 1), ok);
    }

    // ---- Messages (exact field numbers / names / types) ----------------------
    Map<String, List<F>> expectedMessages = new LinkedHashMap<>();
    expectedMessages.put("ProtocolError", Arrays.asList(
        s(1, "code"), b(2, "retryable"), s(3, "action"), s(4, "message")));
    expectedMessages.put("CertificateRef", Arrays.asList(
        bytes(1, "certificate_digest"), s(2, "certificate_profile"), s(3, "key_encipherment_key_id")));
    expectedMessages.put("CurrentKeyVersion", Arrays.asList(
        en(1, "purpose", ".security.keyprov.v1.KeyPurpose"), u64(2, "business_key_version")));
    expectedMessages.put("EcdhEsP256EnvelopeParametersV1", Arrays.asList(
        u32(1, "format_version"), bytes(2, "server_ephemeral_public_key"), bytes(3, "hkdf_salt"),
        s(4, "hkdf_context_version"), bytes(5, "nonce"), bytes(6, "authentication_tag"),
        bytes(7, "canonical_aad"), bytes(8, "aad_digest"), u64(9, "root_key_version"),
        s(10, "derivation_version"), bytes(11, "recipient_certificate_digest"),
        s(12, "operation_id")));
    expectedMessages.put("KeyProvisioningRequest", Arrays.asList(
        s(1, "request_id"), s(2, "idempotency_key"), s(3, "business_domain"),
        repEn(4, "purposes", ".security.keyprov.v1.KeyPurpose"), bytes(5, "device_identity_digest"),
        msg(6, "certificate_ref", ".security.keyprov.v1.CertificateRef"),
        repEn(7, "supported_wrapping_suites", ".security.keyprov.v1.WrappingSuite"),
        repMsg(8, "current_versions", ".security.keyprov.v1.CurrentKeyVersion"),
        i64(9, "timestamp_ms"), i64(10, "expire_at_ms"),
        repEn(11, "supported_envelope_formats", ".security.keyprov.v1.KeyEnvelopeFormat")));
    expectedMessages.put("WrappedKeyItem", Arrays.asList(
        en(1, "purpose", ".security.keyprov.v1.KeyPurpose"), s(2, "key_id"),
        u64(3, "business_key_version"), bytes(4, "wrapped_key"), s(5, "key_algorithm"),
        en(6, "wrapping_suite", ".security.keyprov.v1.WrappingSuite"),
        i64(7, "valid_from_ms"), i64(8, "valid_to_ms"), bytes(9, "parameters"),
        bytes(10, "envelope_digest"), bytes(11, "key_check_value"),
        en(12, "envelope_format", ".security.keyprov.v1.KeyEnvelopeFormat")));
    expectedMessages.put("KeyProvisioningResponse", Arrays.asList(
        s(1, "request_id"), en(2, "result", ".security.keyprov.v1.KeyProvisioningResult"),
        repMsg(3, "items", ".security.keyprov.v1.WrappedKeyItem"), i64(4, "expire_at_ms"),
        msg(5, "error", ".security.keyprov.v1.ProtocolError")));
    expectedMessages.put("KeyImportItemResult", Arrays.asList(
        en(1, "purpose", ".security.keyprov.v1.KeyPurpose"), s(2, "key_id"),
        u64(3, "business_key_version"), en(4, "result", ".security.keyprov.v1.KeyImportResult"),
        bytes(5, "import_proof"), s(6, "proof_algorithm"),
        bytes(7, "envelope_digest"), bytes(8, "key_check_value"),
        en(9, "envelope_format", ".security.keyprov.v1.KeyEnvelopeFormat")));
    expectedMessages.put("KeyProvisioningAck", Arrays.asList(
        s(1, "request_id"), repMsg(2, "items", ".security.keyprov.v1.KeyImportItemResult"),
        i64(3, "timestamp_ms")));
    expectedMessages.put("KeyProvisioningAckResult", Arrays.asList(
        s(1, "request_id"), en(2, "result", ".security.keyprov.v1.KeyProvisioningResult"),
        i64(3, "occurred_at_ms"), msg(4, "error", ".security.keyprov.v1.ProtocolError")));
    expectedMessages.put("KeyProvisioningStatusRequest", Arrays.asList(
        s(1, "request_id"), i64(2, "timestamp_ms")));
    expectedMessages.put("KeyPurposeStatus", Arrays.asList(
        en(1, "purpose", ".security.keyprov.v1.KeyPurpose"), s(2, "key_id"),
        u64(3, "business_key_version"), en(4, "import_result", ".security.keyprov.v1.KeyImportResult")));
    expectedMessages.put("KeyProvisioningStatusResponse", Arrays.asList(
        s(1, "request_id"), en(2, "status", ".security.keyprov.v1.KeyProvisioningStatus"),
        repMsg(3, "items", ".security.keyprov.v1.KeyPurposeStatus"),
        i64(4, "occurred_at_ms"), msg(5, "error", ".security.keyprov.v1.ProtocolError")));

    check("file declares 13 messages", file.getMessageTypeCount() == expectedMessages.size());
    Map<String, DescriptorProtos.DescriptorProto> byName = new HashMap<>();
    for (DescriptorProtos.DescriptorProto m : file.getMessageTypeList()) {
      byName.put(m.getName(), m);
    }
    int enumRefs = 0;
    for (Map.Entry<String, List<F>> entry : expectedMessages.entrySet()) {
      DescriptorProtos.DescriptorProto m = byName.get(entry.getKey());
      if (m == null) {
        fail("message " + entry.getKey() + " missing");
        continue;
      }
      List<F> expected = entry.getValue();
      if (m.getFieldCount() != expected.size()) {
        fail("message " + entry.getKey() + " field count " + m.getFieldCount()
            + " != " + expected.size());
        continue;
      }
      Map<Integer, DescriptorProtos.FieldDescriptorProto> byNum = new HashMap<>();
      for (DescriptorProtos.FieldDescriptorProto f : m.getFieldList()) {
        byNum.put(f.getNumber(), f);
      }
      boolean ok = true;
      for (F f : expected) {
        DescriptorProtos.FieldDescriptorProto actual = byNum.get(f.num);
        if (actual == null) {
          ok = false;
          fail(entry.getKey() + " field #" + f.num + " " + f.name + " missing");
          continue;
        }
        boolean match = actual.getName().equals(f.name)
            && actual.getType() == f.type
            && actual.getLabel() == (f.repeated
                ? DescriptorProtos.FieldDescriptorProto.Label.LABEL_REPEATED
                : DescriptorProtos.FieldDescriptorProto.Label.LABEL_OPTIONAL);
        if (f.typeName != null) {
          match = match && actual.getTypeName().equals(f.typeName);
        }
        if (!match) {
          ok = false;
          fail(entry.getKey() + " field #" + f.num + " " + f.name + " type/label/typeName mismatch");
        }
        if (f.type == DescriptorProtos.FieldDescriptorProto.Type.TYPE_ENUM) {
          enumRefs++;
        }
      }
      check("message " + entry.getKey() + " fields 1.." + expected.size(), ok);
    }
    check("enum-typed fields present (purpose/result/status/suite/format)", enumRefs == 15);

    // ---- Generated Java class resolution ------------------------------------
    Descriptors.FileDescriptor fd = Descriptors.FileDescriptor.buildFrom(file,
        new Descriptors.FileDescriptor[0]);
    List<String> messageNames = new ArrayList<>(expectedMessages.keySet());
    boolean resolved = true;
    for (String name : messageNames) {
      Descriptors.Descriptor gen = fd.findMessageTypeByName(name);
      try {
        Class<?> clazz = Class.forName("net.hwyz.iov.security.keyprov.v1." + name);
        java.lang.reflect.Method getDescriptor = clazz.getMethod("getDescriptor");
        Object genDescriptor = getDescriptor.invoke(null);
        resolved = resolved && gen != null
            && stripJsonName(((Descriptors.Descriptor) genDescriptor).toProto())
                .equals(stripJsonName(byName.get(name)));
      } catch (Exception ex) {
        resolved = false;
        fail("generated class net.hwyz.iov.security.keyprov.v1." + name + " not resolvable: " + ex);
      }
    }
    check("generated Java message classes match committed DescriptorSet", resolved);

    boolean enumsResolved = KeyPurpose.getDescriptor().getFullName().equals("security.keyprov.v1.KeyPurpose")
        && KeyPurpose.getDescriptor().toProto().equals(file.getEnumType(0))
        && WrappingSuite.getDescriptor().getFullName().equals("security.keyprov.v1.WrappingSuite");
    check("generated Java enum classes resolve", enumsResolved);

    // ---- Unknown-field / unknown-enum preservation + fail-closed -------------
    KeyProvisioningRequest base = KeyProvisioningRequest.newBuilder()
        .setRequestId("req-kp-1").setIdempotencyKey("idem-kp-1").setBusinessDomain("v2c_comm")
        .addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        .addPurposes(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
        .setDeviceIdentityDigest(ByteString.copyFrom(new byte[] {1, 2, 3}))
        .setTimestampMs(1_760_000_000_000L).setExpireAtMs(1_760_000_600_000L).build();
    KeyProvisioningRequest unknownField = base.toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(7L).build()).build())
        .build();
    check("unknown field preserved on round-trip",
        KeyProvisioningRequest.parseFrom(unknownField.toByteArray()).getUnknownFields().hasField(99));
    KeyProvisioningRequest withUnknownEnum = base.toBuilder().setPurposesValue(0, 999).build();
    check("unknown enum preserved on round-trip",
        KeyProvisioningRequest.parseFrom(withUnknownEnum.toByteArray()).getPurposesValue(0) == 999);
    check("unknown enum fail-closed lookup (forNumber(999) == null)",
        KeyPurpose.forNumber(999) == null);

    // ---- Normative §4.3 size / count limits ---------------------------------
    expectLegal(() -> validateRequest(base), "complete request is legal");
    expectLegal(() -> validateRequest(base.toBuilder()
        .setRequestId(utf8(MAX_ID_BYTES)).build()), "request_id at 128 bytes legal");
    expectViolation(() -> validateRequest(base.toBuilder()
        .setRequestId(utf8(MAX_ID_BYTES + 1)).build()), "request_id > 128 rejected");
    expectLegal(() -> validateRequest(base.toBuilder()
        .setBusinessDomain(utf8(MAX_DOMAIN_BYTES)).build()), "business_domain at 64 bytes legal");
    expectViolation(() -> validateRequest(base.toBuilder()
        .setBusinessDomain(utf8(MAX_DOMAIN_BYTES + 1)).build()), "business_domain > 64 rejected");

    WrappedKeyItem item = WrappedKeyItem.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("key-1")
        .setBusinessKeyVersion(1L).setWrappedKey(ByteString.copyFrom(new byte[MAX_WRAPPED_KEY_BYTES]))
        .setKeyAlgorithm("AES-128-GCM").setWrappingSuite(WrappingSuite.WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM)
        .setValidFromMs(1_760_000_000_000L).setValidToMs(1_770_000_000_000L)
        .setParameters(ByteString.copyFrom(new byte[MAX_PARAMETERS_BYTES])).build();
    expectLegal(() -> validateItem(item), "wrapped_key/parameters at limit legal");
    expectViolation(() -> validateItem(item.toBuilder()
        .setWrappedKey(ByteString.copyFrom(new byte[MAX_WRAPPED_KEY_BYTES + 1])).build()),
        "wrapped_key > 4096 rejected");
    expectViolation(() -> validateItem(item.toBuilder()
        .setParameters(ByteString.copyFrom(new byte[MAX_PARAMETERS_BYTES + 1])).build()),
        "parameters > 2048 rejected");
    expectViolation(() -> validateItem(item.toBuilder()
        .setValidFromMs(1_770_000_000_000L).setValidToMs(1_760_000_000_000L).build()),
        "valid_from >= valid_to rejected");

    KeyImportItemResult proof = KeyImportItemResult.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("key-1").setBusinessKeyVersion(1L)
        .setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(new byte[MAX_IMPORT_PROOF_BYTES]))
        .setProofAlgorithm("HMAC-SHA256").build();
    expectLegal(() -> validateProof(proof), "import_proof at limit legal");
    expectViolation(() -> validateProof(proof.toBuilder()
        .setImportProof(ByteString.copyFrom(new byte[MAX_IMPORT_PROOF_BYTES + 1])).build()),
        "import_proof > 1024 rejected");

    // ---- Normative §4.4 semantic gates --------------------------------------
    expectLegal(() -> validateRequest(base), "purpose set == {UPLINK,DOWNLINK} accepted");
    expectViolation(() -> validateRequest(base.toBuilder()
        .clearPurposes().addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).build()), "missing purpose rejected");
    expectViolation(() -> validateRequest(base.toBuilder()
        .clearPurposes().addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        .addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).build()), "duplicate purpose rejected");
    expectViolation(() -> validateRequest(base.toBuilder()
        .addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).build()), "oversized purpose set rejected");

    List<KeyPurpose> requested = Arrays.asList(
        KeyPurpose.KEY_PURPOSE_UPLINK_AEAD, KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD);
    WrappedKeyItem downItem = item.toBuilder().setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).build();
    KeyProvisioningResponse okResponse = KeyProvisioningResponse.newBuilder()
        .setRequestId("req-kp-1").setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
        .addItems(item).addItems(downItem).setExpireAtMs(1_760_000_600_000L).build();
    expectLegal(() -> validateResponse(okResponse, requested), "SUCCEEDED with exact 2 items accepted");
    expectViolation(() -> validateResponse(okResponse.toBuilder().removeItems(1).build(), requested),
        "SUCCEEDED missing item rejected");
    expectViolation(() -> validateResponse(okResponse.toBuilder()
        .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
        .setError(ProtocolError.newBuilder().setCode("X").build()).build(), requested),
        "SUCCEEDED with error rejected");
    expectViolation(() -> validateResponse(KeyProvisioningResponse.newBuilder()
        .setRequestId("req-kp-1").setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_REJECTED).build(),
        requested), "non-success without error rejected");

    // ---- CR-007 §6.1 capability negotiation ---------------------------------
    check("unknown envelope format fail-closed (forNumber(777) == null)",
        KeyEnvelopeFormat.forNumber(777) == null);
    KeyProvisioningRequest negotiated = base.toBuilder()
        .addSupportedEnvelopeFormats(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1).build();
    expectLegal(() -> KeyprovCanonicalV1.requireEnvelopeFormatNegotiated(
        negotiated.getSupportedEnvelopeFormatsList()), "declared ECDH-ES v1 format negotiates");
    expectViolation(() -> KeyprovCanonicalV1.requireEnvelopeFormatNegotiated(
        base.getSupportedEnvelopeFormatsList()),
        "legacy request without supported_envelope_formats (no field 11) rejected");
    expectViolation(() -> KeyprovCanonicalV1.requireEnvelopeFormatNegotiated(
        Arrays.asList(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_UNSPECIFIED)),
        "UNSPECIFIED-only format declaration rejected");

    // ---- CR-007 §7 ECDH-ES v1 parameters gates ------------------------------
    byte[] canonicalAad = new byte[MAX_CANONICAL_AAD_BYTES / 16];
    Arrays.fill(canonicalAad, (byte) 0x51);
    EcdhEsP256EnvelopeParametersV1 params = EcdhEsP256EnvelopeParametersV1.newBuilder()
        .setFormatVersion(FORMAT_VERSION_V1)
        .setServerEphemeralPublicKey(ByteString.copyFrom(P256_G_UNCOMPRESSED))
        .setHkdfSalt(ByteString.copyFrom(new byte[HKDF_SALT_BYTES]))
        .setHkdfContextVersion("v1")
        .setNonce(ByteString.copyFrom(new byte[NONCE_BYTES]))
        .setAuthenticationTag(ByteString.copyFrom(new byte[AUTH_TAG_BYTES]))
        .setCanonicalAad(ByteString.copyFrom(canonicalAad))
        .setAadDigest(ByteString.copyFrom(KeyprovCanonicalV1.aadDigest(canonicalAad)))
        .setRootKeyVersion(7L)
        .setDerivationVersion("openiov|v2c|v1")
        .setRecipientCertificateDigest(ByteString.copyFrom(new byte[DIGEST_BYTES]))
        .setOperationId("op-kp-1")
        .build();
    expectLegal(() -> KeyprovCanonicalV1.validateParameters(params), "valid ECDH-ES v1 parameters accepted");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(
        params.toBuilder().setFormatVersion(2).build()), "unknown format_version rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setServerEphemeralPublicKey(ByteString.copyFrom(new byte[EPH_PUBKEY_BYTES - 1])).build()),
        "ephemeral public key wrong length rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setServerEphemeralPublicKey(ByteString.copyFrom(nonUncompressedPoint())).build()),
        "non-0x04 SEC1 point rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setServerEphemeralPublicKey(ByteString.copyFrom(offCurvePoint())).build()),
        "P-256 point not on curve rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setHkdfSalt(ByteString.copyFrom(new byte[HKDF_SALT_BYTES + 1])).build()),
        "hkdf_salt wrong length rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setNonce(ByteString.copyFrom(new byte[NONCE_BYTES - 1])).build()),
        "nonce wrong length rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setAuthenticationTag(ByteString.copyFrom(new byte[AUTH_TAG_BYTES + 1])).build()),
        "authentication_tag wrong length rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setAadDigest(ByteString.copyFrom(new byte[DIGEST_BYTES])).build()),
        "aad_digest not binding canonical_aad rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setRecipientCertificateDigest(ByteString.copyFrom(new byte[DIGEST_BYTES - 1])).build()),
        "recipient_certificate_digest wrong length rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateParameters(params.toBuilder()
        .setCanonicalAad(ByteString.copyFrom(new byte[MAX_CANONICAL_AAD_BYTES + 1])).build()),
        "canonical_aad > 1 KiB rejected");

    // ---- CR-007 §6.2 response item gates ------------------------------------
    byte[] parametersBytes = KeyprovCanonicalV1.deterministicParameters(params);
    check("deterministic parameters serialization is stable",
        Arrays.equals(parametersBytes, KeyprovCanonicalV1.deterministicParameters(params)));
    byte[] kcv = KeyprovCanonicalV1.keyCheckValue(new byte[32]);
    check("KCV is 3 bytes", kcv.length == KCV_BYTES);
    WrappedKeyItem v1Item = WrappedKeyItem.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("biz-key-up-0002")
        .setBusinessKeyVersion(3L).setWrappedKey(ByteString.copyFrom(new byte[64]))
        .setKeyAlgorithm("AES-256")
        .setWrappingSuite(WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
        .setValidFromMs(1_760_000_000_000L).setValidToMs(1_760_000_600_000L)
        .setParameters(ByteString.copyFrom(parametersBytes))
        .setKeyCheckValue(ByteString.copyFrom(kcv))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
        .build();
    byte[] digest = KeyprovCanonicalV1.envelopeDigest("req-kp-1", "v2c_comm", v1Item);
    check("envelopeDigest is 32 bytes and binds requestId",
        digest.length == DIGEST_BYTES
            && !java.util.Arrays.equals(digest,
                KeyprovCanonicalV1.envelopeDigest("other-req", "v2c_comm", v1Item)));
    WrappedKeyItem v1Bound = v1Item.toBuilder().setEnvelopeDigest(ByteString.copyFrom(digest)).build();
    expectLegal(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm", v1Bound),
        "valid ECDH-ES v1 item passes §6.2 gates");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm", v1Item),
        "item without envelope_digest rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm",
        v1Bound.toBuilder().setEnvelopeDigest(ByteString.copyFrom(new byte[DIGEST_BYTES])).build()),
        "envelope_digest mismatch rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("other-req", "v2c_comm", v1Bound),
        "envelope_digest bound to requestId (replay under other request rejected)");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm",
        v1Bound.toBuilder()
            .setWrappingSuite(WrappingSuite.WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM).build()),
        "suite/format mismatch rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm",
        v1Bound.toBuilder().setKeyAlgorithm("AES-128-GCM").build()), "non-AES-256 key_algorithm rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm",
        v1Bound.toBuilder().setKeyCheckValue(ByteString.copyFrom(new byte[KCV_BYTES - 1])).build()),
        "key_check_value wrong length rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateEcdhEsV1Item("req-kp-1", "v2c_comm",
        v1Bound.toBuilder()
            .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_UNSPECIFIED).build()),
        "UNSPECIFIED envelope_format rejected");

    // ---- CR-007 §5 / §6.3 ACK binding ---------------------------------------
    KeyImportItemResult v1Import = KeyImportItemResult.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("biz-key-up-0002")
        .setBusinessKeyVersion(3L).setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(new byte[32])).setProofAlgorithm("HMAC-SHA256")
        .setEnvelopeDigest(ByteString.copyFrom(digest)).setKeyCheckValue(ByteString.copyFrom(kcv))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1).build();
    WrappedKeyItem v1Down = v1Bound.toBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId("biz-key-down-0002").build();
    KeyImportItemResult v1ImportDown = v1Import.toBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId("biz-key-down-0002").build();
    KeyProvisioningResponse v1Response = KeyProvisioningResponse.newBuilder()
        .setRequestId("req-kp-1").setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
        .addItems(v1Bound).addItems(v1Down).setExpireAtMs(1_760_000_600_000L).build();
    KeyProvisioningAck v1Ack = KeyProvisioningAck.newBuilder()
        .setRequestId("req-kp-1").addItems(v1Import).addItems(v1ImportDown)
        .setTimestampMs(1_760_000_001_000L).build();
    expectLegal(() -> KeyprovCanonicalV1.validateAckBinding(v1Response, v1Ack),
        "ACK binding to matching v1 response accepted");
    expectViolation(() -> KeyprovCanonicalV1.validateAckBinding(v1Response, v1Ack.toBuilder()
        .setItems(0, v1Import.toBuilder()
            .setEnvelopeDigest(ByteString.copyFrom(new byte[DIGEST_BYTES])).build()).build()),
        "ACK with mismatched envelope_digest rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateAckBinding(v1Response, v1Ack.toBuilder()
        .setItems(0, v1Import.toBuilder()
            .setKeyCheckValue(ByteString.copyFrom(new byte[KCV_BYTES])).build()).build()),
        "ACK with mismatched key_check_value rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateAckBinding(v1Response, v1Ack.toBuilder()
        .setItems(0, v1Import.toBuilder()
            .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_UNSPECIFIED).build()).build()),
        "ACK with mismatched envelope_format rejected");
    expectViolation(() -> KeyprovCanonicalV1.validateAckBinding(v1Response,
        v1Ack.toBuilder().removeItems(1).build()), "ACK with missing purpose item rejected");

    // ---- §5 sensitivity classification static scan --------------------------
    check("wrapped_key/parameters/import_proof are bytes",
        typeOf(file, "WrappedKeyItem", "wrapped_key") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "WrappedKeyItem", "parameters") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "KeyImportItemResult", "import_proof") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES);
    check("digests are bytes",
        typeOf(file, "CertificateRef", "certificate_digest") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "KeyProvisioningRequest", "device_identity_digest") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "WrappedKeyItem", "envelope_digest") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "WrappedKeyItem", "key_check_value") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "KeyImportItemResult", "envelope_digest") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "KeyImportItemResult", "key_check_value") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "EcdhEsP256EnvelopeParametersV1", "server_ephemeral_public_key") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES
            && typeOf(file, "EcdhEsP256EnvelopeParametersV1", "canonical_aad") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES);
    check("parameters stays a bounded opaque bytes wire type (v1 content is the frozen submessage)",
        typeOf(file, "WrappedKeyItem", "parameters") == DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES);
    String[] forbidden = {"private", "plaintext", "slot", "key_ref", "keyref", "kms"};
    boolean clean = true;
    for (DescriptorProtos.DescriptorProto m : file.getMessageTypeList()) {
      for (DescriptorProtos.FieldDescriptorProto f : m.getFieldList()) {
        String lower = f.getName().toLowerCase();
        for (String token : forbidden) {
          if (lower.contains(token)) {
            clean = false;
            fail("forbidden sensitive field name " + m.getName() + "." + f.getName());
          }
        }
      }
    }
    check("no plaintext/private-key/slot/KMS-keyRef fields in wire", clean);
    check("keyprov protocol_version constant is keyprov-v1", PROTOCOL_VERSION.equals("keyprov-v1"));

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ KEYPROV CONTRACT CHECK PASSED (descriptor + generated class + "
          + "§4.3/§4.4 gates + §5 sensitivity)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " KEYPROV CONTRACT CHECK failure(s)");
      System.exit(1);
    }
  }

  // ---- Portable normative validators (mirrored by vehicle-side C++ checks) ---

  static void validateRequest(KeyProvisioningRequest r) {
    utf8(r.getRequestId(), MAX_ID_BYTES, "request_id");
    utf8(r.getIdempotencyKey(), MAX_ID_BYTES, "idempotency_key");
    utf8(r.getBusinessDomain(), MAX_DOMAIN_BYTES, "business_domain");
    if (r.getPurposesCount() > MAX_REPEATED) {
      throw new Violation("purposes > " + MAX_REPEATED);
    }
    if (r.getSupportedWrappingSuitesCount() > MAX_REPEATED) {
      throw new Violation("supported_wrapping_suites > " + MAX_REPEATED);
    }
    if (r.getCurrentVersionsCount() > MAX_REPEATED) {
      throw new Violation("current_versions > " + MAX_REPEATED);
    }
    if (r.getDeviceIdentityDigest().size() > MAX_DIGEST_BYTES) {
      throw new Violation("device_identity_digest > " + MAX_DIGEST_BYTES);
    }
    Set<KeyPurpose> purposes = new HashSet<>(r.getPurposesList());
    if (r.getPurposesCount() != 2
        || purposes.size() != 2
        || !purposes.contains(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        || !purposes.contains(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)) {
      throw new Violation("v1 purposes must equal {UPLINK_AEAD, DOWNLINK_AEAD} exactly");
    }
  }

  static void validateItem(WrappedKeyItem it) {
    utf8(it.getKeyId(), MAX_ID_BYTES, "key_id");
    utf8(it.getKeyAlgorithm(), MAX_DOMAIN_BYTES, "key_algorithm");
    if (it.getWrappedKey().size() > MAX_WRAPPED_KEY_BYTES) {
      throw new Violation("wrapped_key > " + MAX_WRAPPED_KEY_BYTES);
    }
    if (it.getParameters().size() > MAX_PARAMETERS_BYTES) {
      throw new Violation("parameters > " + MAX_PARAMETERS_BYTES);
    }
    if (it.getValidFromMs() != 0 && it.getValidToMs() != 0 && it.getValidFromMs() >= it.getValidToMs()) {
      throw new Violation("valid_from_ms must be < valid_to_ms when both set");
    }
  }

  static void validateProof(KeyImportItemResult p) {
    utf8(p.getKeyId(), MAX_ID_BYTES, "key_id");
    utf8(p.getProofAlgorithm(), MAX_ID_BYTES, "proof_algorithm");
    if (p.getImportProof().size() > MAX_IMPORT_PROOF_BYTES) {
      throw new Violation("import_proof > " + MAX_IMPORT_PROOF_BYTES);
    }
    boolean proofPresent = p.getImportProof().size() > 0;
    boolean algoPresent = !p.getProofAlgorithm().isEmpty();
    if (proofPresent != algoPresent) {
      throw new Violation("import_proof and proof_algorithm must be paired");
    }
  }

  static void validateResponse(KeyProvisioningResponse resp, List<KeyPurpose> requested) {
    if (resp.getItemsCount() > MAX_REPEATED) {
      throw new Violation("items > " + MAX_REPEATED);
    }
    boolean success = resp.getResult() == KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED;
    if (success && resp.hasError()) {
      throw new Violation("SUCCEEDED must not carry error");
    }
    if (!success && !resp.hasError()) {
      throw new Violation("non-success must carry error");
    }
    if (success) {
      Set<KeyPurpose> expected = new HashSet<>(requested);
      Set<KeyPurpose> actual = new HashSet<>();
      for (WrappedKeyItem it : resp.getItemsList()) {
        validateItem(it);
        if (it.getBusinessKeyVersion() == 0
            || it.getWrappingSuite() == WrappingSuite.WRAPPING_SUITE_UNSPECIFIED
            || !actual.add(it.getPurpose())) {
          throw new Violation("invalid/duplicate success item");
        }
      }
      if (resp.getItemsCount() != expected.size() || !actual.equals(expected)) {
        throw new Violation("SUCCEEDED must return exactly the requested purpose set");
      }
    }
    if (resp.hasError()) {
      utf8(resp.getError().getMessage(), MAX_ERROR_MESSAGE_BYTES, "ProtocolError.message");
    }
  }

  // ---- helpers --------------------------------------------------------------

  static void utf8(String v, int max, String field) {
    int n = v.getBytes(StandardCharsets.UTF_8).length;
    if (n > max) {
      throw new Violation(field + " > " + max + " bytes");
    }
  }

  static String utf8(int n) {
    StringBuilder sb = new StringBuilder(n);
    for (int i = 0; i < n; i++) {
      sb.append('a');
    }
    return sb.toString();
  }

  static byte[] hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  /** 65 bytes but not SEC1 uncompressed (0x02 tag) -> must be rejected on the tag rule. */
  static byte[] nonUncompressedPoint() {
    byte[] p = Arrays.copyOf(P256_G_UNCOMPRESSED, EPH_PUBKEY_BYTES);
    p[0] = 0x02;
    return p;
  }

  /** 0x04 || Gx || 0^(32): a well-formed-length point that is provably not on P-256. */
  static byte[] offCurvePoint() {
    byte[] p = Arrays.copyOf(P256_G_UNCOMPRESSED, EPH_PUBKEY_BYTES);
    for (int i = 33; i < EPH_PUBKEY_BYTES; i++) {
      p[i] = 0;
    }
    return p;
  }

  static DescriptorProtos.FieldDescriptorProto.Type typeOf(DescriptorProtos.FileDescriptorProto file,
      String message, String field) {
    for (DescriptorProtos.DescriptorProto m : file.getMessageTypeList()) {
      if (m.getName().equals(message)) {
        for (DescriptorProtos.FieldDescriptorProto f : m.getFieldList()) {
          if (f.getName().equals(field)) {
            return f.getType();
          }
        }
      }
    }
    return null;
  }

  static void expectLegal(Runnable r, String label) {
    try {
      r.run();
      pass(label);
    } catch (Violation v) {
      fail(label + " (unexpected violation: " + v.getMessage() + ")");
    }
  }

  static void expectViolation(Runnable r, String label) {
    try {
      r.run();
      fail(label + " (expected violation, got none)");
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput v) {
      pass(label);
    }
  }

  static final class Violation extends KeyprovCanonicalV1.InvalidKeyprovInput {
    Violation(String message) {
      super(message);
    }
  }

  // ---- field-spec DSL -------------------------------------------------------

  static final class F {
    final int num;
    final String name;
    final DescriptorProtos.FieldDescriptorProto.Type type;
    final boolean repeated;
    final String typeName;

    F(int num, String name, DescriptorProtos.FieldDescriptorProto.Type type, boolean repeated,
        String typeName) {
      this.num = num;
      this.name = name;
      this.type = type;
      this.repeated = repeated;
      this.typeName = typeName;
    }
  }

  static F s(int num, String name) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_STRING, false, null);
  }

  static F bytes(int num, String name) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_BYTES, false, null);
  }

  static F b(int num, String name) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_BOOL, false, null);
  }

  static F u64(int num, String name) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_UINT64, false, null);
  }

  static F i64(int num, String name) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_INT64, false, null);
  }

  static F u32(int num, String name) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_UINT32, false, null);
  }

  static F en(int num, String name, String typeName) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_ENUM, false, typeName);
  }

  static F repEn(int num, String name, String typeName) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_ENUM, true, typeName);
  }

  static F msg(int num, String name, String typeName) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_MESSAGE, false, typeName);
  }

  static F repMsg(int num, String name, String typeName) {
    return new F(num, name, DescriptorProtos.FieldDescriptorProto.Type.TYPE_MESSAGE, true, typeName);
  }

  static DescriptorProtos.DescriptorProto stripJsonName(DescriptorProtos.DescriptorProto d) {
    DescriptorProtos.DescriptorProto.Builder b = d.toBuilder();
    for (int i = 0; i < b.getFieldCount(); i++) {
      b.setField(i, b.getField(i).toBuilder().clearJsonName());
    }
    return b.build();
  }

  static void check(String label, boolean ok) {
    if (ok) {
      pass(label);
    } else {
      fail(label);
    }
  }

  static void pass(String label) {
    System.out.println("  ✓ " + label);
  }

  static void fail(String label) {
    System.out.println("  ✗ " + label);
    failures++;
  }
}
