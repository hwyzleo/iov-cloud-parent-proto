import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import net.hwyz.iov.security.keyprov.v1.CertificateRef;
import net.hwyz.iov.security.keyprov.v1.CurrentKeyVersion;
import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

import vehicle.common.v1.Envelope;

/**
 * KeyProv ECDH-ES v1 golden producer (PAR-PROTO-DSN-CR-007 §4/§5/§9, REQ-CR-007 acceptance #1/#2/#3).
 *
 * Produces canonical Java reference bytes for the CR-007 envelope v1 surface:
 *   - deterministic EcdhEsP256EnvelopeParametersV1 bytes      (§9 item 1)
 *   - envelopeDigest / aadDigest / KCV / proofInput           (§9 item 2)
 *   - envelope v1 Request/Response/Ack payloads + Envelope    (§9 item 7 relay)
 *
 * All inputs are FIXED constants so the bytes are reproducible; the hash of
 * every file is recorded in provenance/vehicle-proto-baseline.yaml. VEH-PROTO /
 * TBOX generate C++ from the released source/DescriptorSet and MUST round-trip
 * byte-identically against these bytes.
 *
 * No key material is emitted: the parameters carry only public/ephemeral
 * material, digests and metadata. The "business key" here is a fixed test
 * vector used solely to demonstrate the KCV derivation rule.
 */
public class KeyprovCr007GoldenProducer {
  static final long T0 = 1_760_000_000_000L;
  static final long T_EXPIRE = 1_760_000_600_000L;
  static final String REQUEST_ID = "req-kp-0002";
  static final String BUSINESS_DOMAIN = "v2c_comm";
  static final String OPERATION_ID = "op-kp-0002";
  static final String DERIVATION_VERSION = "openiov|v2c|v1";

  // Fixed P-256 generator point G (a valid on-curve SEC1 uncompressed point).
  static final byte[] EPHEMERAL_PUBLIC_KEY = hex(
      "04"
      + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    byte[] canonicalAad = fill((byte) 0x51, 64);
    byte[] aadDigest = KeyprovCanonicalV1.aadDigest(canonicalAad);

    // ---- deterministic EcdhEsP256EnvelopeParametersV1 bytes (§9 item 1) ------
    EcdhEsP256EnvelopeParametersV1 upParams = EcdhEsP256EnvelopeParametersV1.newBuilder()
        .setFormatVersion(KeyprovCanonicalV1.FORMAT_VERSION_V1)
        .setServerEphemeralPublicKey(ByteString.copyFrom(EPHEMERAL_PUBLIC_KEY))
        .setHkdfSalt(ByteString.copyFrom(fill((byte) 0x21, KeyprovCanonicalV1.HKDF_SALT_BYTES)))
        .setHkdfContextVersion(KeyprovCanonicalV1.HKDF_CONTEXT_VERSION_V1)
        .setNonce(ByteString.copyFrom(fill((byte) 0x31, KeyprovCanonicalV1.NONCE_BYTES)))
        .setAuthenticationTag(ByteString.copyFrom(fill((byte) 0x41, KeyprovCanonicalV1.AUTH_TAG_BYTES)))
        .setCanonicalAad(ByteString.copyFrom(canonicalAad))
        .setAadDigest(ByteString.copyFrom(aadDigest))
        .setRootKeyVersion(7L)
        .setDerivationVersion(DERIVATION_VERSION)
        .setRecipientCertificateDigest(ByteString.copyFrom(fill((byte) 0x61, KeyprovCanonicalV1.DIGEST_BYTES)))
        .setOperationId(OPERATION_ID)
        .build();
    byte[] upParameters = KeyprovCanonicalV1.deterministicParameters(upParams);
    KeyprovCanonicalV1.validateParameters(upParams); // fail-fast: the golden must be legal
    write(outDir.resolve("keyprov_ecdh_v1_parameters.bin"), upParameters);

    // Per-purpose business keys (test-vector only) -> KCV = first 3 bytes of SHA-256.
    byte[] upBusinessKey = fill((byte) 0x81, 32);
    byte[] downBusinessKey = fill((byte) 0x91, 32);
    byte[] upKcv = KeyprovCanonicalV1.keyCheckValue(upBusinessKey);
    byte[] downKcv = KeyprovCanonicalV1.keyCheckValue(downBusinessKey);
    write(outDir.resolve("keyprov_ecdh_v1_kcv_up.bin"), upKcv);
    write(outDir.resolve("keyprov_ecdh_v1_kcv_down.bin"), downKcv);
    write(outDir.resolve("keyprov_ecdh_v1_aad_digest.bin"), aadDigest);

    // ---- Request with negotiated envelope format (§6.1) ----------------------
    KeyProvisioningRequest request = KeyProvisioningRequest.newBuilder()
        .setRequestId(REQUEST_ID)
        .setIdempotencyKey("idem-kp-0002")
        .setBusinessDomain(BUSINESS_DOMAIN)
        .addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        .addPurposes(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
        .setDeviceIdentityDigest(ByteString.copyFrom(fill((byte) 0x11, 32)))
        .setCertificateRef(CertificateRef.newBuilder()
            .setCertificateDigest(ByteString.copyFrom(fill((byte) 0x22, 32)))
            .setCertificateProfile("V2C_MTLS_P256")
            .setKeyEnciphermentKeyId("kek-kp-0002"))
        .addSupportedWrappingSuites(WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
        .addCurrentVersions(CurrentKeyVersion.newBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setBusinessKeyVersion(2L))
        .addCurrentVersions(CurrentKeyVersion.newBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setBusinessKeyVersion(2L))
        .setTimestampMs(T0)
        .setExpireAtMs(T_EXPIRE)
        .addSupportedEnvelopeFormats(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
        .build();
    write(outDir.resolve("keyprov_ecdh_v1_request.bin"), request.toByteArray());

    // ---- Response: exactly two ECDH-ES v1 items ------------------------------
    WrappedKeyItem upItem = ecdhV1Item(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD, "biz-key-up-0002",
        upParameters, upKcv, (byte) 0x71);
    WrappedKeyItem downItem = ecdhV1Item(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD, "biz-key-down-0002",
        upParameters, downKcv, (byte) 0x72);
    byte[] upEnvelopeDigest = KeyprovCanonicalV1.envelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, upItem);
    byte[] downEnvelopeDigest = KeyprovCanonicalV1.envelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, downItem);
    write(outDir.resolve("keyprov_ecdh_v1_envelope_digest_up.bin"), upEnvelopeDigest);
    write(outDir.resolve("keyprov_ecdh_v1_envelope_digest_down.bin"), downEnvelopeDigest);

    KeyProvisioningResponse response = KeyProvisioningResponse.newBuilder()
        .setRequestId(REQUEST_ID)
        .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
        .addItems(upItem).addItems(downItem)
        .setExpireAtMs(T_EXPIRE)
        .build();
    // fail-fast: the golden response must satisfy the §6.2 consumer gates.
    KeyprovCanonicalV1.validateEcdhEsV1Item(REQUEST_ID, BUSINESS_DOMAIN, upItem);
    KeyprovCanonicalV1.validateEcdhEsV1Item(REQUEST_ID, BUSINESS_DOMAIN, downItem);
    write(outDir.resolve("keyprov_ecdh_v1_response.bin"), response.toByteArray());

    // ---- Ack bound to the response (§5) --------------------------------------
    KeyImportItemResult upImport = KeyImportItemResult.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("biz-key-up-0002")
        .setBusinessKeyVersion(3L).setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(fill((byte) 0x55, 32)))
        .setProofAlgorithm("HMAC-SHA256")
        .setEnvelopeDigest(ByteString.copyFrom(upEnvelopeDigest))
        .setKeyCheckValue(ByteString.copyFrom(upKcv))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
        .build();
    KeyImportItemResult downImport = upImport.toBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId("biz-key-down-0002")
        .setEnvelopeDigest(ByteString.copyFrom(downEnvelopeDigest))
        .setKeyCheckValue(ByteString.copyFrom(downKcv))
        .setImportProof(ByteString.copyFrom(fill((byte) 0x56, 32)))
        .build();
    KeyProvisioningAck ack = KeyProvisioningAck.newBuilder()
        .setRequestId(REQUEST_ID).addItems(upImport).addItems(downImport)
        .setTimestampMs(T0 + 1000).build();
    KeyprovCanonicalV1.validateAckBinding(response, ack); // fail-fast: ACK must bind
    write(outDir.resolve("keyprov_ecdh_v1_ack.bin"), ack.toByteArray());

    // ---- canonical proof inputs (§5, §9 item 2) ------------------------------
    write(outDir.resolve("keyprov_ecdh_v1_proof_input_up.bin"),
        KeyprovCanonicalV1.proofInput(REQUEST_ID, BUSINESS_DOMAIN, upImport));
    write(outDir.resolve("keyprov_ecdh_v1_proof_input_down.bin"),
        KeyprovCanonicalV1.proofInput(REQUEST_ID, BUSINESS_DOMAIN, downImport));

    // ---- unknown field/enum preservation on the v1 request (§9 item 3) -------
    KeyProvisioningRequest unknownField = request.toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(12345L).build()).build())
        .build();
    write(outDir.resolve("keyprov_ecdh_v1_unknown_field.bin"), unknownField.toByteArray());
    KeyProvisioningRequest unknownFormat = request.toBuilder()
        .setSupportedEnvelopeFormatsValue(0, 777).build();
    write(outDir.resolve("keyprov_ecdh_v1_unknown_format.bin"), unknownFormat.toByteArray());

    // ---- Canonical Envelope wrapping (§9 item 7 relay) -----------------------
    write(outDir.resolve("envelope_keyprov_ecdh_v1_request.bin"),
        envelope(Envelope.MessageKind.MESSAGE_KIND_REQUEST, REQUEST_ID, "msg-kp-ecdh-req-0002", null,
            "security.keyprov.v1.KeyProvisioningRequest", request.toByteArray()));
    write(outDir.resolve("envelope_keyprov_ecdh_v1_response.bin"),
        envelope(Envelope.MessageKind.MESSAGE_KIND_RESPONSE, REQUEST_ID, "msg-kp-ecdh-resp-0002",
            "msg-kp-ecdh-req-0002", "security.keyprov.v1.KeyProvisioningResponse", response.toByteArray()));
    write(outDir.resolve("envelope_keyprov_ecdh_v1_ack.bin"),
        envelope(Envelope.MessageKind.MESSAGE_KIND_REQUEST, REQUEST_ID, "msg-kp-ecdh-ack-0002",
            "msg-kp-ecdh-resp-0002", "security.keyprov.v1.KeyProvisioningAck", ack.toByteArray()));

    System.out.println("[java] keyprov ECDH-ES v1 golden files written:");
    System.out.println("  parameters:          " + upParameters.length + " bytes");
    System.out.println("  envelope_digest(up): " + upEnvelopeDigest.length + " bytes");
    System.out.println("  aad_digest:          " + aadDigest.length + " bytes");
    System.out.println("  kcv(up):             " + upKcv.length + " bytes");
    System.out.println("  request:             " + request.toByteArray().length + " bytes");
    System.out.println("  response:            " + response.toByteArray().length + " bytes");
    System.out.println("  ack:                 " + ack.toByteArray().length + " bytes");
    System.out.println("  proof_input(up):     "
        + KeyprovCanonicalV1.proofInput(REQUEST_ID, BUSINESS_DOMAIN, upImport).length + " bytes");
  }

  private static WrappedKeyItem ecdhV1Item(KeyPurpose purpose, String keyId, byte[] parameters,
      byte[] kcv, byte fill) {
    WrappedKeyItem.Builder b = WrappedKeyItem.newBuilder()
        .setPurpose(purpose)
        .setKeyId(keyId)
        .setBusinessKeyVersion(3L)
        .setWrappedKey(ByteString.copyFrom(fill(fill, 64)))
        .setKeyAlgorithm(KeyprovCanonicalV1.KEY_ALGORITHM_V1)
        .setWrappingSuite(WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
        .setValidFromMs(T0)
        .setValidToMs(T_EXPIRE)
        .setParameters(ByteString.copyFrom(parameters))
        .setKeyCheckValue(ByteString.copyFrom(kcv))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
    WrappedKeyItem item = b.build();
    byte[] digest = KeyprovCanonicalV1.envelopeDigest(REQUEST_ID, BUSINESS_DOMAIN, item);
    return item.toBuilder().setEnvelopeDigest(ByteString.copyFrom(digest)).build();
  }

  private static byte[] envelope(Envelope.MessageKind kind, String requestId, String messageId,
      String correlationId, String payloadType, byte[] payload) {
    Envelope.VehicleMessageEnvelope.Builder b = Envelope.VehicleMessageEnvelope.newBuilder()
        .setRequestId(requestId)
        .setTimestampMs(T0)
        .setProtocolVersion("keyprov-v1")
        .setDeviceId("TBOX-0002")
        .setVin("LSVAB4187N2188888")
        .setPayloadType(payloadType)
        .setPayload(ByteString.copyFrom(payload))
        .setMessageId(messageId)
        .setMessageKind(kind)
        .setService("security.keyprov")
        .setExpireAtMs(T_EXPIRE);
    if (correlationId != null) {
      b.setCorrelationId(correlationId);
    }
    return b.build().toByteArray();
  }

  private static byte[] fill(byte value, int length) {
    byte[] out = new byte[length];
    Arrays.fill(out, value);
    return out;
  }

  private static byte[] hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
