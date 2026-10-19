import com.google.protobuf.ByteString;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import net.hwyz.iov.security.keyprov.v1.ImportProofAlgorithm;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;

import vehicle.common.v1.Envelope;

/**
 * KeyProv CR-008 import attestation golden producer
 * (PAR-PROTO-DSN-CR-008 §3/§4/§5/§9, REQ-CR-008 US-039).
 *
 * Produces the Java reference bytes for the CR-008 additive surface:
 *   - proofInputV1 fixed vectors: purpose 1/2, businessKeyVersion boundaries
 *     (1, 127, 128, 255, 256, 2^32, 2^63-1) and keyIdDigest       (§9 item 1/2)
 *   - a CR-008 KeyProvisioningAck carrying fields 10/11 + its Envelope
 *   - an unknown-ImportProofAlgorithm wire vector (fail-closed vector) (§9 item 3)
 *
 * IMPORTANT (scope): PAR-PROTO does NOT sign and does NOT verify. The
 * import_proof bytes below are a deterministic P1363 low-S *placeholder*
 * (r = 1, s = 1) used only to pin the wire/canonical contract; it is NOT a real
 * signature. Real device signing is owned by TBOX-SEC and real ECDSA P-256
 * verification by FW-SEC. The hash of every file is recorded in
 * provenance/vehicle-proto-baseline.yaml; VEH-PROTO / TBOX generate C++ from the
 * released source / DescriptorSet and MUST round-trip byte-identically.
 *
 * businessDomain is the CR-008 strict value "V2C_COMM" (case-sensitive; no trim/
 * case-fold/alias/fallback). The CR-007 legacy "v2c_comm" vectors are untouched.
 */
public class KeyprovCr008GoldenProducer {
  static final long T0 = 1_760_000_000_000L;
  static final long T_EXPIRE = 1_760_000_600_000L;
  static final String REQUEST_ID = "req-kp-0003";
  static final String BUSINESS_DOMAIN = KeyprovCanonicalV1.BUSINESS_DOMAIN_V1; // "V2C_COMM"

  static final byte[] CERT_DIGEST = fill((byte) 0x61, 32);
  static final byte[] ENVELOPE_DIGEST_UP = fill((byte) 0x74, 32);
  static final byte[] ENVELOPE_DIGEST_DOWN = fill((byte) 0x75, 32);

  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    byte[] upKcv = KeyprovCanonicalV1.keyCheckValue(fill((byte) 0x81, 32));
    byte[] downKcv = KeyprovCanonicalV1.keyCheckValue(fill((byte) 0x91, 32));

    KeyImportItemResult upItem = cr008Item(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD,
        "biz-key-up-0003", 3L, ENVELOPE_DIGEST_UP, upKcv);
    KeyImportItemResult downItem = cr008Item(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD,
        "biz-key-down-0003", 3L, ENVELOPE_DIGEST_DOWN, downKcv);
    // fail-fast: the golden items must satisfy the §3.1/§5 gates.
    KeyprovCanonicalV1.validateCr008SuccessItem(upItem, CERT_DIGEST);
    KeyprovCanonicalV1.validateCr008SuccessItem(downItem, CERT_DIGEST);

    // ---- proofInputV1 vectors (§4.1/§9 items 1-2) ----------------------------
    byte[] upProofInput = KeyprovCanonicalV1.proofInputV1(REQUEST_ID, BUSINESS_DOMAIN, upItem);
    byte[] downProofInput = KeyprovCanonicalV1.proofInputV1(REQUEST_ID, BUSINESS_DOMAIN, downItem);
    write(outDir.resolve("keyprov_cr008_proof_input_up.bin"), upProofInput);
    write(outDir.resolve("keyprov_cr008_proof_input_down.bin"), downProofInput);
    write(outDir.resolve("keyprov_cr008_key_id_digest.bin"),
        KeyprovCanonicalV1.keyIdDigest("biz-key-up-0003"));

    long[] versions = {1L, 127L, 128L, 255L, 256L, 1L << 32, (1L << 63) - 1};
    String[] versionNames = {"v1", "v127", "v128", "v255", "v256", "v2e32", "v2e63m1"};
    for (int i = 0; i < versions.length; i++) {
      KeyImportItemResult vItem = upItem.toBuilder().setBusinessKeyVersion(versions[i]).build();
      write(outDir.resolve("keyprov_cr008_proof_input_" + versionNames[i] + ".bin"),
          KeyprovCanonicalV1.proofInputV1(REQUEST_ID, BUSINESS_DOMAIN, vItem));
    }

    // ---- CR-008 Ack carrying fields 10/11 (+ legacy field 6 empty) -----------
    KeyProvisioningAck ack = KeyProvisioningAck.newBuilder()
        .setRequestId(REQUEST_ID).addItems(upItem).addItems(downItem)
        .setTimestampMs(T0 + 1000).build();
    write(outDir.resolve("keyprov_cr008_ack.bin"), ack.toByteArray());

    // ---- unknown ImportProofAlgorithm (fail-closed vector) -------------------
    KeyImportItemResult unknownAlgorithm = upItem.toBuilder()
        .setImportProofAlgorithmValue(777).build();
    write(outDir.resolve("keyprov_cr008_unknown_algorithm.bin"), unknownAlgorithm.toByteArray());

    // ---- Canonical Envelope wrapping the CR-008 Ack --------------------------
    write(outDir.resolve("envelope_keyprov_cr008_ack.bin"),
        envelope(Envelope.MessageKind.MESSAGE_KIND_REQUEST, REQUEST_ID, "msg-kp-cr008-ack-0003",
            "msg-kp-cr008-resp-0003", "security.keyprov.v1.KeyProvisioningAck",
            ack.toByteArray()));

    System.out.println("[java] keyprov CR-008 golden files written:");
    System.out.println("  proof_input(up):   " + upProofInput.length + " bytes");
    System.out.println("  proof_input(down): " + downProofInput.length + " bytes");
    System.out.println("  ack:               " + ack.toByteArray().length + " bytes");
  }

  /** A CR-008 success item: new algorithm enum + 32B cert digest, legacy string empty. */
  private static KeyImportItemResult cr008Item(KeyPurpose purpose, String keyId, long version,
      byte[] envelopeDigest, byte[] kcv) {
    return KeyImportItemResult.newBuilder()
        .setPurpose(purpose)
        .setKeyId(keyId)
        .setBusinessKeyVersion(version)
        .setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(lowSPlaceholder()))
        // field 6 intentionally left empty: it must not form a second source of truth.
        .setEnvelopeDigest(ByteString.copyFrom(envelopeDigest))
        .setKeyCheckValue(ByteString.copyFrom(kcv))
        .setEnvelopeFormat(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)
        .setImportProofAlgorithm(ImportProofAlgorithm.IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363)
        .setRecipientCertificateDigest(ByteString.copyFrom(CERT_DIGEST))
        .build();
  }

  /**
   * Deterministic P1363 low-S wire placeholder (r = 1, s = 1). NOT a signature:
   * it only pins the 64-byte framing and passes the PAR-PROTO range gate.
   */
  private static byte[] lowSPlaceholder() {
    byte[] out = new byte[KeyprovCanonicalV1.P1363_SIGNATURE_BYTES];
    out[31] = 0x01;
    out[63] = 0x01;
    return out;
  }

  private static byte[] envelope(Envelope.MessageKind kind, String requestId, String messageId,
      String correlationId, String payloadType, byte[] payload) {
    Envelope.VehicleMessageEnvelope.Builder b = Envelope.VehicleMessageEnvelope.newBuilder()
        .setRequestId(requestId)
        .setTimestampMs(T0)
        .setProtocolVersion("keyprov-v1")
        .setDeviceId("TBOX-0003")
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

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
