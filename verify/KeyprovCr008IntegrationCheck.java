import com.google.protobuf.Message;
import com.google.protobuf.Parser;
import com.google.protobuf.UnknownFieldSet;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import net.hwyz.iov.security.keyprov.v1.ImportProofAlgorithm;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;

import vehicle.common.v1.Envelope;

/**
 * KeyProv CR-008 import attestation integration check
 * (PAR-PROTO-DSN-CR-008 §3/§4/§5/§7/§9, REQ-CR-008 US-039).
 *
 * Runs against the Java-produced CR-008 golden bytes and verifies the
 * cross-process / cross-service integration properties that the descriptor
 * contract check alone cannot:
 *
 *   1. byte-for-byte relay    — VAGW / TBOX-MQTT / TBOX-TSP may forward the CR-008
 *                               ack and its Envelope without re-encoding;
 *   2. additive downgrade      — stripping fields 10/11 yields the pre-CR-008
 *                               (CR-007 shaped) item, so a legacy consumer ignores
 *                               them instead of mis-reading the payload;
 *   3. fail-closed             — unknown ImportProofAlgorithm / non-empty legacy
 *                               proof_algorithm never become capability-ready;
 *   4. P1363 contract          — 63/65 byte, DER, r/s = 0, r/s >= n and high-S are
 *                               deterministically rejected (format/range only; the
 *                               real ECDSA verify is owned by FW-SEC);
 *   5. proofInputV1 binding    — every canonical segment is bound;
 *   6. replay idempotency      — re-encode is byte-identical.
 *
 * Consumes verify/golden/expected/keyprov_cr008_*.bin produced by
 * KeyprovCr008GoldenProducer. Deliberately imports NO cryptography: this repo
 * validates carrying and canonical input only (design §5/§10).
 */
public class KeyprovCr008IntegrationCheck {

  private static final BigInteger P256_N = new BigInteger(
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    Path dir = Paths.get(args.length > 0 ? args[0] : "verify/golden/expected");

    // ---- 1. byte-for-byte relay ---------------------------------------------
    relay(dir, "keyprov_cr008_ack.bin", KeyProvisioningAck.parser());
    relay(dir, "keyprov_cr008_unknown_algorithm.bin", KeyImportItemResult.parser());
    relay(dir, "envelope_keyprov_cr008_ack.bin", Envelope.VehicleMessageEnvelope.parser());

    Envelope.VehicleMessageEnvelope envAck =
        Envelope.VehicleMessageEnvelope.parseFrom(read(dir, "envelope_keyprov_cr008_ack.bin"));
    check("envelope service unchanged", envAck.getService().equals("security.keyprov"));
    check("envelope protocol_version unchanged", envAck.getProtocolVersion().equals("keyprov-v1"));
    check("envelope payload_type is exact full name",
        envAck.getPayloadType().equals("security.keyprov.v1.KeyProvisioningAck"));

    // ---- 2. additive downgrade -> pre-CR-008 (CR-007 shaped) item ------------
    byte[] ackBytes = read(dir, "keyprov_cr008_ack.bin");
    KeyProvisioningAck ack = KeyProvisioningAck.parseFrom(ackBytes);
    check("CR-008 ack carries exactly two purposes", ack.getItemsCount() == 2);
    boolean itemsAdditive = true;
    for (KeyImportItemResult item : ack.getItemsList()) {
      byte[] stripped = strip(UnknownFieldSet.parseFrom(item.toByteArray()), 10, 11).toByteArray();
      byte[] legacyView = item.toBuilder()
          .clearImportProofAlgorithm().clearRecipientCertificateDigest().build().toByteArray();
      if (!Arrays.equals(stripped, legacyView)) {
        itemsAdditive = false;
      }
      // Legacy fields 5..9 must survive (core ACK binding still intact).
      if (item.getImportProof().size() != 64
          || item.getEnvelopeDigest().size() != 32
          || item.getKeyCheckValue().size() != 3
          || !item.getProofAlgorithm().isEmpty()) {
        itemsAdditive = false;
      }
    }
    check("legacy consumer sees pre-CR-008 KeyImportItemResult bytes (fields 10/11 additive)",
        itemsAdditive);

    // ---- 3. fail-closed on unknown / legacy algorithm -----------------------
    KeyImportItemResult unknownAlgorithm =
        KeyImportItemResult.parseFrom(read(dir, "keyprov_cr008_unknown_algorithm.bin"));
    check("unknown import_proof_algorithm preserved on the wire",
        unknownAlgorithm.getImportProofAlgorithmValue() == 777);
    check("unknown import_proof_algorithm fail-closed (forNumber == null)",
        ImportProofAlgorithm.forNumber(777) == null);
    check("unknown algorithm item is not capability-ready",
        !KeyprovCanonicalV1.isCr008Attested(unknownAlgorithm));
    boolean unknownRejected = false;
    try {
      KeyprovCanonicalV1.validateCr008SuccessItem(
          unknownAlgorithm, unknownAlgorithm.getRecipientCertificateDigest().toByteArray());
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      unknownRejected = true;
    }
    check("unknown algorithm success item rejected", unknownRejected);

    KeyImportItemResult cr008Item = ack.getItems(0);
    check("CR-008 item is capability-ready", KeyprovCanonicalV1.isCr008Attested(cr008Item));
    KeyImportItemResult legacyProofItem = cr008Item.toBuilder()
        .setImportProofAlgorithm(ImportProofAlgorithm.IMPORT_PROOF_ALGORITHM_UNSPECIFIED)
        .setProofAlgorithm("HMAC-SHA256").build();
    check("legacy proof_algorithm string alone is not capability-ready",
        !KeyprovCanonicalV1.isCr008Attested(legacyProofItem));
    check("legacy proofInput(...) is stable but cannot drive capability",
        Arrays.equals(KeyprovCanonicalV1.proofInput("req-kp-0003", "V2C_COMM", legacyProofItem),
            KeyprovCanonicalV1.proofInput("req-kp-0003", "V2C_COMM", legacyProofItem))
            && !KeyprovCanonicalV1.isCr008Attested(legacyProofItem));

    // ---- 4. P1363 format / range contract (no crypto) -----------------------
    expectAccepted("valid P1363 low-S (r=1,s=1)", p1363(BigInteger.ONE, BigInteger.ONE));
    expectRejected("63-byte proof", new byte[63]);
    expectRejected("65-byte proof", new byte[65]);
    expectRejected("DER-encoded signature", derSignature());
    expectRejected("r = 0", p1363(BigInteger.ZERO, BigInteger.ONE));
    expectRejected("s = 0", p1363(BigInteger.ONE, BigInteger.ZERO));
    expectRejected("r >= n", p1363(P256_N, BigInteger.ONE));
    expectRejected("s >= n", p1363(BigInteger.ONE, P256_N));
    expectRejected("high-S (s = n/2 + 1)", p1363(BigInteger.ONE, P256_N.shiftRight(1).add(BigInteger.ONE)));

    // ---- 5. proofInputV1 canonical binding ----------------------------------
    String req = "req-kp-0003";
    String domain = KeyprovCanonicalV1.BUSINESS_DOMAIN_V1;
    byte[] baseProofInput = KeyprovCanonicalV1.proofInputV1(req, domain, cr008Item);
    check("proofInputV1 binds requestId",
        differs(baseProofInput, KeyprovCanonicalV1.proofInputV1("req-other", domain, cr008Item)));
    check("proofInputV1 binds purpose", differs(baseProofInput, KeyprovCanonicalV1.proofInputV1(
        req, domain, cr008Item.toBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).build())));
    check("proofInputV1 binds keyId (digest)",
        differs(baseProofInput, KeyprovCanonicalV1.proofInputV1(
            req, domain, cr008Item.toBuilder().setKeyId("another-key").build())));
    check("proofInputV1 binds businessKeyVersion (uint64be)",
        differs(baseProofInput, KeyprovCanonicalV1.proofInputV1(
            req, domain, cr008Item.toBuilder().setBusinessKeyVersion(128L).build())));
    check("proofInputV1 binds envelopeDigest",
        differs(baseProofInput, KeyprovCanonicalV1.proofInputV1(
            req, domain, cr008Item.toBuilder()
                .setEnvelopeDigest(com.google.protobuf.ByteString.copyFrom(new byte[32])).build())));
    check("proofInputV1 binds keyCheckValue",
        differs(baseProofInput, KeyprovCanonicalV1.proofInputV1(
            req, domain, cr008Item.toBuilder()
                .setKeyCheckValue(com.google.protobuf.ByteString.copyFrom(new byte[3])).build())));
    check("canonical encoding binds businessDomain segment",
        differs(KeyprovCanonicalV1.proofInput(req, "V2C_COMM", cr008Item),
            KeyprovCanonicalV1.proofInput(req, "V2C_OTHER", cr008Item)));
    expectViolation("proofInputV1 rejects lowercase businessDomain",
        () -> KeyprovCanonicalV1.proofInputV1(req, "v2c_comm", cr008Item));
    expectViolation("proofInputV1 rejects UNSPECIFIED purpose", () -> KeyprovCanonicalV1.proofInputV1(
        req, domain, cr008Item.toBuilder().setPurpose(KeyPurpose.KEY_PURPOSE_UNSPECIFIED).build()));
    expectViolation("proofInputV1 rejects out-of-range version", () -> KeyprovCanonicalV1.proofInputV1(
        req, domain, cr008Item.toBuilder().setBusinessKeyVersion(1L << 63).build()));

    // ---- 6. replay idempotency ----------------------------------------------
    check("ack re-encode is byte-identical (replay idempotency)",
        Arrays.equals(ackBytes, KeyProvisioningAck.parseFrom(ackBytes).toByteArray()));
    check("proofInputV1 re-encode is byte-identical",
        Arrays.equals(baseProofInput, KeyprovCanonicalV1.proofInputV1(req, domain, cr008Item)));

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ KEYPROV CR-008 INTEGRATION CHECK PASSED "
          + "(relay + additive downgrade + fail-closed + P1363 + proofInputV1 + replay)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " KEYPROV CR-008 INTEGRATION failure(s)");
      System.exit(1);
    }
  }

  // ---- helpers --------------------------------------------------------------

  private static <T extends Message> void relay(Path dir, String file, Parser<T> parser)
      throws Exception {
    byte[] bytes = read(dir, file);
    check("relay byte-for-byte: " + file, Arrays.equals(bytes, parser.parseFrom(bytes).toByteArray()));
  }

  private static UnknownFieldSet strip(UnknownFieldSet raw, int... fieldNumbers) {
    Set<Integer> drop = new LinkedHashSet<>();
    for (int n : fieldNumbers) {
      drop.add(n);
    }
    UnknownFieldSet.Builder b = UnknownFieldSet.newBuilder();
    raw.asMap().forEach((num, field) -> {
      if (!drop.contains(num)) {
        b.addField(num, field);
      }
    });
    return b.build();
  }

  private static void expectAccepted(String label, byte[] proof) {
    try {
      KeyprovCanonicalV1.validateP1363LowS(proof);
      check("accept " + label, true);
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      check("accept " + label + " (unexpected reject: " + e.getMessage() + ")", false);
    }
  }

  private static void expectRejected(String label, byte[] proof) {
    try {
      KeyprovCanonicalV1.validateP1363LowS(proof);
      check("reject " + label, false);
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      check("reject " + label, true);
    }
  }

  private static void expectViolation(String label, Runnable r) {
    try {
      r.run();
      check(label, false);
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      check(label, true);
    }
  }

  private static boolean differs(byte[] a, byte[] b) {
    return !Arrays.equals(a, b);
  }

  private static byte[] p1363(BigInteger r, BigInteger s) {
    byte[] out = new byte[64];
    System.arraycopy(toFixed(r, 32), 0, out, 0, 32);
    System.arraycopy(toFixed(s, 32), 0, out, 32, 32);
    return out;
  }

  private static byte[] toFixed(BigInteger v, int len) {
    byte[] b = v.toByteArray();
    byte[] out = new byte[len];
    if (b.length > len) {
      System.arraycopy(b, b.length - len, out, 0, len);
    } else {
      System.arraycopy(b, 0, out, len - b.length, b.length);
    }
    return out;
  }

  /** A minimal valid DER SEQUENCE(r=1, s=1): 30 06 02 01 01 02 01 01 (8 bytes != 64). */
  private static byte[] derSignature() {
    return new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
  }

  private static byte[] read(Path dir, String file) throws Exception {
    return Files.readAllBytes(dir.resolve(file));
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
