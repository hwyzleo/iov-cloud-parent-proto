import com.google.protobuf.Message;
import com.google.protobuf.Parser;
import com.google.protobuf.UnknownFieldSet;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;

import vehicle.common.v1.Envelope;

/**
 * KeyProv ECDH-ES v1 integration check
 * (PAR-PROTO-DSN-CR-007 §8/§9 items 3, 5, 6, 7; REQ-CR-007 acceptance #3/#5/#6).
 *
 * Runs against the Java-produced golden reference bytes and verifies the
 * cross-process / cross-service integration properties that a descriptor
 * contract check alone cannot:
 *
 *   1. byte-for-byte relay   — parse + re-serialize of every envelope v1 payload
 *                              and its canonical Envelope is identity, i.e.
 *                              VAGW / TBOX-MQTT / TBOX-TSP may forward the bytes
 *                              without re-encoding (§9 item 7, acceptance #6);
 *   2. additive downgrade     — stripping the CR-007 fields from the wire yields
 *                              exactly the CR-006 message bytes, so a legacy
 *                              consumer ignores them (unknown-field tolerance)
 *                              instead of mis-reading the payload (§8, §9 item 3);
 *   3. unknown-format fail-closed + legacy-request non-negotiation (§6.1, §9 item 5);
 *   4. replay idempotency     — the same request/correlation re-encodes to the
 *                              same bytes (§9 item 3, acceptance #3).
 *
 * Consumes verify/golden/expected/keyprov_ecdh_v1_*.bin produced by
 * KeyprovCr007GoldenProducer.
 */
public class KeyprovCr007IntegrationCheck {

  private static int failures = 0;

  public static void main(String[] args) throws Exception {
    Path dir = Paths.get(args.length > 0 ? args[0] : "verify/golden/expected");

    // ---- 1. byte-for-byte relay (VAGW / MQTT transparency) -------------------
    relay(dir, "keyprov_ecdh_v1_request.bin", KeyProvisioningRequest.parser());
    relay(dir, "keyprov_ecdh_v1_response.bin", KeyProvisioningResponse.parser());
    relay(dir, "keyprov_ecdh_v1_ack.bin", KeyProvisioningAck.parser());
    relay(dir, "keyprov_ecdh_v1_unknown_field.bin", KeyProvisioningRequest.parser());
    relay(dir, "envelope_keyprov_ecdh_v1_request.bin", Envelope.VehicleMessageEnvelope.parser());
    relay(dir, "envelope_keyprov_ecdh_v1_response.bin", Envelope.VehicleMessageEnvelope.parser());
    relay(dir, "envelope_keyprov_ecdh_v1_ack.bin", Envelope.VehicleMessageEnvelope.parser());

    // Envelope metadata must stay frozen (no new service/protocol_version).
    Envelope.VehicleMessageEnvelope envReq =
        Envelope.VehicleMessageEnvelope.parseFrom(read(dir, "envelope_keyprov_ecdh_v1_request.bin"));
    check("envelope service unchanged", envReq.getService().equals("security.keyprov"));
    check("envelope protocol_version unchanged", envReq.getProtocolVersion().equals("keyprov-v1"));
    check("envelope payload_type is exact full name",
        envReq.getPayloadType().equals("security.keyprov.v1.KeyProvisioningRequest"));

    // ---- 2. additive downgrade -> CR-006 message bytes -----------------------
    byte[] reqBytes = read(dir, "keyprov_ecdh_v1_request.bin");
    KeyProvisioningRequest req = KeyProvisioningRequest.parseFrom(reqBytes);
    byte[] reqLegacy = req.toBuilder().clearSupportedEnvelopeFormats().build().toByteArray();
    check("legacy consumer sees CR-006 request bytes (field 11 is additive)",
        Arrays.equals(strip(UnknownFieldSet.parseFrom(reqBytes), 11).toByteArray(), reqLegacy));

    byte[] respBytes = read(dir, "keyprov_ecdh_v1_response.bin");
    KeyProvisioningResponse resp = KeyProvisioningResponse.parseFrom(respBytes);
    boolean itemsAdditive = true;
    for (WrappedKeyItem item : resp.getItemsList()) {
      if (!Arrays.equals(strip(UnknownFieldSet.parseFrom(item.toByteArray()), 10, 11, 12).toByteArray(),
          item.toBuilder().clearEnvelopeDigest().clearKeyCheckValue().clearEnvelopeFormat()
              .build().toByteArray())) {
        itemsAdditive = false;
      }
    }
    check("legacy consumer sees CR-006 WrappedKeyItem bytes (fields 10..12 additive)", itemsAdditive);
    for (WrappedKeyItem item : resp.getItemsList()) {
      check("v1 item carries 32-byte digest + 3-byte KCV + negotiated format",
          item.getEnvelopeDigest().size() == 32 && item.getKeyCheckValue().size() == 3
              && item.getEnvelopeFormat() == KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
    }

    KeyProvisioningAck ack = KeyProvisioningAck.parseFrom(read(dir, "keyprov_ecdh_v1_ack.bin"));
    boolean ackAdditive = true;
    for (KeyImportItemResult item : ack.getItemsList()) {
      if (!Arrays.equals(strip(UnknownFieldSet.parseFrom(item.toByteArray()), 7, 8, 9).toByteArray(),
          item.toBuilder().clearEnvelopeDigest().clearKeyCheckValue().clearEnvelopeFormat()
              .build().toByteArray())) {
        ackAdditive = false;
      }
    }
    check("legacy consumer sees CR-006 KeyImportItemResult bytes (fields 7..9 additive)", ackAdditive);
    check("ACK binds the response digests/KCVs",
        ack.getItemsCount() == resp.getItemsCount()
            && ack.getItems(0).getEnvelopeDigest().equals(resp.getItems(0).getEnvelopeDigest())
            && ack.getItems(1).getEnvelopeDigest().equals(resp.getItems(1).getEnvelopeDigest())
            && ack.getItems(0).getKeyCheckValue().equals(resp.getItems(0).getKeyCheckValue()));

    // ---- 3. capability negotiation ------------------------------------------
    check("v1 request negotiated the envelope format",
        req.getSupportedEnvelopeFormatsList().contains(
            KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1));
    boolean legacyRejected = false;
    try {
      KeyprovCanonicalV1.requireEnvelopeFormatNegotiated(reqLegacyFormatList(req));
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      legacyRejected = true;
    }
    check("legacy request (no field 11) must not get envelope v1", legacyRejected);

    byte[] unknownFormatBytes = read(dir, "keyprov_ecdh_v1_unknown_format.bin");
    KeyProvisioningRequest unknownFormat = KeyProvisioningRequest.parseFrom(unknownFormatBytes);
    check("unknown envelope format value preserved on the wire",
        unknownFormat.getSupportedEnvelopeFormatsValue(0) == 777);
    check("unknown envelope format is fail-closed (forNumber == null)",
        KeyEnvelopeFormat.forNumber(777) == null);
    boolean unknownRejected = false;
    try {
      KeyprovCanonicalV1.requireEnvelopeFormatNegotiated(unknownFormat.getSupportedEnvelopeFormatsList());
    } catch (KeyprovCanonicalV1.InvalidKeyprovInput e) {
      unknownRejected = true;
    }
    check("unknown-format-only request rejected (fail-closed)", unknownRejected);

    // ---- 4. replay idempotency (same bytes on re-encode) --------------------
    check("request re-encode is byte-identical (replay idempotency)",
        Arrays.equals(reqBytes, KeyProvisioningRequest.parseFrom(reqBytes).toByteArray()));
    check("response re-encode is byte-identical (byte-level idempotency)",
        Arrays.equals(respBytes, KeyProvisioningResponse.parseFrom(respBytes).toByteArray()));

    System.out.println();
    if (failures == 0) {
      System.out.println("✅ KEYPROV CR-007 INTEGRATION CHECK PASSED "
          + "(relay + additive downgrade + negotiation + replay)");
      System.exit(0);
    } else {
      System.out.println("❌ " + failures + " KEYPROV CR-007 INTEGRATION failure(s)");
      System.exit(1);
    }
  }

  /** The CR-006 (pre-CR-007) view of a request: no supported_envelope_formats. */
  private static java.util.List<KeyEnvelopeFormat> reqLegacyFormatList(KeyProvisioningRequest req) {
    return req.toBuilder().clearSupportedEnvelopeFormats().build()
        .getSupportedEnvelopeFormatsList();
  }

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
