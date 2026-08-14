import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import vagw.v1.Delivery;

/**
 * VAGW golden producer (PAR-PROTO-DSN-CR-003 §9 acceptance #2).
 *
 * Produces canonical reference serialization bytes for
 * vagw.v1.Delivery.GatewayDeliveryStatus, covering the contract matrix:
 *   - Outcome tri-state: OUTCOME_ACCEPTED / OUTCOME_REJECTED / OUTCOME_UNKNOWN
 *   - optional correlation_id: absent / present
 *   - optional retry_after_ms: absent / present
 *   - unknown-field and unknown-enum preservation (acceptance #3)
 *
 * VAGW and IOV-OTA consume the SAME proto-vagw artifact (no local proto copy,
 * no field alias, no JSON fallback), so cross-service byte consistency is
 * guaranteed by construction; these committed bytes are the regression
 * reference (hashes recorded in provenance/vehicle-proto-baseline.yaml).
 */
public class VagwGoldenProducer {
  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    // ---- OUTCOME_ACCEPTED, all fields set (correlation_id + retry_after_ms present)
    Delivery.GatewayDeliveryStatus accepted = Delivery.GatewayDeliveryStatus.newBuilder()
        .setOriginalMessageId("msg-3001")
        .setCorrelationId("corr-4001")
        .setVin("LSVAB4187N2188888")
        .setStage("MQTT_PUBLISHED")
        .setOutcome(Delivery.Outcome.OUTCOME_ACCEPTED)
        .setReason("")
        .setRetryable(false)
        .setRetryAfterMs(0)
        .setOccurredAtMs(1723600000000L)
        .build();
    write(outDir.resolve("vagw_delivery_accepted.bin"), accepted.toByteArray());

    // ---- OUTCOME_REJECTED, correlation_id absent, retry_after_ms absent
    Delivery.GatewayDeliveryStatus rejected = Delivery.GatewayDeliveryStatus.newBuilder()
        .setOriginalMessageId("msg-3002")
        .setVin("LSVAB4187N2188888")
        .setStage("DOWNLINK_RECEIVED")
        .setOutcome(Delivery.Outcome.OUTCOME_REJECTED)
        .setReason("VEHICLE_OFFLINE")
        .setRetryable(true)
        .setOccurredAtMs(1723600001000L)
        .build();
    write(outDir.resolve("vagw_delivery_rejected.bin"), rejected.toByteArray());

    // ---- OUTCOME_UNKNOWN, correlation_id present, retry_after_ms absent
    Delivery.GatewayDeliveryStatus unknown = Delivery.GatewayDeliveryStatus.newBuilder()
        .setOriginalMessageId("msg-3003")
        .setCorrelationId("corr-4003")
        .setVin("LSVAB4187N2188888")
        .setStage("MQTT_PUBLISHED")
        .setOutcome(Delivery.Outcome.OUTCOME_UNKNOWN)
        .setReason("MQTT_PUBLISH_FAILED")
        .setRetryable(true)
        .setOccurredAtMs(1723600002000L)
        .build();
    write(outDir.resolve("vagw_delivery_unknown.bin"), unknown.toByteArray());

    // ---- Unknown field preservation: accepted + raw unknown tag 99 varint
    UnknownFieldSet unknownField = UnknownFieldSet.newBuilder()
        .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(12345L).build())
        .build();
    Delivery.GatewayDeliveryStatus withUnknownField = accepted.toBuilder()
        .setUnknownFields(unknownField)
        .build();
    write(outDir.resolve("vagw_delivery_unknown_field.bin"), withUnknownField.toByteArray());

    // ---- Unknown enum preservation: out-of-range enum value 999
    Delivery.GatewayDeliveryStatus withUnknownEnum = accepted.toBuilder()
        .setOutcomeValue(999)
        .build();
    write(outDir.resolve("vagw_delivery_unknown_enum.bin"), withUnknownEnum.toByteArray());

    System.out.println("[java] vagw golden files written:");
    System.out.println("  accepted:  " + accepted.toByteArray().length + " bytes"
        + " (correlationId=" + accepted.hasCorrelationId()
        + ", retryAfterMs=" + accepted.hasRetryAfterMs() + ")");
    System.out.println("  rejected:  " + rejected.toByteArray().length + " bytes"
        + " (correlationId=" + rejected.hasCorrelationId()
        + ", retryAfterMs=" + rejected.hasRetryAfterMs() + ")");
    System.out.println("  unknown:   " + unknown.toByteArray().length + " bytes"
        + " (correlationId=" + unknown.hasCorrelationId()
        + ", retryAfterMs=" + unknown.hasRetryAfterMs() + ")");
    System.out.println("  unknown-field: " + withUnknownField.toByteArray().length + " bytes");
    System.out.println("  unknown-enum:  " + withUnknownEnum.toByteArray().length + " bytes");
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
