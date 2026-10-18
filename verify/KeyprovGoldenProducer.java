import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAckResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatus;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatusRequest;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningStatusResponse;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;
import net.hwyz.iov.security.keyprov.v1.KeyPurposeStatus;
import net.hwyz.iov.security.keyprov.v1.ProtocolError;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

import vehicle.common.v1.Envelope;

/**
 * KeyProv golden producer (PAR-PROTO-DSN-CR-006 §3/§7, REQ US-018 acceptance #2).
 *
 * Produces canonical Java reference serialization bytes for all six
 * security.keyprov.v1 payloads and their canonical Envelope wrapping:
 *   - service = security.keyprov, protocol_version = keyprov-v1
 *   - payload_type = security.keyprov.v1.<MessageName> (exact full name)
 *   - MessageKind / direction / correlation per CR-006 §3
 *   - unknown-field and unknown-enum preservation (fail-closed evidence)
 *
 * VEH-PROTO / TBOX generate C++ from the released canonical source /
 * DescriptorSet and MUST round-trip byte-identically against these bytes; the
 * hashes are recorded in provenance/vehicle-proto-baseline.yaml.
 */
public class KeyprovGoldenProducer {
  static final long T0 = 1_760_000_000_000L;
  static final long T_EXPIRE = 1_760_000_600_000L;

  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    // ---- KeyProvisioningRequest (UP REQUEST) ---------------------------------
    KeyProvisioningRequest request = KeyProvisioningRequest.newBuilder()
        .setRequestId("req-kp-0001")
        .setIdempotencyKey("idem-kp-0001")
        .setBusinessDomain("v2c_comm")
        .addPurposes(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD)
        .addPurposes(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD)
        .setDeviceIdentityDigest(digest((byte) 0x11))
        .setCertificateRef(net.hwyz.iov.security.keyprov.v1.CertificateRef.newBuilder()
            .setCertificateDigest(digest((byte) 0x22))
            .setCertificateProfile("V2C_MTLS_P256")
            .setKeyEnciphermentKeyId("kek-kp-0001"))
        .addSupportedWrappingSuites(WrappingSuite.WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM)
        .addSupportedWrappingSuites(WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM)
        .addCurrentVersions(net.hwyz.iov.security.keyprov.v1.CurrentKeyVersion.newBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setBusinessKeyVersion(1L))
        .addCurrentVersions(net.hwyz.iov.security.keyprov.v1.CurrentKeyVersion.newBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setBusinessKeyVersion(1L))
        .setTimestampMs(T0)
        .setExpireAtMs(T_EXPIRE)
        .build();
    write(outDir.resolve("keyprov_request.bin"), request.toByteArray());

    // ---- KeyProvisioningResponse (DOWN RESPONSE, SUCCEEDED, 2 items) ---------
    WrappedKeyItem upItem = WrappedKeyItem.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("biz-key-up-0001")
        .setBusinessKeyVersion(2L).setWrappedKey(wrapped((byte) 0x33)).setKeyAlgorithm("AES-128-GCM")
        .setWrappingSuite(WrappingSuite.WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM)
        .setValidFromMs(T0).setValidToMs(T_EXPIRE).setParameters(ByteString.copyFrom(new byte[] {9, 9}))
        .build();
    WrappedKeyItem downItem = upItem.toBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId("biz-key-down-0001")
        .setWrappedKey(wrapped((byte) 0x44)).build();
    KeyProvisioningResponse response = KeyProvisioningResponse.newBuilder()
        .setRequestId("req-kp-0001")
        .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
        .addItems(upItem).addItems(downItem)
        .setExpireAtMs(T_EXPIRE)
        .build();
    write(outDir.resolve("keyprov_response_success.bin"), response.toByteArray());

    // ---- KeyProvisioningAck (UP REQUEST) -------------------------------------
    KeyImportItemResult upImport = KeyImportItemResult.newBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("biz-key-up-0001")
        .setBusinessKeyVersion(2L).setResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED)
        .setImportProof(ByteString.copyFrom(new byte[] {0x55, 0x56}))
        .setProofAlgorithm("HMAC-SHA256").build();
    KeyImportItemResult downImport = upImport.toBuilder()
        .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId("biz-key-down-0001")
        .setImportProof(ByteString.copyFrom(new byte[] {0x57, 0x58})).build();
    KeyProvisioningAck ack = KeyProvisioningAck.newBuilder()
        .setRequestId("req-kp-0001").addItems(upImport).addItems(downImport)
        .setTimestampMs(T0 + 1000).build();
    write(outDir.resolve("keyprov_ack.bin"), ack.toByteArray());

    // ---- KeyProvisioningAckResult (DOWN RESPONSE) ----------------------------
    KeyProvisioningAckResult ackResult = KeyProvisioningAckResult.newBuilder()
        .setRequestId("req-kp-0001")
        .setResult(KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED)
        .setOccurredAtMs(T0 + 2000).build();
    write(outDir.resolve("keyprov_ack_result.bin"), ackResult.toByteArray());

    // ---- KeyProvisioningStatusRequest (UP REQUEST) ---------------------------
    KeyProvisioningStatusRequest statusRequest = KeyProvisioningStatusRequest.newBuilder()
        .setRequestId("req-kp-0001").setTimestampMs(T0 + 3000).build();
    write(outDir.resolve("keyprov_status_request.bin"), statusRequest.toByteArray());

    // ---- KeyProvisioningStatusResponse (DOWN RESPONSE) -----------------------
    KeyProvisioningStatusResponse statusResponse = KeyProvisioningStatusResponse.newBuilder()
        .setRequestId("req-kp-0001")
        .setStatus(KeyProvisioningStatus.KEY_PROVISIONING_STATUS_ACTIVE)
        .addItems(KeyPurposeStatus.newBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_UPLINK_AEAD).setKeyId("biz-key-up-0001")
            .setBusinessKeyVersion(2L).setImportResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED))
        .addItems(KeyPurposeStatus.newBuilder()
            .setPurpose(KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD).setKeyId("biz-key-down-0001")
            .setBusinessKeyVersion(2L).setImportResult(KeyImportResult.KEY_IMPORT_RESULT_IMPORTED))
        .setOccurredAtMs(T0 + 4000).build();
    write(outDir.resolve("keyprov_status_response.bin"), statusResponse.toByteArray());

    // ---- Unknown-field / unknown-enum preservation ---------------------------
    KeyProvisioningRequest unknownField = request.toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(12345L).build()).build())
        .build();
    write(outDir.resolve("keyprov_unknown_field.bin"), unknownField.toByteArray());
    KeyProvisioningRequest unknownEnum = request.toBuilder().setPurposesValue(0, 999).build();
    write(outDir.resolve("keyprov_unknown_enum.bin"), unknownEnum.toByteArray());

    // ---- Canonical Envelope wrapping (CR-006 §3) -----------------------------
    Envelope.VehicleMessageEnvelope envRequest = envelope(
        Envelope.MessageKind.MESSAGE_KIND_REQUEST, request.getRequestId(), "msg-kp-req-0001", null,
        "security.keyprov.v1.KeyProvisioningRequest", request.toByteArray());
    write(outDir.resolve("envelope_keyprov_request.bin"), envRequest.toByteArray());

    Envelope.VehicleMessageEnvelope envResponse = envelope(
        Envelope.MessageKind.MESSAGE_KIND_RESPONSE, response.getRequestId(), "msg-kp-resp-0001",
        "msg-kp-req-0001", "security.keyprov.v1.KeyProvisioningResponse", response.toByteArray());
    write(outDir.resolve("envelope_keyprov_response.bin"), envResponse.toByteArray());

    Envelope.VehicleMessageEnvelope envAck = envelope(
        Envelope.MessageKind.MESSAGE_KIND_REQUEST, ack.getRequestId(), "msg-kp-ack-0001",
        "msg-kp-resp-0001", "security.keyprov.v1.KeyProvisioningAck", ack.toByteArray());
    write(outDir.resolve("envelope_keyprov_ack.bin"), envAck.toByteArray());

    Envelope.VehicleMessageEnvelope envAckResult = envelope(
        Envelope.MessageKind.MESSAGE_KIND_RESPONSE, ackResult.getRequestId(), "msg-kp-ackresult-0001",
        "msg-kp-ack-0001", "security.keyprov.v1.KeyProvisioningAckResult", ackResult.toByteArray());
    write(outDir.resolve("envelope_keyprov_ack_result.bin"), envAckResult.toByteArray());

    Envelope.VehicleMessageEnvelope envStatusRequest = envelope(
        Envelope.MessageKind.MESSAGE_KIND_REQUEST, statusRequest.getRequestId(),
        "msg-kp-statusreq-0001", null, "security.keyprov.v1.KeyProvisioningStatusRequest",
        statusRequest.toByteArray());
    write(outDir.resolve("envelope_keyprov_status_request.bin"), envStatusRequest.toByteArray());

    Envelope.VehicleMessageEnvelope envStatusResponse = envelope(
        Envelope.MessageKind.MESSAGE_KIND_RESPONSE, statusResponse.getRequestId(),
        "msg-kp-statusresp-0001", "msg-kp-statusreq-0001",
        "security.keyprov.v1.KeyProvisioningStatusResponse", statusResponse.toByteArray());
    write(outDir.resolve("envelope_keyprov_status_response.bin"), envStatusResponse.toByteArray());

    Envelope.VehicleMessageEnvelope envUnknownField = envRequest.toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(12345L).build()).build())
        .build();
    write(outDir.resolve("envelope_keyprov_unknown_field.bin"), envUnknownField.toByteArray());
    Envelope.VehicleMessageEnvelope envUnknownEnum = envRequest.toBuilder()
        .setPayload(ByteString.copyFrom(unknownEnum.toByteArray())).build();
    write(outDir.resolve("envelope_keyprov_unknown_enum.bin"), envUnknownEnum.toByteArray());

    System.out.println("[java] keyprov golden files written:");
    System.out.println("  request:             " + request.toByteArray().length + " bytes");
    System.out.println("  response_success:    " + response.toByteArray().length + " bytes");
    System.out.println("  ack:                 " + ack.toByteArray().length + " bytes");
    System.out.println("  ack_result:          " + ackResult.toByteArray().length + " bytes");
    System.out.println("  status_request:      " + statusRequest.toByteArray().length + " bytes");
    System.out.println("  status_response:     " + statusResponse.toByteArray().length + " bytes");
    System.out.println("  unknown_field:       " + unknownField.toByteArray().length + " bytes");
    System.out.println("  unknown_enum:        " + unknownEnum.toByteArray().length + " bytes");
    System.out.println("  envelope_request:    " + envRequest.toByteArray().length + " bytes");
    System.out.println("  envelope_response:   " + envResponse.toByteArray().length + " bytes");
  }

  private static Envelope.VehicleMessageEnvelope envelope(Envelope.MessageKind kind,
      String requestId, String messageId, String correlationId, String payloadType, byte[] payload) {
    Envelope.VehicleMessageEnvelope.Builder b = Envelope.VehicleMessageEnvelope.newBuilder()
        .setRequestId(requestId)
        .setTimestampMs(T0)
        .setProtocolVersion("keyprov-v1")
        .setDeviceId("TBOX-0001")
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
    return b.build();
  }

  private static ByteString digest(byte fill) {
    byte[] d = new byte[32];
    java.util.Arrays.fill(d, fill);
    return ByteString.copyFrom(d);
  }

  private static ByteString wrapped(byte fill) {
    byte[] w = new byte[64];
    java.util.Arrays.fill(w, fill);
    return ByteString.copyFrom(w);
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
