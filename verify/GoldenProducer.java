import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import vehicle.common.v1.Envelope;
import vehicle.fota.v1.Task;
import vehicle.fota.v1.Types;

/**
 * Java golden producer (PAR-PROTO-DSN-CR-002 cross-language contract).
 *
 * This repo generates Java only. The producer writes canonical reference
 * serialization bytes from the generated Java classes (incl. unknown-field and
 * unknown-enum preservation cases). VEH-PROTO / vehicle builds generate C++
 * from the released canonical source / DescriptorSet and must round-trip
 * byte-identically against these reference bytes (design §5 gate 6/7).
 */
public class GoldenProducer {
  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    // ---- Canonical envelope wrapping a TaskCheckRequest payload ----
    Types.Digest ecuListDigest = Types.Digest.newBuilder()
        .setAlgorithm("sha256")
        .setValueHex("aabbccddeeff00112233445566778899")
        .build();
    Types.EcuVersion ecu = Types.EcuVersion.newBuilder()
        .setEcuId("ECU-ENGINE")
        .setHardwarePartNumber("HW-1")
        .setSoftwarePartNumber("SW-1")
        .setHwVersion("H1")
        .setSwVersion("S1")
        .build();
    Task.TaskCheckRequest task = Task.TaskCheckRequest.newBuilder()
        .setBaselineCode("BL-001")
        .setFotaMasterVersion("FM-1.0")
        .setLocalVehicleTaskId("vt-local-001")
        .setLocalTaskRevision(7L)
        .setLocalVehicleTaskStatus(Types.VehicleTaskStatus.VEHICLE_TASK_STATUS_READY)
        .setInventoryMode(Types.InventoryMode.INVENTORY_MODE_FULL)
        .setInventoryRevision(9L)
        .setEcuListDigest(ecuListDigest)
        .addEcuList(ecu)
        .build();
    byte[] payloadBytes = task.toByteArray();

    Envelope.VehicleMessageEnvelope envelope = Envelope.VehicleMessageEnvelope.newBuilder()
        .setRequestId("req-20260814-001")
        .setTimestampMs(1723600000000L)
        .setProtocolVersion("fota-v1")
        .setDeviceId("TBOX-0001")
        .setVin("LSVAB4187N2188888")
        .setVehicleTaskId("vt-1001")
        .setExecutionId("ex-2001")
        .setIdempotencyKey("idem-0001")
        .setPayloadType("vehicle.fota.v1.TaskCheckRequest")
        .setPayload(ByteString.copyFrom(payloadBytes))
        .setMessageId("msg-3001")
        .setCorrelationId("corr-4001")
        .setMessageKind(Envelope.MessageKind.MESSAGE_KIND_REQUEST)
        .setService("vehicle.fota")
        .setExpireAtMs(1723690000000L)
        .setTraceContext(Envelope.TraceContext.newBuilder()
            .setTraceId("t-1")
            .setParentSpanId("p-1")
            .setTraceFlags("01"))
        .build();
    write(outDir.resolve("envelope_taskcheck.bin"), envelope.toByteArray());

    // ---- Unknown field preservation: envelope + raw unknown tag 99 varint ----
    UnknownFieldSet unknown = UnknownFieldSet.newBuilder()
        .addField(99, UnknownFieldSet.Field.newBuilder().addVarint(12345L).build())
        .build();
    Envelope.VehicleMessageEnvelope envelopeUnknown = envelope.toBuilder()
        .setUnknownFields(unknown)
        .build();
    write(outDir.resolve("envelope_unknown_field.bin"), envelopeUnknown.toByteArray());

    // ---- Unknown enum preservation: out-of-range enum value 999 ----
    Task.TaskCheckRequest taskUnknownEnum = task.toBuilder()
        .setLocalVehicleTaskStatusValue(999)
        .build();
    Envelope.VehicleMessageEnvelope envelopeUnknownEnum = envelope.toBuilder()
        .setPayload(ByteString.copyFrom(taskUnknownEnum.toByteArray()))
        .build();
    write(outDir.resolve("envelope_unknown_enum.bin"), envelopeUnknownEnum.toByteArray());

    System.out.println("[java] golden files written:");
    System.out.println("  canonical envelope:     " + envelope.toByteArray().length + " bytes");
    System.out.println("  payload TaskCheck:      " + payloadBytes.length + " bytes");
    System.out.println("  unknown-field envelope: " + envelopeUnknown.toByteArray().length + " bytes");
    System.out.println("  unknown-enum envelope:  " + envelopeUnknownEnum.toByteArray().length + " bytes");
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
