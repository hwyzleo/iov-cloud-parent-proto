import com.google.protobuf.UnknownFieldSet;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import vehicle.fota.v1.Download;
import vehicle.fota.v1.Types;

/**
 * CR-011 golden producer (PAR-PROTO-DSN-CR-011 §8 item 6 / SPEC 设计 §6.5).
 *
 * Produces canonical Java reference serialization bytes for the CR-011 fota
 * download-progress additions (cross-language contract: VEH-PROTO/CGW-FOTA C++
 * must round-trip byte-identically against these bytes) and the deterministic
 * golden manifest:
 *
 *   fota_download_started.bin                 DownloadState.STARTED
 *   fota_download_progress.bin                DownloadState.PROGRESS
 *   fota_download_completed.bin               DownloadState.COMPLETED
 *   fota_download_reset_offset.bin            DownloadState.RESET_OFFSET (non-zero authorized baseline)
 *   fota_download_unknown_enum.bin            unknown DownloadState value 99 (wire retention)
 *   fota_download_unknown_field.bin           unknown field 999 (wire retention)
 *   fota_download_uint64_high_bit.bin         downloaded_bytes = 2^64-1 (Java long -1)
 *   fota_download_response_current.bin        DownloadProgressDisposition.CURRENT
 *   fota_download_response_late.bin           LATE_OBSERVATION
 *   fota_download_response_duplicate.bin      DUPLICATE
 *   fota_download_response_conflict.bin       CONFLICT
 *   fota_download_response_rejected.bin       REJECTED
 *
 * verify/golden/manifest-cr011.json records source/descriptor/toolchain,
 * every golden file name, its byte length and SHA-256. The manifest's own
 * SHA-256 is recorded in provenance/vehicle-proto-baseline.yaml
 * (cr011_extension.golden_manifest_sha256) and re-checked by run_verify.sh.
 *
 * No cloud business state is produced here: download-progress acceptance
 * semantics live in verify/Cr011SemanticsCheck.java (reference model).
 */
public class Cr011GoldenProducer {
  private static final String T0_MS = "1800000000000";
  private static final long TOTAL_BYTES = 1048576L;

  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    // ---- report goldens (contact sheet of the frozen DownloadState set) ------
    Download.DownloadProgressReport started = report("DP-1", 1, 1)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_STARTED)
        .setDownloadedBytes(0).setResumeOffset(0).setEtag("etag-1")
        .build();
    Download.DownloadProgressReport progress = report("DP-2", 1, 2)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_PROGRESS)
        .setDownloadedBytes(TOTAL_BYTES / 2).setResumeOffset(0).setEtag("etag-1")
        .build();
    Download.DownloadProgressReport completed = report("DP-3", 1, 3)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_COMPLETED)
        .setDownloadedBytes(TOTAL_BYTES).setResumeOffset(0).setEtag("etag-1")
        .build();
    // RESET_OFFSET: downloaded_bytes == resume_offset, new monotonic baseline.
    Download.DownloadProgressReport resetOffset = report("DP-4", 2, 1)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_RESET_OFFSET)
        .setDownloadedBytes(262144L).setResumeOffset(262144L).setEtag("etag-1")
        .build();
    // unknown enum value: wire must retain 99, business layer must fail closed.
    Download.DownloadProgressReport unknownEnum = report("DP-5", 1, 4)
        .setDownloadStateValue(99)
        .setDownloadedBytes(TOTAL_BYTES / 2).setResumeOffset(0).setEtag("etag-1")
        .build();
    Download.DownloadProgressReport unknownField = report("DP-6", 1, 5)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_PROGRESS)
        .setDownloadedBytes(TOTAL_BYTES / 2).setResumeOffset(0).setEtag("etag-1")
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(999, UnknownFieldSet.Field.newBuilder().addVarint(4242L).build())
            .build())
        .build();

    write(outDir.resolve("fota_download_started.bin"), started.toByteArray());
    write(outDir.resolve("fota_download_progress.bin"), progress.toByteArray());
    write(outDir.resolve("fota_download_completed.bin"), completed.toByteArray());
    write(outDir.resolve("fota_download_reset_offset.bin"), resetOffset.toByteArray());
    write(outDir.resolve("fota_download_unknown_enum.bin"), unknownEnum.toByteArray());
    // Java long -1 is the uint64 wire value 0xFFFFFFFFFFFFFFFF. Both Java and
    // C++ acceptance layers must reject it before snapshot/percentage handling.
    Download.DownloadProgressReport uint64HighBit = report("DP-7", 1, 6)
        .setDownloadState(Download.DownloadState.DOWNLOAD_STATE_PROGRESS)
        .setDownloadedBytes(-1L).setResumeOffset(0).setEtag("etag-1")
        .build();

    write(outDir.resolve("fota_download_unknown_field.bin"), unknownField.toByteArray());
    write(outDir.resolve("fota_download_uint64_high_bit.bin"), uint64HighBit.toByteArray());

    // ---- response goldens (disposition matrix, §6.3) ------------------------
    Download.DownloadProgressResponse current = response(true,
        Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_CURRENT, 3, null);
    Download.DownloadProgressResponse late = response(true,
        Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_LATE_OBSERVATION, 3, null);
    Download.DownloadProgressResponse duplicate = response(true,
        Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_DUPLICATE, 3, null);
    Download.DownloadProgressResponse conflict = response(false,
        Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_CONFLICT, 3,
        "SECOND_KEY_CONFLICT");
    Download.DownloadProgressResponse rejected = response(false,
        Download.DownloadProgressDisposition.DOWNLOAD_PROGRESS_DISPOSITION_REJECTED, 0,
        "BYTES_REGRESSION");

    write(outDir.resolve("fota_download_response_current.bin"), current.toByteArray());
    write(outDir.resolve("fota_download_response_late.bin"), late.toByteArray());
    write(outDir.resolve("fota_download_response_duplicate.bin"), duplicate.toByteArray());
    write(outDir.resolve("fota_download_response_conflict.bin"), conflict.toByteArray());
    write(outDir.resolve("fota_download_response_rejected.bin"), rejected.toByteArray());

    // ---- deterministic manifest (verify/golden/manifest-cr011.json) ---------
    Path manifest = Paths.get("verify/golden/manifest-cr011.json");
    Files.write(manifest, manifestJson().getBytes(StandardCharsets.UTF_8));

    System.out.println("[java] CR-011 golden files written:");
    for (Path p : goldenFiles()) {
      System.out.println("  " + p.getFileName() + ": " + Files.size(p) + " bytes  sha256="
          + sha256(Files.readAllBytes(p)));
    }
    System.out.println("  manifest-cr011.json: " + Files.size(manifest) + " bytes  sha256="
        + sha256(Files.readAllBytes(manifest)));
  }

  private static Download.DownloadProgressReport.Builder report(
      String progressId, int attemptNo, long seq) {
    return Download.DownloadProgressReport.newBuilder()
        .setProgressId(progressId)
        .setVehicleTaskId("VT-CR011")
        .setPackageId("PKG-CR011")
        .setPackageRevision("REV-1")
        .setDownloadAttemptNo(attemptNo)
        .setProgressSeq(seq)
        .setTotalBytes(TOTAL_BYTES)
        .setOccurredAtMs(Long.parseLong(T0_MS))
        .setEventDigest(Types.Digest.newBuilder()
            .setAlgorithm("SHA-256")
            .setValueHex(sha256(("cr011-golden-" + progressId).getBytes(StandardCharsets.UTF_8)))
            .build());
  }

  private static Download.DownloadProgressResponse response(boolean accepted,
      Download.DownloadProgressDisposition disposition, long latestAcceptedSeq, String denyReason) {
    Download.DownloadProgressResponse.Builder b = Download.DownloadProgressResponse.newBuilder()
        .setStatus(Types.ResponseStatus.newBuilder().setCode("0").setServerTimeMs(Long.parseLong(T0_MS)))
        .setAccepted(accepted)
        .setDisposition(disposition)
        .setLatestAcceptedProgressSeq(latestAcceptedSeq);
    if (denyReason != null) {
      b.setDenyReason(denyReason);
    }
    return b.build();
  }

  /** Golden payload file set (deterministic order) — also used by the manifest + checks. */
  static List<Path> goldenFiles() {
    String[] names = {
      "fota_download_started.bin",
      "fota_download_progress.bin",
      "fota_download_completed.bin",
      "fota_download_reset_offset.bin",
      "fota_download_unknown_enum.bin",
      "fota_download_unknown_field.bin",
      "fota_download_uint64_high_bit.bin",
      "fota_download_response_current.bin",
      "fota_download_response_late.bin",
      "fota_download_response_duplicate.bin",
      "fota_download_response_conflict.bin",
      "fota_download_response_rejected.bin",
    };
    List<Path> out = new ArrayList<>();
    for (String n : names) {
      out.add(Paths.get("verify/golden/expected", n));
    }
    return out;
  }

  static String manifestJson() throws Exception {
    List<String> goldens = new ArrayList<>();
    for (Path p : goldenFiles()) {
      goldens.add("    {\"file\": \"" + p.getFileName() + "\", \"bytes\": "
          + Files.size(p) + ", \"sha256\": \"" + sha256(Files.readAllBytes(p)) + "\"}");
    }
    List<String> sourceLines = new ArrayList<>();
    for (String rel : sourceFiles()) {
      sourceLines.add("      \"" + rel + "\": \""
          + sha256(Files.readAllBytes(fotaRoot().resolve(rel))) + "\"");
    }
    String sources = String.join(",\n", sourceLines);

    StringBuilder sb = new StringBuilder();
    sb.append("{\n");
    sb.append("  \"cr\": \"PAR-PROTO-DSN-CR-011\",\n");
    sb.append("  \"contract\": \"vehicle/fota/v1/download.proto\",\n");
    sb.append("  \"package\": \"vehicle.fota.v1\",\n");
    sb.append("  \"protocol_version\": \"fota-v1\",\n");
    sb.append("  \"service\": \"vehicle.fota\",\n");
    sb.append("  \"family\": \"DOWNLOAD_PROGRESS\",\n");
    sb.append("  \"release_set\": [\"PAR-PROTO\", \"VEH-PROTO/CGW-FOTA\", \"VAGW\", \"IOV-OTA\"],\n");
    sb.append("  \"directions\": [\n");
    sb.append("    {\"payload_type\": \"vehicle.fota.v1.DownloadProgressReport\", \"direction\": \"INBOUND\","
        + " \"message_kind\": \"REQUEST\", \"topic\": \"vagw.fota\"},\n");
    sb.append("    {\"payload_type\": \"vehicle.fota.v1.DownloadProgressResponse\", \"direction\": \"OUTBOUND\","
        + " \"message_kind\": \"RESPONSE\", \"topic\": \"ota.fota\"}\n");
    sb.append("  ],\n");
    sb.append("  \"source\": {\n");
    sb.append("    \"root\": \"iov-cloud-proto-fota/src/main/proto\",\n");
    sb.append("    \"files\": {\n").append(sources).append("\n    },\n");
    sb.append("    \"fota_source_aggregate_sha256\": \"").append(sourceAggregateSha256()).append("\"\n");
    sb.append("  },\n");
    sb.append("  \"descriptor\": {\n");
    sb.append("    \"path\": \"descriptors/vehicle-fota-v1.pb\",\n");
    sb.append("    \"sha256\": \"").append(sha256(Files.readAllBytes(
        Paths.get("descriptors/vehicle-fota-v1.pb")))).append("\"\n");
    sb.append("  },\n");
    sb.append("  \"toolchain\": {\"protoc\": \"3.25.5\", \"protobuf_java\": \"3.25.5\","
        + " \"buf\": \"1.72.0\", \"maven\": \"3.9.14\", \"jdk\": \"17\"},\n");
    sb.append("  \"golden\": [\n").append(String.join(",\n", goldens)).append("\n  ]\n");
    sb.append("}\n");
    return sb.toString();
  }

  private static Path fotaRoot() {
    return Paths.get("iov-cloud-proto-fota/src/main/proto");
  }

  /** All official FOTA protos, relative path UTF-8 lexicographic (SPEC §11 aggregate). */
  static List<String> sourceFiles() throws Exception {
    Path root = fotaRoot();
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(p -> p.toString().endsWith(".proto"))
          .map(p -> root.relativize(p).toString().replace('\\', '/'))
          .sorted(Cr011GoldenProducer::compareUtf8)
          .collect(Collectors.toList());
    }
  }

  /** Unsigned UTF-8 byte ordering; relative paths contain no ./ prefix and use '/' separators. */
  private static int compareUtf8(String left, String right) {
    byte[] a = left.getBytes(StandardCharsets.UTF_8);
    byte[] b = right.getBytes(StandardCharsets.UTF_8);
    int length = Math.min(a.length, b.length);
    for (int i = 0; i < length; i++) {
      int comparison = Integer.compare(Byte.toUnsignedInt(a[i]), Byte.toUnsignedInt(b[i]));
      if (comparison != 0) {
        return comparison;
      }
    }
    return Integer.compare(a.length, b.length);
  }

  /** fotaSourceAggregateSha256 = SHA-256 over UTF8(path) || 0x00 || hex(fileSha256) || 0x0A. */
  static String sourceAggregateSha256() throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    for (String rel : sourceFiles()) {
      digest.update(rel.getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0x00);
      digest.update(sha256(Files.readAllBytes(fotaRoot().resolve(rel)))
          .getBytes(StandardCharsets.US_ASCII));
      digest.update((byte) 0x0A);
    }
    return hex(digest.digest());
  }

  static String sha256(byte[] data) {
    try {
      return hex(MessageDigest.getInstance("SHA-256").digest(data));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] readAll(Path p) throws Exception {
    return Files.readAllBytes(p);
  }

  private static String hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(Character.forDigit((b >> 4) & 0xF, 16));
      sb.append(Character.forDigit(b & 0xF, 16));
    }
    return sb.toString();
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
