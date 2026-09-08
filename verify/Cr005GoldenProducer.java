import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import vehicle.fota.v1.Task;
import vehicle.fota.v1.Types;

/**
 * CR-005 golden producer (PAR-PROTO-DSN-CR-005 §10.1/§10.3).
 *
 * Produces canonical reference serialization bytes for the CR-005 fota additions:
 *   - fota_ecu_version_multitarget.bin : vehicle.fota.v1.EcuVersion (MULTI_TARGET + software_units)
 *   - fota_taskcheck_canonical_v2.bin  : vehicle.fota.v1.TaskCheckRequest
 *     (inventory_canonicalization_version=2 + mixed ECU list)
 *
 * Java-generated reference bytes are the cross-language contract: vehicle-side C++
 * (VEH-PROTO) must round-trip byte-identically. Hashes are recorded in
 * provenance/vehicle-proto-baseline.yaml. The OTA->VMD cloud event is NOT part of
 * PAR-PROTO (design §7) and has no golden producer here.
 */
public class Cr005GoldenProducer {
  public static void main(String[] args) throws Exception {
    Path outDir = Paths.get("verify/golden/expected");
    Files.createDirectories(outDir);

    // ---- mixed inventory (SINGLE_IMAGE legacy + MULTI_TARGET) ---------------
    Types.EcuVersion engine = Types.EcuVersion.newBuilder()
        .setEcuId("ECU-ENGINE").setHardwarePartNumber("HW-1").setHwVersion("H1")
        .setSoftwarePartNumber("SW-1").setSwVersion("S1")
        .setSoftwareModel(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_SINGLE_IMAGE)
        .build();
    Types.EcuVersion gw = Types.EcuVersion.newBuilder()
        .setEcuId("ECU-GW").setHardwarePartNumber("HW-9").setHwVersion("H9")
        .setSoftwareModel(Types.EcuSoftwareModel.ECU_SOFTWARE_MODEL_MULTI_TARGET)
        .addSoftwareUnits(Types.SoftwareUnitVersion.newBuilder()
            .setSoftwareTargetCode("BODY").setSoftwarePartNumber("PN-B").setSwVersion("VB").build())
        .addSoftwareUnits(Types.SoftwareUnitVersion.newBuilder()
            .setSoftwareTargetCode("GW").setSoftwarePartNumber("PN-G").setSwVersion("VG")
            .setSlot("slotA").setActive(true).build())
        .build();

    // ---- fota MULTI_TARGET EcuVersion ---------------------------------------
    write(outDir.resolve("fota_ecu_version_multitarget.bin"), gw.toByteArray());

    // ---- fota TaskCheckRequest with canonicalization version 2 ---------------
    Task.TaskCheckRequest task = Task.TaskCheckRequest.newBuilder()
        .setBaselineCode("BL-001").setFotaMasterVersion("FM-1.0")
        .setInventoryMode(Types.InventoryMode.INVENTORY_MODE_FULL)
        .setInventoryRevision(9L)
        .setInventoryCanonicalizationVersion(2)
        .addEcuList(engine)
        .addEcuList(gw)
        .build();
    write(outDir.resolve("fota_taskcheck_canonical_v2.bin"), task.toByteArray());

    System.out.println("[java] CR-005 golden files written:");
    System.out.println("  fota_ecu_version_multitarget.bin: " + gw.toByteArray().length + " bytes");
    System.out.println("  fota_taskcheck_canonical_v2.bin:  " + task.toByteArray().length + " bytes");
  }

  private static void write(Path p, byte[] data) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(p.toFile())) {
      fos.write(data);
    }
  }
}
