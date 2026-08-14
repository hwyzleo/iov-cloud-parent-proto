import com.google.protobuf.DescriptorProtos;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Gate 8 (PAR-PROTO-DSN-CR-002 §5): verifies every payload_type in the
 * provenance registry resolves to a message full-name present in the shipped
 * normalized FileDescriptorSets. payload_type is the proto fully-qualified
 * name (package.Message), e.g. vehicle.fota.v1.TaskCheckRequest.
 */
public class PayloadTypeCheck {
  public static void main(String[] args) throws Exception {
    String manifest = args[0];
    Set<String> payloadTypes = parsePayloadTypes(manifest);
    Set<String> messageNames = new HashSet<>();
    for (int i = 1; i < args.length; i++) {
      DescriptorProtos.FileDescriptorSet set;
      try (FileInputStream in = new FileInputStream(args[i])) {
        set = DescriptorProtos.FileDescriptorSet.parseFrom(in);
      }
      for (DescriptorProtos.FileDescriptorProto f : set.getFileList()) {
        collectMessages(f.getPackage(), f.getMessageTypeList(), messageNames);
      }
    }
    int failures = 0;
    for (String pt : payloadTypes) {
      if (messageNames.contains(pt)) {
        System.out.println("  ✓ payload_type " + pt + " resolved");
      } else {
        System.out.println("  ✗ payload_type " + pt + " NOT in descriptor set");
        failures++;
      }
    }
    if (failures > 0) {
      System.exit(1);
    }
    System.out.println("  payload_type registry ↔ descriptor full-name: OK (" + payloadTypes.size() + ")");
  }

  private static void collectMessages(String pkg,
      java.util.List<DescriptorProtos.DescriptorProto> msgs, Set<String> out) {
    for (DescriptorProtos.DescriptorProto m : msgs) {
      out.add(pkg + "." + m.getName());
      collectMessages(pkg + "." + m.getName(), m.getNestedTypeList(), out);
    }
  }

  /** Minimal line-scanner for the payload_type_registry YAML block (indent-insensitive to "- "). */
  private static Set<String> parsePayloadTypes(String path) throws Exception {
    Set<String> types = new HashSet<>();
    boolean inBlock = false;
    for (String line : Files.readAllLines(Paths.get(path))) {
      if (line.startsWith("payload_type_registry:")) {
        inBlock = true;
        continue;
      }
      if (inBlock) {
        if (line.startsWith("  ") || line.startsWith("\t")) {
          Matcher m = Pattern.compile("^\\s*-\\s+(.+)$").matcher(line);
          if (m.find() && m.group(1).contains(".")) {
            types.add(m.group(1).trim());
          }
        } else if (!line.trim().isEmpty() && !line.startsWith("#")) {
          inBlock = false; // left the block
        }
      }
    }
    return types;
  }
}
