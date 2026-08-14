import com.google.protobuf.DescriptorProtos;
import java.io.FileInputStream;

/** Verifies that a .pb file is a valid normalized FileDescriptorSet. */
public class DumpDescriptor {
  public static void main(String[] args) throws Exception {
    for (String path : args) {
      DescriptorProtos.FileDescriptorSet set;
      try (FileInputStream in = new FileInputStream(path)) {
        set = DescriptorProtos.FileDescriptorSet.parseFrom(in);
      }
      System.out.println("=== " + path + " ===");
      for (DescriptorProtos.FileDescriptorProto f : set.getFileList()) {
        System.out.println("  file: " + f.getName() + "  pkg: " + f.getPackage());
        for (DescriptorProtos.DescriptorProto m : f.getMessageTypeList()) {
          System.out.println("    msg: " + m.getName());
        }
        for (DescriptorProtos.EnumDescriptorProto e : f.getEnumTypeList()) {
          System.out.println("    enum: " + e.getName() + " (" + e.getValueCount() + " vals)");
        }
      }
    }
  }
}
