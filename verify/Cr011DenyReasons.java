import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Machine-readable CR-011 deny_reason registry consumed by the semantic checks. */
final class Cr011DenyReasons {
  static final Path REGISTRY = Paths.get("verify/download-deny-reasons.json");
  private static final int EXPECTED_COUNT = 20;
  private static final Pattern ENTRY = Pattern.compile("\\{[^{}]*\"deny_reason\"[^{}]*\\}");

  static final class Rule {
    final String reason;
    final String trigger;
    final String disposition;
    final boolean occupiesSecondUniqueKey;

    Rule(String reason, String trigger, String disposition, boolean occupiesSecondUniqueKey) {
      this.reason = reason;
      this.trigger = trigger;
      this.disposition = disposition;
      this.occupiesSecondUniqueKey = occupiesSecondUniqueKey;
    }
  }

  private final Map<String, Rule> rules;

  private Cr011DenyReasons(Map<String, Rule> rules) {
    this.rules = Collections.unmodifiableMap(rules);
  }

  static Cr011DenyReasons load() throws IOException {
    String json = Files.readString(REGISTRY);
    Map<String, Rule> rules = new LinkedHashMap<>();
    Matcher entries = ENTRY.matcher(json);
    while (entries.find()) {
      String entry = entries.group();
      String reason = stringField(entry, "deny_reason");
      String trigger = stringField(entry, "trigger");
      String disposition = stringField(entry, "disposition");
      boolean occupiesSecondUniqueKey = booleanField(entry, "occupies_second_unique_key");
      if (trigger.isEmpty()) {
        throw new IllegalArgumentException("Empty trigger for " + reason);
      }
      if (!disposition.equals("REJECTED") && !disposition.equals("CONFLICT")) {
        throw new IllegalArgumentException("Unsupported disposition for " + reason + ": " + disposition);
      }
      if (occupiesSecondUniqueKey) {
        throw new IllegalArgumentException("Denied report must not occupy the second unique key: " + reason);
      }
      Rule previous = rules.putIfAbsent(reason,
          new Rule(reason, trigger, disposition, occupiesSecondUniqueKey));
      if (previous != null) {
        throw new IllegalArgumentException("Duplicate deny_reason: " + reason);
      }
    }
    if (rules.size() != EXPECTED_COUNT) {
      throw new IllegalArgumentException(
          "CR-011 deny_reason count must be " + EXPECTED_COUNT + ", got " + rules.size());
    }
    return new Cr011DenyReasons(rules);
  }

  Rule require(String reason) {
    Rule rule = rules.get(reason);
    if (rule == null) {
      throw new IllegalArgumentException("Unregistered CR-011 deny_reason: " + reason);
    }
    return rule;
  }

  Map<String, Rule> rules() {
    return rules;
  }

  private static String stringField(String entry, String name) {
    Pattern pattern = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"([^\"]*)\"");
    Matcher matcher = pattern.matcher(entry);
    if (!matcher.find()) {
      throw new IllegalArgumentException("Missing JSON string field: " + name);
    }
    String value = matcher.group(1);
    if (value.contains("\\")) {
      throw new IllegalArgumentException("Escaped registry strings are not supported: " + name);
    }
    return value;
  }

  private static boolean booleanField(String entry, String name) {
    Pattern pattern = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(true|false)");
    Matcher matcher = pattern.matcher(entry);
    if (!matcher.find()) {
      throw new IllegalArgumentException("Missing JSON boolean field: " + name);
    }
    return Boolean.parseBoolean(matcher.group(1));
  }
}
