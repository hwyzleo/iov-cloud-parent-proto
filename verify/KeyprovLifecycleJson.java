import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader / writer used by the KL1 lifecycle vector check
 * (PAR-PROTO-DSN-CR-010 §8.6.3 / §8.6.4).
 *
 * <p>Purpose: reproduce <b>byte-identically</b> the reference oracle's
 * canonical JSON convention — {@code json.dumps(obj, separators=(',', ':'),
 * sort_keys=True, ensure_ascii=False)} — so that {@code input_hash} /
 * {@code expected_hash} recomputed here match the frozen values inside
 * {@code verify/keyprov-lifecycle-kl1-v1/lifecycle-vectors.json} on every
 * platform (Java 17, no third-party JSON dependency).
 *
 * <p>Object model: {@link Map}&lt;String,Object&gt; (insertion order preserved,
 * canonical writer sorts keys), {@link List}&lt;Object&gt;, {@link String},
 * {@link Long} (all JSON numbers in this case-set are integers), {@link Boolean}
 * and {@code null}. Any float / double or non-ASCII string would fail closed
 * with {@link IllegalArgumentException} instead of silently producing a hash
 * that diverges from the reference oracle.
 */
public final class KeyprovLifecycleJson {

  private KeyprovLifecycleJson() {}

  /** Parse a JSON document into the object model. */
  public static Object parse(String text) {
    Parser p = new Parser(text);
    Object v = p.parseValue();
    p.skipWs();
    if (p.pos != p.text.length()) {
      throw new IllegalArgumentException("trailing JSON content at offset " + p.pos);
    }
    return v;
  }

  /** Python-compatible canonical serialization (sort_keys, compact, ensure_ascii=False). */
  public static String canonical(Object v) {
    StringBuilder sb = new StringBuilder();
    write(sb, v);
    return sb.toString();
  }

  public static String sha256Hex(String utf8Text) {
    return sha256Hex(utf8Text.getBytes(StandardCharsets.UTF_8));
  }

  public static String sha256Hex(byte[] data) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] d = md.digest(data);
      StringBuilder sb = new StringBuilder(d.length * 2);
      for (byte b : d) {
        sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
      }
      return sb.toString();
    } catch (Exception e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  // ---- canonical writer (must match Python json.dumps with the exact options) ---

  private static void write(StringBuilder sb, Object v) {
    if (v == null) {
      sb.append("null");
    } else if (v instanceof String) {
      writeString(sb, (String) v);
    } else if (v instanceof Boolean) {
      sb.append(v.toString());
    } else if (v instanceof Long || v instanceof Integer) {
      sb.append(v.toString());
    } else if (v instanceof Map) {
      Map<?, ?> m = (Map<?, ?>) v;
      List<String> keys = new ArrayList<>();
      for (Object k : m.keySet()) {
        keys.add(String.valueOf(k));
      }
      Collections.sort(keys); // Python sort_keys: ascending code point order
      sb.append('{');
      boolean first = true;
      for (String k : keys) {
        if (!first) {
          sb.append(',');
        }
        first = false;
        writeString(sb, k);
        sb.append(':');
        write(sb, m.get(k));
      }
      sb.append('}');
    } else if (v instanceof List) {
      List<?> list = (List<?>) v;
      sb.append('[');
      boolean first = true;
      for (Object item : list) {
        if (!first) {
          sb.append(',');
        }
        first = false;
        write(sb, item);
      }
      sb.append(']');
    } else {
      throw new IllegalArgumentException(
          "unsupported JSON value type for canonical hash: " + v.getClass().getName());
    }
  }

  private static void writeString(StringBuilder sb, String s) {
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b"); break;
        case '\f': sb.append("\\f"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c); // ensure_ascii=False: non-ASCII emitted raw as UTF-8
          }
      }
    }
    sb.append('"');
  }

  // ---- parser -----------------------------------------------------------------

  private static final class Parser {
    final String text;
    int pos;

    Parser(String text) {
      this.text = text;
    }

    void skipWs() {
      while (pos < text.length()) {
        char c = text.charAt(pos);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
          pos++;
        } else {
          break;
        }
      }
    }

    Object parseValue() {
      skipWs();
      if (pos >= text.length()) {
        throw new IllegalArgumentException("unexpected end of JSON");
      }
      char c = text.charAt(pos);
      switch (c) {
        case '{': return parseObject();
        case '[': return parseArray();
        case '"': return parseString();
        case 't':
          expect("true");
          return Boolean.TRUE;
        case 'f':
          expect("false");
          return Boolean.FALSE;
        case 'n':
          expect("null");
          return null;
        default:
          return parseNumber();
      }
    }

    Map<String, Object> parseObject() {
      expectChar('{');
      Map<String, Object> map = new LinkedHashMap<>();
      skipWs();
      if (peek() == '}') {
        pos++;
        return map;
      }
      while (true) {
        skipWs();
        if (peek() != '"') {
          throw new IllegalArgumentException("expected string key at offset " + pos);
        }
        String key = parseString();
        skipWs();
        expectChar(':');
        map.put(key, parseValue());
        skipWs();
        char c = peek();
        if (c == ',') {
          pos++;
        } else if (c == '}') {
          pos++;
          return map;
        } else {
          throw new IllegalArgumentException("expected ',' or '}' at offset " + pos);
        }
      }
    }

    List<Object> parseArray() {
      expectChar('[');
      List<Object> list = new ArrayList<>();
      skipWs();
      if (peek() == ']') {
        pos++;
        return list;
      }
      while (true) {
        list.add(parseValue());
        skipWs();
        char c = peek();
        if (c == ',') {
          pos++;
        } else if (c == ']') {
          pos++;
          return list;
        } else {
          throw new IllegalArgumentException("expected ',' or ']' at offset " + pos);
        }
      }
    }

    String parseString() {
      expectChar('"');
      StringBuilder sb = new StringBuilder();
      while (pos < text.length()) {
        char c = text.charAt(pos++);
        if (c == '"') {
          return sb.toString();
        }
        if (c == '\\') {
          if (pos >= text.length()) {
            throw new IllegalArgumentException("dangling escape");
          }
          char e = text.charAt(pos++);
          switch (e) {
            case '"': sb.append('"'); break;
            case '\\': sb.append('\\'); break;
            case '/': sb.append('/'); break;
            case 'b': sb.append('\b'); break;
            case 'f': sb.append('\f'); break;
            case 'n': sb.append('\n'); break;
            case 'r': sb.append('\r'); break;
            case 't': sb.append('\t'); break;
            case 'u':
              if (pos + 4 > text.length()) {
                throw new IllegalArgumentException("short \\u escape");
              }
              sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
              pos += 4;
              break;
            default:
              throw new IllegalArgumentException("unknown escape \\" + e);
          }
        } else {
          sb.append(c);
        }
      }
      throw new IllegalArgumentException("unterminated string");
    }

    Long parseNumber() {
      int start = pos;
      if (peek() == '-') {
        pos++;
      }
      while (pos < text.length() && (Character.isDigit(text.charAt(pos)))) {
        pos++;
      }
      if (pos < text.length()) {
        char c = text.charAt(pos);
        if (c == '.' || c == 'e' || c == 'E') {
          throw new IllegalArgumentException(
              "float number at offset " + start + " cannot be hashed canonically");
        }
      }
      if (pos == start || (pos == start + 1 && text.charAt(start) == '-')) {
        throw new IllegalArgumentException("malformed number at offset " + start);
      }
      return Long.parseLong(text.substring(start, pos));
    }

    char peek() {
      if (pos >= text.length()) {
        throw new IllegalArgumentException("unexpected end of JSON");
      }
      return text.charAt(pos);
    }

    void expectChar(char c) {
      if (pos >= text.length() || text.charAt(pos) != c) {
        throw new IllegalArgumentException("expected '" + c + "' at offset " + pos);
      }
      pos++;
    }

    void expect(String literal) {
      if (!text.startsWith(literal, pos)) {
        throw new IllegalArgumentException("expected " + literal + " at offset " + pos);
      }
      pos += literal.length();
    }
  }
}
