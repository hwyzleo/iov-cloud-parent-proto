import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.MessageLite;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

/**
 * security.keyprov.v1 ECDH-ES v1 canonical reference implementation
 * (PAR-PROTO-DSN-CR-007 §4 / §5 / §6 / §7).
 *
 * This class is the single Java authority for the cross-language (Java/C++)
 * byte-exact contract of the ECDH-ES v1 envelope. It deliberately contains NO
 * key material and NO cryptography beyond hashing: the design freezes the
 * canonical framing, digests and gates here; the actual ECDH/HKDF/AEAD and the
 * ACK proof algorithm are owned by FW-SEC / TBOX-SEC.
 *
 * Framing (design §4.2 / §5):
 *   - every segment is prefixed with an unsigned 32-bit big-endian length;
 *   - strings enter as raw UTF-8 bytes;
 *   - enums enter as their canonical unsigned varint integer value;
 *   - bytes enter as raw content;
 *   - businessKeyVersion enters as a fixed 8-byte big-endian uint64
 *     (design §4.2 leaves this unstated; this repo pins the §5 proofInput
 *     convention and records it in the golden vectors).
 *
 *   envelopeDigest = SHA-256(lengthPrefixed(
 *       envelopeFormat, requestId, businessDomain, purpose, keyId,
 *       businessKeyVersion, wrappingSuite, wrappedKey, parameters))
 *   (the envelope_digest field itself never enters the digest)
 *
 *   proofInput = lengthPrefixed(
 *       UTF8("openiov|keyprov-ack|v1"), UTF8(requestId), UTF8(businessDomain),
 *       enumValue(purpose), SHA-256(UTF8(keyId)), uint64be(businessKeyVersion),
 *       envelopeDigest, keyCheckValue)
 *
 *   aadDigest      = SHA-256(canonicalAad)
 *   keyCheckValue  = first_3_bytes(SHA-256(businessKey))
 *
 * Producers and consumers MUST NOT customize field order, wire kind, string
 * comparison, domain framing or the fixed v1 lengths below.
 */
public final class KeyprovCanonicalV1 {

  public static final String PROOF_DOMAIN = "openiov|keyprov-ack|v1";

  public static final int FORMAT_VERSION_V1 = 1;
  public static final int EPHEMERAL_PUBLIC_KEY_BYTES = 65;   // 0x04 || X(32) || Y(32)
  public static final byte UNCOMPRESSED_POINT_TAG = 0x04;
  public static final int HKDF_SALT_BYTES = 32;
  public static final int NONCE_BYTES = 12;
  public static final int AUTH_TAG_BYTES = 16;
  public static final int DIGEST_BYTES = 32;                 // aadDigest / envelopeDigest / recipientCertDigest
  public static final int KCV_BYTES = 3;
  public static final int MAX_CANONICAL_AAD_BYTES = 1024;
  public static final int MAX_PARAMETERS_BYTES = 2048;

  public static final String KEY_ALGORITHM_V1 = "AES-256";
  public static final String HKDF_CONTEXT_VERSION_V1 = "v1";

  private static final BigInteger P256_P = new BigInteger(
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
  private static final BigInteger P256_A = P256_P.subtract(BigInteger.valueOf(3));
  private static final BigInteger P256_B = new BigInteger(
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

  private KeyprovCanonicalV1() {}

  // ---- framing primitives ---------------------------------------------------

  /** Concatenate segments, each prefixed with its unsigned 32-bit big-endian length. */
  public static byte[] lengthPrefixed(byte[]... segments) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] s : segments) {
      byte[] b = s == null ? new byte[0] : s;
      out.write((b.length >>> 24) & 0xFF);
      out.write((b.length >>> 16) & 0xFF);
      out.write((b.length >>> 8) & 0xFF);
      out.write(b.length & 0xFF);
      out.write(b, 0, b.length);
    }
    return out.toByteArray();
  }

  public static byte[] utf8(String s) {
    return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
  }

  /** Canonical unsigned varint (protobuf integer encoding, as design §4.2 requires for enums). */
  public static byte[] unsignedVarint(long value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    long v = value;
    while (true) {
      if ((v & ~0x7FL) == 0) {
        out.write((int) v);
        return out.toByteArray();
      }
      out.write((int) ((v & 0x7F) | 0x80));
      v >>>= 7;
    }
  }

  /** Fixed 8-byte big-endian uint64 (design §5; also used for envelopeDigest per this repo). */
  public static byte[] uint64be(long value) {
    byte[] b = new byte[8];
    for (int i = 7; i >= 0; i--) {
      b[i] = (byte) (value & 0xFF);
      value >>>= 8;
    }
    return b;
  }

  public static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** design §5/§7: v1 KCV = first_3_bytes(SHA-256(businessKey)). */
  public static byte[] keyCheckValue(byte[] businessKey) {
    return Arrays.copyOf(sha256(businessKey), KCV_BYTES);
  }

  /** design §4.3/§7: aadDigest = SHA-256(canonical_aad). */
  public static byte[] aadDigest(byte[] canonicalAad) {
    return sha256(canonicalAad == null ? new byte[0] : canonicalAad);
  }

  /**
   * Deterministic protobuf serialization of the v1 parameters message
   * (design §4.1). Enables protobuf deterministic serialization explicitly so
   * the bytes are stable across producers/platforms.
   */
  public static byte[] deterministicParameters(EcdhEsP256EnvelopeParametersV1 params) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      CodedOutputStream cos = CodedOutputStream.newInstance(bos);
      cos.useDeterministicSerialization();
      params.writeTo(cos);
      cos.flush();
      return bos.toByteArray();
    } catch (Exception e) {
      throw new IllegalStateException("deterministic parameters serialization failed", e);
    }
  }

  /** Serialize any message with deterministic serialization enabled. */
  public static byte[] deterministicSerialize(MessageLite message) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      CodedOutputStream cos = CodedOutputStream.newInstance(bos);
      cos.useDeterministicSerialization();
      message.writeTo(cos);
      cos.flush();
      return bos.toByteArray();
    } catch (Exception e) {
      throw new IllegalStateException("deterministic serialization failed", e);
    }
  }

  // ---- canonical digests ----------------------------------------------------

  /** design §4.2 canonical envelope digest (excludes envelope_digest itself). */
  public static byte[] envelopeDigest(String requestId, String businessDomain, WrappedKeyItem item) {
    return sha256(lengthPrefixed(
        unsignedVarint(item.getEnvelopeFormatValue()),
        utf8(requestId),
        utf8(businessDomain),
        unsignedVarint(item.getPurposeValue()),
        utf8(item.getKeyId()),
        uint64be(item.getBusinessKeyVersion()),
        unsignedVarint(item.getWrappingSuiteValue()),
        item.getWrappedKey().toByteArray(),
        item.getParameters().toByteArray()));
  }

  /** design §5 canonical proof input for an ACK item. */
  public static byte[] proofInput(String requestId, String businessDomain, KeyImportItemResult item) {
    return lengthPrefixed(
        utf8(PROOF_DOMAIN),
        utf8(requestId),
        utf8(businessDomain),
        unsignedVarint(item.getPurposeValue()),
        sha256(utf8(item.getKeyId())),
        uint64be(item.getBusinessKeyVersion()),
        item.getEnvelopeDigest().toByteArray(),
        item.getKeyCheckValue().toByteArray());
  }

  // ---- v1 verification / fail-closed gates ---------------------------------

  /** P-256 allowlist entry: format ECDH_ES_P256_V1 <-> suite ECDH_ES_P256_HKDF_SHA256_AES256GCM. */
  public static boolean isV1SuiteFormatPair(KeyEnvelopeFormat format, WrappingSuite suite) {
    return format == KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1
        && suite == WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM;
  }

  /** Reject malformed/unsupported ECDH-ES v1 parameters (design §4.1/§7). */
  public static void validateParameters(EcdhEsP256EnvelopeParametersV1 p) {
    if (p.getFormatVersion() != FORMAT_VERSION_V1) {
      throw new InvalidKeyprovInput("unsupported format_version: " + p.getFormatVersion());
    }
    validateP256UncompressedPoint(p.getServerEphemeralPublicKey().toByteArray());
    exactLength("hkdf_salt", p.getHkdfSalt(), HKDF_SALT_BYTES);
    exactLength("nonce", p.getNonce(), NONCE_BYTES);
    exactLength("authentication_tag", p.getAuthenticationTag(), AUTH_TAG_BYTES);
    exactLength("aad_digest", p.getAadDigest(), DIGEST_BYTES);
    exactLength("recipient_certificate_digest", p.getRecipientCertificateDigest(), DIGEST_BYTES);
    if (p.getCanonicalAad().size() > MAX_CANONICAL_AAD_BYTES) {
      throw new InvalidKeyprovInput("canonical_aad > " + MAX_CANONICAL_AAD_BYTES + " bytes");
    }
    if (p.getHkdfContextVersion().isEmpty()) {
      throw new InvalidKeyprovInput("hkdf_context_version must be present");
    }
    // aad_digest must bind the carried canonical AAD bytes (design §4.3).
    if (!Arrays.equals(p.getAadDigest().toByteArray(),
        aadDigest(p.getCanonicalAad().toByteArray()))) {
      throw new InvalidKeyprovInput("aad_digest does not match SHA-256(canonical_aad)");
    }
    if (p.getDerivationVersion().isEmpty()) {
      throw new InvalidKeyprovInput("derivation_version must be present");
    }
    if (p.getOperationId().isEmpty()) {
      throw new InvalidKeyprovInput("operation_id must be present");
    }
  }

  /** Parse + fully validate a v1 parameters blob (design §4.1 consumer rules). */
  public static EcdhEsP256EnvelopeParametersV1 parseAndValidateParameters(byte[] parametersBytes) {
    if (parametersBytes == null) {
      throw new InvalidKeyprovInput("parameters must be present");
    }
    if (parametersBytes.length == 0 || parametersBytes.length > MAX_PARAMETERS_BYTES) {
      throw new InvalidKeyprovInput("parameters length out of range: " + parametersBytes.length);
    }
    EcdhEsP256EnvelopeParametersV1 p;
    try {
      p = EcdhEsP256EnvelopeParametersV1.parseFrom(parametersBytes);
    } catch (Exception e) {
      throw new InvalidKeyprovInput("parameters are not a valid EcdhEsP256EnvelopeParametersV1");
    }
    validateParameters(p);
    return p;
  }

  /**
   * design §6.2: the full success-item verification a consumer must run before
   * handing an item to TBOX-SEC. Any failure rejects the whole batch.
   */
  public static void validateEcdhEsV1Item(String requestId, String businessDomain, WrappedKeyItem item) {
    if (!isV1SuiteFormatPair(item.getEnvelopeFormat(), item.getWrappingSuite())) {
      throw new InvalidKeyprovInput("envelope_format / wrapping_suite combination not in v1 allowlist");
    }
    if (!KEY_ALGORITHM_V1.equals(item.getKeyAlgorithm())) {
      throw new InvalidKeyprovInput("key_algorithm must be " + KEY_ALGORITHM_V1 + " for v1");
    }
    if (item.getWrappedKey().size() == 0) {
      throw new InvalidKeyprovInput("wrapped_key must carry the AES-GCM ciphertext");
    }
    parseAndValidateParameters(item.getParameters().toByteArray());
    exactLength("envelope_digest", item.getEnvelopeDigest(), DIGEST_BYTES);
    exactLength("key_check_value", item.getKeyCheckValue(), KCV_BYTES);
    byte[] recomputed = envelopeDigest(requestId, businessDomain, item);
    if (!Arrays.equals(recomputed, item.getEnvelopeDigest().toByteArray())) {
      throw new InvalidKeyprovInput("envelope_digest mismatch (recomputed != carried)");
    }
  }

  /**
   * design §6.1: capability negotiation. The server may only emit an envelope v1
   * item when the request explicitly declared the format (and it was non-
   * UNSPECIFIED). Absence or UNSPECIFIED-only is fail-closed.
   */
  public static void requireEnvelopeFormatNegotiated(java.util.List<KeyEnvelopeFormat> declared) {
    if (declared == null || declared.isEmpty()) {
      throw new InvalidKeyprovInput("request did not declare supported_envelope_formats");
    }
    for (KeyEnvelopeFormat f : declared) {
      if (f == KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1) {
        return;
      }
    }
    throw new InvalidKeyprovInput("request did not negotiate KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1");
  }

  /**
   * design §5/§6.3: success ACK binding. Every ACK item must mirror the exact
   * response item's purpose / keyId / businessKeyVersion / format / digest /
   * KCV; otherwise the business version must not be activated.
   */
  public static void validateAckBinding(KeyProvisioningResponse response, KeyProvisioningAck ack) {
    if (response.getResult() != KeyProvisioningResult.KEY_PROVISIONING_RESULT_SUCCEEDED) {
      throw new InvalidKeyprovInput("ACK binding requires a SUCCEEDED response");
    }
    if (ack.getItemsCount() != response.getItemsCount()) {
      throw new InvalidKeyprovInput("ACK item count must equal response item count");
    }
    for (int i = 0; i < response.getItemsCount(); i++) {
      WrappedKeyItem r = response.getItems(i);
      KeyImportItemResult a = ack.getItems(i);
      if (a.getPurpose() != r.getPurpose()
          || !a.getKeyId().equals(r.getKeyId())
          || a.getBusinessKeyVersion() != r.getBusinessKeyVersion()
          || a.getEnvelopeFormat() != r.getEnvelopeFormat()
          || !Arrays.equals(a.getEnvelopeDigest().toByteArray(), r.getEnvelopeDigest().toByteArray())
          || !Arrays.equals(a.getKeyCheckValue().toByteArray(), r.getKeyCheckValue().toByteArray())) {
        throw new InvalidKeyprovInput("ACK item #" + i + " does not bind response item #" + i);
      }
      exactLength("ack.envelope_digest", a.getEnvelopeDigest(), DIGEST_BYTES);
      exactLength("ack.key_check_value", a.getKeyCheckValue(), KCV_BYTES);
    }
  }

  // ---- helpers --------------------------------------------------------------

  public static void validateP256UncompressedPoint(byte[] point) {
    if (point == null || point.length != EPHEMERAL_PUBLIC_KEY_BYTES) {
      throw new InvalidKeyprovInput("server_ephemeral_public_key must be exactly "
          + EPHEMERAL_PUBLIC_KEY_BYTES + " bytes");
    }
    if (point[0] != UNCOMPRESSED_POINT_TAG) {
      throw new InvalidKeyprovInput("server_ephemeral_public_key must be SEC1 uncompressed (0x04)");
    }
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 33));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 33, 65));
    if (x.signum() < 0 || y.signum() < 0 || x.compareTo(P256_P) >= 0 || y.compareTo(P256_P) >= 0) {
      throw new InvalidKeyprovInput("server_ephemeral_public_key coordinates out of field range");
    }
    // y^2 == x^3 + a*x + b  (mod p); also rejects the point at infinity (0,0).
    BigInteger lhs = y.multiply(y).mod(P256_P);
    BigInteger rhs = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P);
    if (!lhs.equals(rhs)) {
      throw new InvalidKeyprovInput("server_ephemeral_public_key is not on P-256");
    }
  }

  private static void exactLength(String name, ByteString value, int expected) {
    exactLength(name, value.toByteArray(), expected);
  }

  private static void exactLength(String name, byte[] value, int expected) {
    if (value == null || value.length != expected) {
      throw new InvalidKeyprovInput(name + " must be exactly " + expected + " bytes (got "
          + (value == null ? 0 : value.length) + ")");
    }
  }

  /** Byte-wise constant-time comparison (design §6.2 step 5). */
  public static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a == null || b == null || a.length != b.length) {
      return false;
    }
    int diff = 0;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /** Fail-closed validation error. Shared with the contract check. */
  public static class InvalidKeyprovInput extends RuntimeException {
    public InvalidKeyprovInput(String message) {
      super(message);
    }
  }
}
