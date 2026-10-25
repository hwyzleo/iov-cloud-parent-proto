import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.MessageLite;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import net.hwyz.iov.security.keyprov.v1.EcdhEsP256EnvelopeParametersV1;
import net.hwyz.iov.security.keyprov.v1.ImportProofAlgorithm;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyImportItemResult;
import net.hwyz.iov.security.keyprov.v1.KeyImportResult;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningAck;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResponse;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningResult;
import net.hwyz.iov.security.keyprov.v1.KeyPurpose;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;

/**
 * security.keyprov.v1 ECDH-ES v1 canonical reference implementation
 * (PAR-PROTO-DSN-CR-007 §4 / §5 / §6 / §7, PAR-PROTO-DSN-CR-009 §2).
 *
 * <p>PAR-PROTO-DSN-CR-008 adds the versioned {@code proofInputV1} production
 * canonical method, {@code V2C_COMM} businessDomain gate, frozen purpose 1/2
 * mapping, businessKeyVersion range and the ECDSA P-256/SHA-256 IEEE-P1363
 * low-S format/range contract. It still performs NO cryptographic verification:
 * device signing is owned by TBOX-SEC and real ECDSA verification by FW-SEC.
 *
 * <p>PAR-PROTO-DSN-CR-009 freezes the V2C wire canonical registry: the 9-field
 * {@code wireEnvelopeDigest} (WIRE_PROFILE {@link #WIRE_PROFILE}) is the ONLY
 * digest carried in {@code WrappedKeyItem.envelope_digest} / {@code
 * KeyImportItemResult.envelope_digest}; the 10-segment canonical AAD (AAD_PROFILE
 * {@link #AAD_PROFILE}) is frozen by this registry and the authoritative vector
 * bundle {@code verify/keyprov-ecdh-es-p256-v1/}. FW-SEC's 18-field
 * {@code coreEnvelopeDigest} stays an internal result-integrity fact and MUST
 * NOT enter the wire, ACK or import attestation.
 *
 * This class is the single Java authority for the cross-language (Java/C++)
 * byte-exact contract of the ECDH-ES v1 envelope. It deliberately contains NO
 * key material and NO cryptography beyond hashing: the design freezes the
 * canonical framing, digests and gates here; the actual ECDH/HKDF/AEAD and the
 * ACK proof algorithm are owned by FW-SEC / TBOX-SEC.
 *
 * Framing (design §4.2 / CR-009 §2.1):
 *   - every segment is prefixed with an unsigned 32-bit big-endian length;
 *   - strings enter as raw UTF-8 bytes (no BOM, no trim, no case-fold);
 *   - enums enter as their canonical shortest unsigned varint integer value
 *     (never name()/ordinal()/ZigZag);
 *   - bytes (wrappedKey / parameters / recipientCertificateDigest) enter as
 *     raw content;
 *   - businessKeyVersion / rootKeyVersion enter as a fixed 8-byte big-endian
 *     uint64 (never protobuf varint / decimal text).
 *
 *   wireDigestInput = lengthPrefixed(
 *       envelopeFormat, requestId, businessDomain, purpose, keyId,
 *       businessKeyVersion, wrappingSuite, wrappedKey, parameters)
 *   wireEnvelopeDigest = SHA-256(wireDigestInput)
 *   (the envelope_digest field itself never enters the digest)
 *
 *   canonicalAad (CR-009 §2.2, 10 segments, order frozen):
 *     envelopeFormat(varint) || wrappingSuite(varint) || purpose(varint)
 *     || uint64be(businessKeyVersion) || uint64be(rootKeyVersion)
 *     || recipientCertificateDigest(raw) || UTF8(requestId)
 *     || UTF8(businessDomain) || UTF8(keyId) || UTF8(derivationVersion)
 *   aadDigest = SHA-256(canonicalAad)
 *
 *   proofInput = lengthPrefixed(
 *       UTF8("openiov|keyprov-ack|v1"), UTF8(requestId), UTF8(businessDomain),
 *       enumValue(purpose), SHA-256(UTF8(keyId)), uint64be(businessKeyVersion),
 *       envelopeDigest, keyCheckValue)
 *
 *   proofInputV1 (CR-008 §4.1) has the same eight flat segments; it is the only
 *   production method. The pre-CR-008 proofInput(...) is @Deprecated and only a
 *   compatibility regression vector.
 *
 *   keyCheckValue = first_3_bytes(SHA-256(businessKey))
 *
 * Producers and consumers MUST NOT customize field order, wire kind, string
 * comparison, domain framing or the fixed v1 lengths below.
 */
public final class KeyprovCanonicalV1 {

  public static final String PROOF_DOMAIN = "openiov|keyprov-ack|v1";

  // ---- CR-009 wire canonical registry (PAR-PROTO-DSN-CR-009 §2) ------------
  /** 9-field wire envelope digest profile, frozen by the PAR-PROTO registry. */
  public static final String WIRE_PROFILE = "PAR_PROTO_KEYPROV_ECDH_ES_P256_V1";
  /** 10-segment canonical AAD profile, frozen by the PAR-PROTO registry. */
  public static final String AAD_PROFILE = "PAR_PROTO_KEYPROV_AAD_V1";
  /** FW-SEC 18-field internal digest name; MUST NOT enter the wire/ACK/proof. */
  public static final String CORE_ENVELOPE_DIGEST_NAME = "coreEnvelopeDigest";
  /** PAR-PROTO wire digest name carried in envelope_digest fields. */
  public static final String WIRE_ENVELOPE_DIGEST_NAME = "wireEnvelopeDigest";

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

  // ---- CR-008 import attestation constants (PAR-PROTO-DSN-CR-008 §3/§4/§5) --
  /** design §4.2/RD-008-5: the only accepted businessDomain value in v1. */
  public static final String BUSINESS_DOMAIN_V1 = "V2C_COMM";
  public static final long MIN_BUSINESS_KEY_VERSION = 1L;
  public static final long MAX_BUSINESS_KEY_VERSION = (1L << 63) - 1;
  /** ECDSA P-256 P1363: r(32) || s(32). */
  public static final int P1363_SIGNATURE_BYTES = 64;

  private static final BigInteger P256_P = new BigInteger(
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
  private static final BigInteger P256_A = P256_P.subtract(BigInteger.valueOf(3));
  private static final BigInteger P256_B = new BigInteger(
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
  private static final BigInteger P256_ORDER_N = new BigInteger(
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
  private static final BigInteger P256_HALF_ORDER_N = P256_ORDER_N.shiftRight(1);

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

  // ---- CR-009 canonical AAD registry (§2.2) --------------------------------

  /**
   * CR-009 §2.2: the 10-segment canonical AAD frozen by the PAR-PROTO registry
   * (AAD_PROFILE {@link #AAD_PROFILE}). Field order and segment rules are fixed:
   * envelopeFormat / wrappingSuite / purpose as shortest unsigned varint,
   * businessKeyVersion / rootKeyVersion as 8-byte big-endian uint64,
   * recipientCertificateDigest as raw 32 bytes, strings as no-BOM UTF-8.
   * The cloud AES-GCM encryption MUST use exactly these bytes; TBOX-SEC rebuilds
   * the AAD from the outer context and compares in constant time.
   */
  public static byte[] canonicalAad(WrappedKeyItem item, EcdhEsP256EnvelopeParametersV1 params,
      String requestId, String businessDomain) {
    if (item == null || params == null) {
      throw new InvalidKeyprovInput("canonical AAD requires item and parameters");
    }
    return lengthPrefixed(
        unsignedVarint(item.getEnvelopeFormatValue()),
        unsignedVarint(item.getWrappingSuiteValue()),
        unsignedVarint(item.getPurposeValue()),
        uint64be(item.getBusinessKeyVersion()),
        uint64be(params.getRootKeyVersion()),
        params.getRecipientCertificateDigest().toByteArray(),
        utf8(requestId),
        utf8(businessDomain),
        utf8(item.getKeyId()),
        utf8(params.getDerivationVersion()));
  }

  /**
   * CR-009 §2.2 / §8.2.2.3: rebuild the canonical AAD from the outer Response /
   * request context and bind it to the carried {@code canonical_aad} + {@code
   * aad_digest}. Constant-time comparison; any mismatch rejects the whole item.
   * (The real AES-GCM unseal with the same AAD is owned by TBOX-SEC.)
   */
  public static void validateAadBinding(WrappedKeyItem item,
      EcdhEsP256EnvelopeParametersV1 params, String requestId, String businessDomain) {
    byte[] rebuilt = canonicalAad(item, params, requestId, businessDomain);
    if (rebuilt.length > MAX_CANONICAL_AAD_BYTES) {
      throw new InvalidKeyprovInput("canonical_aad > " + MAX_CANONICAL_AAD_BYTES + " bytes");
    }
    if (!constantTimeEquals(rebuilt, params.getCanonicalAad().toByteArray())) {
      throw new InvalidKeyprovInput(
          "canonical_aad does not match PAR_PROTO_KEYPROV_AAD_V1 registry rebuild");
    }
    if (!constantTimeEquals(aadDigest(rebuilt), params.getAadDigest().toByteArray())) {
      throw new InvalidKeyprovInput("aad_digest does not match SHA-256(canonicalAad)");
    }
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

  // ---- CR-009 wire envelope digest (§2.1) ---------------------------------

  /**
   * CR-009 §2.1: raw 9-segment wire digest input (before SHA-256). Exposed so
   * the authoritative vector bundle can freeze {@code wire_digest_input.bin}
   * and Java/C++ can compare byte-exactly.
   */
  public static byte[] wireDigestInput(String requestId, String businessDomain, WrappedKeyItem item) {
    return lengthPrefixed(
        unsignedVarint(item.getEnvelopeFormatValue()),
        utf8(requestId),
        utf8(businessDomain),
        unsignedVarint(item.getPurposeValue()),
        utf8(item.getKeyId()),
        uint64be(item.getBusinessKeyVersion()),
        unsignedVarint(item.getWrappingSuiteValue()),
        item.getWrappedKey().toByteArray(),
        item.getParameters().toByteArray());
  }

  /**
   * CR-009 §2.1: the single production wire digest
   * {@code SHA-256(wireDigestInput)}, profile {@link #WIRE_PROFILE}. Carried in
   * {@code envelope_digest}; it is NOT FW-SEC {@link #CORE_ENVELOPE_DIGEST_NAME}.
   */
  public static byte[] wireEnvelopeDigest(String requestId, String businessDomain,
      WrappedKeyItem item) {
    return sha256(wireDigestInput(requestId, businessDomain, item));
  }

  /**
   * CR-007 legacy alias of {@link #wireEnvelopeDigest(String, String,
   * WrappedKeyItem)}. Kept ONLY so the CR-007/CR-008 golden reference bytes stay
   * byte-identical (additive wire). Production code and new vectors must use
   * {@link #wireEnvelopeDigest}.
   *
   * @deprecated use {@link #wireEnvelopeDigest(String, String, WrappedKeyItem)}.
   */
  @Deprecated
  public static byte[] envelopeDigest(String requestId, String businessDomain, WrappedKeyItem item) {
    return wireEnvelopeDigest(requestId, businessDomain, item);
  }

  /**
   * CR-008 §4.3 legacy canonical proof input. Kept ONLY as a compatibility
   * regression vector: it MUST NOT be used for production signing/verification,
   * readiness, capability or new golden vectors, and performs no CR-008 value
   * gate (e.g. it still accepts the legacy lowercase businessDomain).
   *
   * @deprecated use {@link #proofInputV1(String, String, KeyImportItemResult)}.
   */
  @Deprecated
  public static byte[] proofInput(String requestId, String businessDomain, KeyImportItemResult item) {
    return proofInputCore(requestId, businessDomain, item);
  }

  /**
   * CR-008 §4.1/§4.2 the single production canonical method: eight flat
   * length-prefixed segments. Fails closed on a non-{@code V2C_COMM}
   * businessDomain, UNSPECIFIED purpose, out-of-range version or malformed
   * digest/KCV.
   */
  public static byte[] proofInputV1(String requestId, String businessDomain, KeyImportItemResult item) {
    validateBusinessDomain(businessDomain);
    validatePurpose(item.getPurpose());
    validateBusinessKeyVersion(item.getBusinessKeyVersion());
    exactLength("envelope_digest", item.getEnvelopeDigest(), DIGEST_BYTES);
    exactLength("key_check_value", item.getKeyCheckValue(), KCV_BYTES);
    return proofInputCore(requestId, businessDomain, item);
  }

  private static byte[] proofInputCore(String requestId, String businessDomain, KeyImportItemResult item) {
    return lengthPrefixed(
        utf8(PROOF_DOMAIN),
        utf8(requestId),
        utf8(businessDomain),
        unsignedVarint(item.getPurposeValue()),
        keyIdDigest(item.getKeyId()),
        uint64be(item.getBusinessKeyVersion()),
        item.getEnvelopeDigest().toByteArray(),
        item.getKeyCheckValue().toByteArray());
  }

  /** CR-008 §4.2: keyId enters the canonical input as SHA-256(UTF-8(keyId)). */
  public static byte[] keyIdDigest(String keyId) {
    return sha256(utf8(keyId));
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
    byte[] recomputed = wireEnvelopeDigest(requestId, businessDomain, item);
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

  // ---- CR-008 import attestation gates (§3.1/§4.2/§5/§9/§10) ---------------

  /** CR-008 §4.2: businessDomain must be exactly V2C_COMM (no trim/fold/alias/fallback). */
  public static void validateBusinessDomain(String businessDomain) {
    if (!BUSINESS_DOMAIN_V1.equals(businessDomain)) {
      throw new InvalidKeyprovInput("businessDomain must be exactly " + BUSINESS_DOMAIN_V1
          + " (no trim/case-fold/alias/fallback)");
    }
  }

  /** CR-008 §4.2 / RD-008-6: only the frozen numeric purposes 1/2 are accepted; 0 is reserved. */
  public static void validatePurpose(KeyPurpose purpose) {
    if (purpose != KeyPurpose.KEY_PURPOSE_UPLINK_AEAD
        && purpose != KeyPurpose.KEY_PURPOSE_DOWNLINK_AEAD) {
      throw new InvalidKeyprovInput("purpose must be UPLINK_AEAD(1) or DOWNLINK_AEAD(2)");
    }
  }

  /** CR-008 §4.2: businessKeyVersion valid range is 1..2^63-1, encoded uint64be. */
  public static void validateBusinessKeyVersion(long version) {
    if (version < MIN_BUSINESS_KEY_VERSION || version > MAX_BUSINESS_KEY_VERSION) {
      throw new InvalidKeyprovInput("business_key_version out of range [1, 2^63-1]: " + version);
    }
  }

  /**
   * CR-008 §5: ECDSA P-256/SHA-256 IEEE-P1363 r(32)||s(32), low-S.
   *
   * <p>Deterministic fail-closed on wrong length (rejects 63/65 byte and DER
   * encodings), r/s = 0, r/s &gt;= n and s &gt; n/2 (high-S). This performs NO
   * cryptographic verification: the real ECDSA P-256 verify is owned by FW-SEC
   * and device signing by TBOX-SEC (design §5/§7).
   */
  public static void validateP1363LowS(byte[] proof) {
    if (proof == null || proof.length != P1363_SIGNATURE_BYTES) {
      throw new InvalidKeyprovInput("import_proof must be exactly " + P1363_SIGNATURE_BYTES
          + " bytes (P1363 r||s); DER/other encodings are not accepted");
    }
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(proof, 0, 32));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(proof, 32, 64));
    if (r.signum() == 0 || r.compareTo(P256_ORDER_N) >= 0) {
      throw new InvalidKeyprovInput("import_proof r out of range [1, n-1]");
    }
    if (s.signum() == 0 || s.compareTo(P256_HALF_ORDER_N) > 0) {
      throw new InvalidKeyprovInput("import_proof s out of range [1, n/2] (low-S required)");
    }
  }

  /**
   * CR-008 §3.1 success-item contract for a per-purpose ECDSA P-256 import
   * attestation. Only IMPORTED items are constrained; failure/unknown items are
   * governed by the result status matrix. The legacy proof_algorithm string must
   * stay empty so it cannot form a second source of truth.
   */
  public static void validateCr008SuccessItem(KeyImportItemResult item, byte[] expectedCertificateDigest) {
    if (item.getResult() != KeyImportResult.KEY_IMPORT_RESULT_IMPORTED) {
      return;
    }
    if (item.getImportProofAlgorithm()
        != ImportProofAlgorithm.IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363) {
      throw new InvalidKeyprovInput("success import_proof_algorithm must be ECDSA_P256_SHA256_P1363");
    }
    if (!item.getProofAlgorithm().isEmpty()) {
      throw new InvalidKeyprovInput("legacy proof_algorithm must be empty for CR-008 producers");
    }
    validateP1363LowS(item.getImportProof().toByteArray());
    exactLength("recipient_certificate_digest", item.getRecipientCertificateDigest(), DIGEST_BYTES);
    if (expectedCertificateDigest != null
        && !constantTimeEquals(item.getRecipientCertificateDigest().toByteArray(),
            expectedCertificateDigest)) {
      throw new InvalidKeyprovInput(
          "recipient_certificate_digest does not match the provisioning-bound certificate digest");
    }
  }

  /**
   * CR-008 §9 item 8 / §10: readiness derived ONLY from the governed CR-008
   * fields. A stable legacy proofInput(...) or a legacy proof_algorithm string
   * can never make this true.
   */
  public static boolean isCr008Attested(KeyImportItemResult item) {
    return item.getImportProofAlgorithm()
            == ImportProofAlgorithm.IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363
        && item.getProofAlgorithm().isEmpty()
        && item.getImportProof().size() == P1363_SIGNATURE_BYTES
        && item.getRecipientCertificateDigest().size() == DIGEST_BYTES;
  }

  /**
   * CR-008 §10 capability is a conjunction of independent, externally verified
   * conditions. PAR-PROTO only encodes the gate; it never infers readiness from
   * wire parseability or a legacy proof method.
   */
  public static boolean importAttestationCapabilityReady(boolean parProtoCr008Effective,
      boolean tboxSecSignReady, boolean fwSecVerifyReady, boolean vmdAdapterReady,
      boolean vectorsPass) {
    return parProtoCr008Effective && tboxSecSignReady && fwSecVerifyReady && vmdAdapterReady
        && vectorsPass;
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
