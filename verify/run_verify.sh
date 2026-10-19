#!/usr/bin/env bash
# =============================================================================
# run_verify.sh — PAR-PROTO-DSN-CR-002/003/004/005/006 verification harness
#
# Reproduces the release gates runnable here:
#   1. Maven reactor build (Java generation)            — gate 5 (Java)
#   2. buf lint on all modules                          — gate 1
#   3. Donor parity (common: schema-equal; fota: CR-005 touched files extend
#      the donor, untouched files byte-identical)       — acceptance #1 (CR-002)
#   4. Provenance SHA-256 vs committed sources/descriptors — gate 9 (CR-002/003/005)
#   5. Descriptor determinism (regenerate + compare)     — gate 3 (incl. ota)
#   6. PayloadType registry ↔ descriptor full-name        — gate 8
#   7. Java golden producer (reference bytes)             — cross-language contract
#   8. VAGW contract check + golden producer (CR-003)     — gates 2/3, acc. #1/#2/#3
#   9. CR-005 fota contract (old fields intact + additions + tri-state + compat)
#   10. canonicalization-v2 test vectors (bundle + invariants)  — §10.3
#   11. swinv deprecated + VAGW dep tree + raw Envelope bytes unchanged — §10.1.5/§10.4
#   12. CR-005 golden producer (MULTI_TARGET fota bytes)
#   13. CR-006 keyprov contract check (descriptor + generated class + §4.3/§4.4
#       gates + §5 sensitivity scan)                     — gates 2/3/4/8
#   14. CR-006 keyprov golden producer (6 payloads + Envelope wrapping) — acc. #1/#2
#   15. CR-007 keyprov ECDH-ES v1 contract check + golden producer (deterministic
#       parameters, envelopeDigest/AAD/KCV/proofInput, envelope v1 payloads)
#                                                        — CR-007 §4/§5/§7/§9 1-3
#   16. CR-007 keyprov integration check (relay byte-for-byte + additive downgrade
#       + capability negotiation + replay)               — CR-007 §8/§9 5-7
#   17. CR-008 keyprov import attestation golden producer (proofInputV1 vectors +
#       CR-008 ack with fields 10/11 + P1363 low-S placeholder) — CR-008 §3/§4/§5
#   18. CR-008 keyprov integration check (relay + additive downgrade + fail-closed
#       unknown/legacy algorithm + P1363 format/range + proofInputV1 binding)
#                                                        — CR-008 §3/§4/§5/§9
#   (buf breaking runs in CI against the previous release tag — first release
#    establishes an empty baseline and is documented in provenance.)
#
# Requires: mvn, java 17, shasum.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
PB_JAR="${HOME}/.m2/repository/com/google/protobuf/protobuf-java/3.25.5/protobuf-java-3.25.5.jar"
FAILURES=0

step()  { echo; echo "━━━ [$1/18] $2 ━━━"; }
fail()  { echo "  ✗ $1"; FAILURES=$((FAILURES+1)); }
pass()  { echo "  ✓ $1"; }

# ---- 1. Maven reactor build (Java generation) ------------------------------
step 1 "Maven reactor build (Java generation)"
if mvn -q clean install -DskipTests >/dev/null 2>&1; then
  pass "mvn clean install (proto-vmd, proto-vehicle-common, proto-fota, proto-vagw)"
else
  fail "mvn clean install"
fi

# ---- 2. buf lint (all active modules) -------------------------------------
# NOTE: iov-cloud-proto-vmd (deprecated legacy swinv) is intentionally NOT linted:
# CR-005 §8 freezes its enums/fields (no rename / no reuse), so its pre-existing
# ENUM_VALUE_PREFIX violations are tolerated until the separate compat-cleanup CR.
step 2 "buf lint (STANDARD) on active modules"
if command -v buf >/dev/null 2>&1; then
  if buf lint iov-cloud-proto-vehicle-common/src/main/proto >/dev/null 2>&1 \
     && buf lint iov-cloud-proto-fota/src/main/proto >/dev/null 2>&1 \
     && buf lint iov-cloud-proto-vagw/src/main/proto >/dev/null 2>&1 \
     && buf lint iov-cloud-proto-keyprov/src/main/proto >/dev/null 2>&1; then
    pass "buf lint common + fota + vagw + keyprov"
  else
    fail "buf lint common + fota + vagw + keyprov"
  fi
else
  echo "  (buf not installed — gate enforced in CI)"
fi

# ---- 3. Donor parity -------------------------------------------------------
# common/envelope.proto is compared by SCHEMA (descriptor without SourceCodeInfo).
# FOTA: CR-005 extends types/task/execution (canonical PAR-PROTO extensions); the
# other five files remain byte-identical to the donor snapshot.
step 3 "Donor parity (common: schema-equal; fota: CR-005 touched extend, others identical)"
DONOR_COMMON="${DONOR_COMMON:-/Users/hwyz_leo/Projects/open-iov/vehicle/cgw/iov-vehicle-cgw-fota/proto/vehicle/common/v1/envelope.proto}"
DONOR_FOTA="${DONOR_FOTA:-/Users/hwyz_leo/Projects/open-iov/vehicle/cgw/iov-vehicle-cgw-fota/proto/vehicle/fota/v1}"
PROTOC="${PROTOC:-$ROOT/iov-cloud-proto-fota/target/protoc-plugins/protoc-3.25.5-osx-aarch_64.exe}"
if [ -f "$DONOR_COMMON" ]; then
  if [ -x "$PROTOC" ]; then
    DONOR_PROTO_ROOT="${DONOR_COMMON%/vehicle/common/v1/envelope.proto}"
    "$PROTOC" -I "$DONOR_PROTO_ROOT" \
      --descriptor_set_out=/tmp/donor-common.pb vehicle/common/v1/envelope.proto
    "$PROTOC" -I iov-cloud-proto-vehicle-common/src/main/proto \
      --descriptor_set_out=/tmp/committed-common.pb vehicle/common/v1/envelope.proto
    if cmp -s /tmp/donor-common.pb /tmp/committed-common.pb; then
      pass "common/envelope.proto schema-equal to donor (CR-004 comment-only ok)"
    else
      fail "common/envelope.proto schema differs from donor"
    fi
  else
    echo "  (protoc not cached — schema-parity gate enforced in CI)"
  fi
  for f in "$DONOR_FOTA"/*.proto; do
    b=$(basename "$f")
    case "$b" in
      types.proto|task.proto|execution.proto)
        if diff -q "$f" "iov-cloud-proto-fota/src/main/proto/vehicle/fota/v1/$b" >/dev/null; then
          fail "fota/$b unexpectedly identical to donor (CR-005 must extend it)"
        else
          pass "fota/$b extends donor per CR-005 (canonical PAR-PROTO, one-way to VEH-PROTO)"
        fi
        ;;
      *)
        if diff -q "$f" "iov-cloud-proto-fota/src/main/proto/vehicle/fota/v1/$b" >/dev/null; then
          pass "fota/$b identical to donor"
        else
          fail "fota/$b differs from donor"
        fi
        ;;
    esac
  done
else
  echo "  (donor path not present — skipped; see provenance/vehicle-proto-baseline.yaml)"
fi

# ---- 4. Provenance SHA-256 verification ------------------------------------
step 4 "Provenance SHA-256 vs committed sources/descriptors"
shasum -a 256 \
  iov-cloud-proto-vehicle-common/src/main/proto/vehicle/common/v1/envelope.proto \
  descriptors/vehicle-common-v1.pb descriptors/vehicle-fota-v1.pb \
  > /tmp/cr002_checksums.txt
grep -q "5b6dbb6b981a95a98e06394f21f3b13a5ee52f1214b61c6cb02f56fd37932e6d" /tmp/cr002_checksums.txt && pass "common source sha256 matches manifest" || fail "common source sha256 mismatch"
grep -q "4ba4c1470270b16a44f30ce3bfff2062a703c0c88ac56bf89925a810651bc200" /tmp/cr002_checksums.txt && pass "common descriptor sha256 matches manifest" || fail "common descriptor sha256 mismatch"
# CR-005: fota descriptor hash updated (field append); donor bootstrap hash stays historical.
grep -q "8eb241c987e7b1546c15c76be3fcb67331e9d553af2ac8a28a7d0c8cd36c8908" /tmp/cr002_checksums.txt && pass "fota descriptor sha256 matches cr005_extension" || fail "fota descriptor sha256 mismatch"
# ---- CR-003: vagw source + descriptor (cloud_artifacts section) -----------
shasum -a 256 \
  iov-cloud-proto-vagw/src/main/proto/vagw/v1/delivery.proto \
  descriptors/vagw-delivery-v1.pb \
  > /tmp/cr003_checksums.txt
grep -q "d954d4661bf9d284a367eb01117550154368c5c91e90466158d82b43724b76db" /tmp/cr003_checksums.txt && pass "vagw source sha256 matches manifest" || fail "vagw source sha256 mismatch"
grep -q "556e3a3d3916e65ce03e392440911d5d01ae899d61777cd8a7b8e84679c913d7" /tmp/cr003_checksums.txt && pass "vagw descriptor sha256 matches manifest" || fail "vagw descriptor sha256 mismatch"
# ---- CR-005: canonical-v2 vector bundle ----------------------------------
shasum -a 256 verify/inventory-canonical-v2/vectors.yaml \
  > /tmp/cr005_checksums.txt
grep -q "897a8abb811441a944c9eea2a2c61ccee4f2fec88c0d7ab00206cd0ea055b89b" /tmp/cr005_checksums.txt && pass "canonical-v2 vector bundle sha256 matches manifest" || fail "canonical-v2 vector bundle sha256 mismatch"
# ---- CR-006/007/008: keyprov source + descriptor (security_artifact) -------
# CR-007 appended fields/messages/enum (additive); CR-008 appended
# ImportProofAlgorithm + KeyImportItemResult fields 10/11 and deprecated field 6.
# Hashes track the current canonical source. CR-006/007 payload bytes stay
# byte-identical (steps 14/15/17).
shasum -a 256 \
  iov-cloud-proto-keyprov/src/main/proto/security/keyprov/v1/key_provisioning.proto \
  descriptors/security-keyprov-v1.pb \
  > /tmp/cr006_checksums.txt
grep -q "5e737477ddc1cae57a8ac2350870c7614f2b2f378e17a51db15a03321cd944dd" /tmp/cr006_checksums.txt && pass "keyprov source sha256 matches manifest (CR-008)" || fail "keyprov source sha256 mismatch"
grep -q "cd610406aad05d5215a953c140a28b547fa3b2eb537ac7b27023e2911c3f5230" /tmp/cr006_checksums.txt && pass "keyprov descriptor sha256 matches manifest (CR-008)" || fail "keyprov descriptor sha256 mismatch"

# ---- 5. Descriptor determinism ---------------------------------------------
step 5 "DescriptorSet determinism (regenerate + compare)"
PROTOC="${PROTOC:-$ROOT/iov-cloud-proto-fota/target/protoc-plugins/protoc-3.25.5-osx-aarch_64.exe}"
if [ -x "$PROTOC" ]; then
  "$PROTOC" -I iov-cloud-proto-vehicle-common/src/main/proto \
    --descriptor_set_out=/tmp/common-regenerated.pb --include_imports \
    vehicle/common/v1/envelope.proto
  "$PROTOC" -I iov-cloud-proto-fota/src/main/proto \
    --descriptor_set_out=/tmp/fota-regenerated.pb --include_imports \
    vehicle/fota/v1/types.proto vehicle/fota/v1/task.proto vehicle/fota/v1/consent.proto \
    vehicle/fota/v1/package.proto vehicle/fota/v1/execution.proto vehicle/fota/v1/log.proto \
    vehicle/fota/v1/reconcile.proto vehicle/fota/v1/policy.proto
  "$PROTOC" -I iov-cloud-proto-vagw/src/main/proto \
    --descriptor_set_out=/tmp/vagw-regenerated.pb --include_imports \
    vagw/v1/delivery.proto
  "$PROTOC" -I iov-cloud-proto-keyprov/src/main/proto \
    --descriptor_set_out=/tmp/keyprov-regenerated.pb --include_imports \
    security/keyprov/v1/key_provisioning.proto
  if cmp -s /tmp/common-regenerated.pb descriptors/vehicle-common-v1.pb; then
    pass "common descriptor deterministic"
  else
    fail "common descriptor non-deterministic"
  fi
  if cmp -s /tmp/fota-regenerated.pb descriptors/vehicle-fota-v1.pb; then
    pass "fota descriptor deterministic"
  else
    fail "fota descriptor non-deterministic"
  fi
  if cmp -s /tmp/vagw-regenerated.pb descriptors/vagw-delivery-v1.pb; then
    pass "vagw descriptor deterministic"
  else
    fail "vagw descriptor non-deterministic"
  fi
  if cmp -s /tmp/keyprov-regenerated.pb descriptors/security-keyprov-v1.pb; then
    pass "keyprov descriptor deterministic"
  else
    fail "keyprov descriptor non-deterministic"
  fi
else
  echo "  (pinned protoc 3.25.5 not cached — run 'mvn compile' first)"
fi

# ---- 6. PayloadType registry ↔ descriptor full-name ------------------------
step 6 "PayloadType registry ↔ descriptor message full-name (gate 8)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR" -d verify/out verify/PayloadTypeCheck.java
  java -cp "$PB_JAR:verify/out" PayloadTypeCheck provenance/vehicle-proto-baseline.yaml \
    descriptors/vehicle-common-v1.pb descriptors/vehicle-fota-v1.pb descriptors/security-keyprov-v1.pb
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 7. Java golden producer (reference bytes) ---------------------------
step 7 "Java golden producer (reference bytes for vehicle-side C++ validation)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/golden/expected verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes" \
    -d verify/out verify/GoldenProducer.java
  java -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes:verify/out" \
    GoldenProducer
  pass "Java golden reference bytes produced (envelope_taskcheck / unknown_field / unknown_enum)"
  shasum -a 256 verify/golden/expected/*.bin
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 8. VAGW contract check + golden producer (CR-003) --------------------
step 8 "VAGW contract + golden (gate 2/3, acceptance #1/#2/#3)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-vagw/target/classes" -d verify/out verify/VagwContractCheck.java
  java -cp "$PB_JAR:iov-cloud-proto-vagw/target/classes:verify/out" VagwContractCheck descriptors/vagw-delivery-v1.pb

  mkdir -p verify/golden/expected verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-vagw/target/classes" -d verify/out verify/VagwGoldenProducer.java
  java -cp "$PB_JAR:iov-cloud-proto-vagw/target/classes:verify/out" VagwGoldenProducer
  pass "vagw golden reference bytes produced (accepted / rejected / unknown / unknown_field / unknown_enum)"
  shasum -a 256 verify/golden/expected/vagw_delivery_*.bin
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 9. CR-005 fota contract (CI gates 2/3/4/5/7/8) ------------------------
step 9 "CR-005 fota contract (old fields intact + additions + tri-state + compat)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes" \
    -d verify/out verify/CanonicalV2.java verify/FotaContractCheck.java \
    verify/EcuVersionComboCheck.java verify/ConsistencyCheck.java
  java -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes:verify/out" \
    FotaContractCheck descriptors/vehicle-fota-v1.pb
  java -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes:verify/out" \
    EcuVersionComboCheck
  java -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes:verify/out" \
    ConsistencyCheck
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 10. canonicalization-v2 test vectors (design §5.3 / gate 6) -----------
step 10 "canonicalization-v2 test vectors (bundle + invariants)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes" \
    -d verify/out verify/CanonicalV2.java verify/CanonicalV2Check.java
  java -cp "$PB_JAR:iov-cloud-proto-vehicle-common/target/classes:iov-cloud-proto-fota/target/classes:verify/out" \
    CanonicalV2Check
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 11. swinv deprecated + VAGW dep tree + raw Envelope bytes ------------
step 11 "swinv deprecated + VAGW dependency tree + raw Envelope bytes (§10.1.5/§10.4)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-vmd/target/classes" \
    -d verify/out verify/SwinvContractCheck.java
  java -cp "$PB_JAR:iov-cloud-proto-vmd/target/classes:verify/out" \
    SwinvContractCheck
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi
# VAGW dependency tree: proto-vagw must NOT depend on proto-fota / proto-vmd
# (design §2/§10.1.5: VAGW 对 FOTA 只解析 common Envelope metadata 并原样转发
# payload bytes，不得引入 proto-fota 或解析 EcuVersion/SoftwareUnitVersion)
if grep -qE "proto-(fota|vmd)" iov-cloud-proto-vagw/pom.xml 2>/dev/null; then
  fail "VAGW pom must not depend on proto-fota/proto-vmd"
else
  pass "VAGW dependency tree clean (no proto-fota/proto-vmd)"
fi
# raw Envelope bytes unchanged (design §10.1.5): golden hashes match manifest
shasum -a 256 verify/golden/expected/envelope_taskcheck.bin \
  verify/golden/expected/envelope_unknown_field.bin \
  verify/golden/expected/envelope_unknown_enum.bin \
  > /tmp/envelope_checksums.txt
grep -q "7f260cefd97ef972f64e8b5ece85fb79286eec9b67c87a74ae993b33d257b2c0" /tmp/envelope_checksums.txt \
  && grep -q "75a5e30b9f67e340edca41eacf585b954f501340364b1ee23eb691bfe59b5a11" /tmp/envelope_checksums.txt \
  && grep -q "b5a73b164b176d92086e4f4976822a9c44bdb4ecaf0e9d110111147a75d23b6f" /tmp/envelope_checksums.txt \
  && pass "raw Envelope bytes unchanged (golden hashes match manifest)" \
  || fail "raw Envelope bytes changed vs manifest"

# ---- 12. CR-005 golden producer (design §10.1/§10.3) ----------------------
step 12 "CR-005 golden producer (MULTI_TARGET fota bytes)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/golden/expected verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-fota/target/classes" \
    -d verify/out verify/Cr005GoldenProducer.java
  java -cp "$PB_JAR:iov-cloud-proto-fota/target/classes:verify/out" \
    Cr005GoldenProducer
  pass "CR-005 golden reference bytes produced (fota_ecu_version_multitarget / fota_taskcheck_canonical_v2)"
  shasum -a 256 verify/golden/expected/fota_ecu_version_multitarget.bin \
    verify/golden/expected/fota_taskcheck_canonical_v2.bin
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 13. CR-006/007 keyprov contract check (gates 2/3/4/8) ----------------
step 13 "CR-006/007 keyprov contract (descriptor + generated class + §4.3/§4.4/§5/§6/§7)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes" \
    -d verify/out verify/KeyprovCanonicalV1.java verify/KeyprovContractCheck.java
  java -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:verify/out" \
    KeyprovContractCheck descriptors/security-keyprov-v1.pb
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 14. CR-006 keyprov golden producer (§3/§7, acceptance #1/#2) ----------
step 14 "CR-006 keyprov golden producer (6 payloads + Envelope wrapping)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/golden/expected verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes" \
    -d verify/out verify/KeyprovGoldenProducer.java
  java -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes:verify/out" \
    KeyprovGoldenProducer
  pass "keyprov golden reference bytes produced (request/response/ack/ack_result/status + Envelope)"
  shasum -a 256 verify/golden/expected/keyprov_*.bin verify/golden/expected/envelope_keyprov_*.bin
  # CR-007 §8 additive compatibility: the CR-006 payload bytes must be unchanged.
  shasum -a 256 \
    verify/golden/expected/keyprov_request.bin \
    verify/golden/expected/keyprov_response_success.bin \
    verify/golden/expected/keyprov_ack.bin \
    > /tmp/cr006_golden_checksums.txt
  grep -q "964184dd8bd6914dc2f97888baec83335bfeaeb5669c2400b14ec52eac32b055" /tmp/cr006_golden_checksums.txt \
    && grep -q "4b80c0d8250ad45ff8bf991332c63d863910bad90771bb434f037f18bafa8fbb" /tmp/cr006_golden_checksums.txt \
    && grep -q "0e241a3aac817d9cb8c25bae9de30a744c900360512cdceef97c1190731eb789" /tmp/cr006_golden_checksums.txt \
    && pass "CR-006 keyprov payload bytes unchanged by CR-007 (additive wire compatible)" \
    || fail "CR-006 keyprov payload bytes changed — CR-007 is not additive"
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 15. CR-007 keyprov ECDH-ES v1 golden producer (§4/§5/§9 items 1-3) ----
step 15 "CR-007 keyprov ECDH-ES v1 golden producer (parameters/digests/KCV/proofInput)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/golden/expected verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes" \
    -d verify/out verify/KeyprovCanonicalV1.java verify/KeyprovCr007GoldenProducer.java
  java -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes:verify/out" \
    KeyprovCr007GoldenProducer
  pass "CR-007 golden reference bytes produced (deterministic parameters + envelopeDigest/AAD/KCV/proofInput)"
  shasum -a 256 verify/golden/expected/keyprov_ecdh_v1_*.bin \
    verify/golden/expected/envelope_keyprov_ecdh_v1_*.bin > /tmp/cr007_golden_checksums.txt
  grep -q "86c5059c217aaea74dc0dba488ebab88d4e2fc409e4fb694b044c476652a990c" /tmp/cr007_golden_checksums.txt \
    && grep -q "03cef07f69c3b33af26409720d47577d92f6b442721a72d9f88b68ce2435f63e" /tmp/cr007_golden_checksums.txt \
    && grep -q "011e5f381fb949dcb5d8e3bf31f560594682c1cedf34c3a165209365d2571b89" /tmp/cr007_golden_checksums.txt \
    && pass "CR-007 golden hashes match manifest (parameters/envelopeDigest/proofInput)" \
    || fail "CR-007 golden hashes differ from manifest"
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 16. CR-007 keyprov integration check (§8/§9 items 5-7) ---------------
step 16 "CR-007 keyprov integration (relay byte-for-byte + additive downgrade + negotiation)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes" \
    -d verify/out verify/KeyprovCanonicalV1.java verify/KeyprovCr007IntegrationCheck.java
  java -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes:verify/out" \
    KeyprovCr007IntegrationCheck
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 17. CR-008 keyprov import attestation golden producer (§3/§4/§5/§9) --
step 17 "CR-008 keyprov import attestation golden producer (proofInputV1 + ack + P1363)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/golden/expected verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes" \
    -d verify/out verify/KeyprovCanonicalV1.java verify/KeyprovCr008GoldenProducer.java
  java -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes:verify/out" \
    KeyprovCr008GoldenProducer
  pass "CR-008 golden reference bytes produced (proofInputV1 vectors + CR-008 ack + Envelope)"
  shasum -a 256 verify/golden/expected/keyprov_cr008_*.bin \
    verify/golden/expected/envelope_keyprov_cr008_*.bin > /tmp/cr008_golden_checksums.txt
  grep -q "f998b4800f01850a8768d90164912657293ee59cefc45f1f9ea6fb1312c17110" /tmp/cr008_golden_checksums.txt \
    && grep -q "2a7685c06d37cac2498d8318bfbc7d1d96dd59b74f115638d104263d304787d3" /tmp/cr008_golden_checksums.txt \
    && grep -q "c67957e7f9fa588dad6f1e60737185b5af92a874cd66bbd09d4ff5fc24cbd383" /tmp/cr008_golden_checksums.txt \
    && pass "CR-008 golden hashes match manifest (proofInputV1 up/down + ack)" \
    || fail "CR-008 golden hashes differ from manifest"
  # CR-007 legacy proofInput golden must remain byte-identical (additive wire).
  shasum -a 256 verify/golden/expected/keyprov_ecdh_v1_proof_input_up.bin \
    > /tmp/cr008_legacy_check.txt
  grep -q "011e5f381fb949dcb5d8e3bf31f560594682c1cedf34c3a165209365d2571b89" /tmp/cr008_legacy_check.txt \
    && pass "CR-007 proofInput golden bytes unchanged by CR-008 (legacy regression only)" \
    || fail "CR-007 proofInput golden bytes changed by CR-008"
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 18. CR-008 keyprov integration check (§3/§4/§5/§9 items 2-8) ----------
step 18 "CR-008 keyprov integration (relay + additive downgrade + fail-closed + P1363)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes" \
    -d verify/out verify/KeyprovCanonicalV1.java verify/KeyprovCr008IntegrationCheck.java
  java -cp "$PB_JAR:iov-cloud-proto-keyprov/target/classes:iov-cloud-proto-vehicle-common/target/classes:verify/out" \
    KeyprovCr008IntegrationCheck
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "✅ ALL VERIFY GATES PASSED"
  exit 0
else
  echo "❌ ${FAILURES} gate(s) FAILED"
  exit 1
fi
