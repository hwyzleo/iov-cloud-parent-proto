#!/usr/bin/env bash
# =============================================================================
# run_verify.sh — PAR-PROTO-DSN-CR-002 + PAR-PROTO-DSN-CR-003 verification harness
#
# Reproduces the release gates (design §5 / §11 + CR-003 §6 / §9) runnable here:
#   1. Maven reactor build (Java generation)            — gate 5 (Java)
#   2. buf lint on vehicle-common + fota + vagw modules — gate 1
#   3. Donor parity (common: schema-equal to donor; fota: byte-identical) — acceptance #1
#   4. Provenance SHA-256 vs committed sources/descriptors — gate 9
#   5. Descriptor determinism (regenerate + compare)     — gate 3 (incl. vagw)
#   6. PayloadType registry ↔ descriptor full-name        — gate 8
#   7. Java golden producer (reference bytes)             — cross-language contract
#      (C++ generation + byte-identical round-trip is validated on the
#       VEH-PROTO/vehicle side from the released DescriptorSet)
#   8. VAGW contract check + golden producer (CR-003)     — gates 2/3, acceptance #1/#2/#3
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

step()  { echo; echo "━━━ [$1/8] $2 ━━━"; }
fail()  { echo "  ✗ $1"; FAILURES=$((FAILURES+1)); }
pass()  { echo "  ✓ $1"; }

# ---- 1. Maven reactor build (Java generation) ------------------------------
step 1 "Maven reactor build (Java generation)"
if mvn -q clean install -DskipTests >/dev/null 2>&1; then
  pass "mvn clean install (proto-vmd, proto-vehicle-common, proto-fota, proto-vagw)"
else
  fail "mvn clean install"
fi

# ---- 2. buf lint (vehicle-common + fota) -----------------------------------
step 2 "buf lint (STANDARD) on new modules"
if command -v buf >/dev/null 2>&1; then
  if buf lint iov-cloud-proto-vehicle-common/src/main/proto >/dev/null 2>&1 \
     && buf lint iov-cloud-proto-fota/src/main/proto >/dev/null 2>&1 \
     && buf lint iov-cloud-proto-vagw/src/main/proto >/dev/null 2>&1; then
    pass "buf lint common + fota + vagw"
  else
    fail "buf lint common + fota + vagw"
  fi
else
  echo "  (buf not installed — gate enforced in CI)"
fi

# ---- 3. Donor parity -------------------------------------------------------
# common/envelope.proto is compared by SCHEMA (descriptor without SourceCodeInfo):
# after PAR-PROTO-DSN-CR-004 the canonical field-3 comment is normative and
# intentionally diverges from the donor snapshot, but the schema / wire contract
# MUST stay identical (comment-only changes never appear in the descriptor).
# FOTA files are untouched by this CR and remain byte-identical to the donor.
step 3 "Donor parity (common: schema-equal; fota: byte-identical)"
DONOR_COMMON="${DONOR_COMMON:-/Users/hwyz_leo/Projects/open-iov/vehicle/cgw/iov-vehicle-cgw-fota/proto/vehicle/common/v1/envelope.proto}"
DONOR_FOTA="${DONOR_FOTA:-/Users/hwyz_leo/Projects/open-iov/vehicle/cgw/iov-vehicle-cgw-fota/proto/vehicle/fota/v1}"
PROTOC="${PROTOC:-$ROOT/iov-cloud-proto-fota/target/protoc-plugins/protoc-3.25.5-osx-aarch_64.exe}"
if [ -f "$DONOR_COMMON" ]; then
  if [ -x "$PROTOC" ]; then
    # Schema parity: regenerate descriptors from donor and committed source
    # (no --include_source_info) using the SAME proto root + relative path, so
    # the FileDescriptorProto.name matches and comment-only changes (CR-004)
    # never alter the bytes; any field/type/package drift would.
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
    if diff -q "$f" "iov-cloud-proto-fota/src/main/proto/vehicle/fota/v1/$b" >/dev/null; then
      pass "fota/$b identical to donor"
    else
      fail "fota/$b differs from donor"
    fi
  done
else
  echo "  (donor path not present — skipped; see provenance/vehicle-proto-baseline.yaml)"
fi

# ---- 4. Provenance SHA-256 verification ------------------------------------
step 4 "Provenance SHA-256 vs committed sources/descriptors"
# Recompute and diff against the manifest's recorded values.
shasum -a 256 \
  iov-cloud-proto-vehicle-common/src/main/proto/vehicle/common/v1/envelope.proto \
  descriptors/vehicle-common-v1.pb descriptors/vehicle-fota-v1.pb \
  > /tmp/cr002_checksums.txt
grep -q "5b6dbb6b981a95a98e06394f21f3b13a5ee52f1214b61c6cb02f56fd37932e6d" /tmp/cr002_checksums.txt && pass "common source sha256 matches manifest" || fail "common source sha256 mismatch"
grep -q "4ba4c1470270b16a44f30ce3bfff2062a703c0c88ac56bf89925a810651bc200" /tmp/cr002_checksums.txt && pass "common descriptor sha256 matches manifest" || fail "common descriptor sha256 mismatch"
grep -q "56924c848d767e5e2c0cde20a1831208ab5d416035dd83ccd8354d6742a9008e" /tmp/cr002_checksums.txt && pass "fota descriptor sha256 matches manifest" || fail "fota descriptor sha256 mismatch"
# ---- CR-003: vagw source + descriptor (cloud_artifacts section) -----------
shasum -a 256 \
  iov-cloud-proto-vagw/src/main/proto/vagw/v1/delivery.proto \
  descriptors/vagw-delivery-v1.pb \
  > /tmp/cr003_checksums.txt
grep -q "d954d4661bf9d284a367eb01117550154368c5c91e90466158d82b43724b76db" /tmp/cr003_checksums.txt && pass "vagw source sha256 matches manifest" || fail "vagw source sha256 mismatch"
grep -q "556e3a3d3916e65ce03e392440911d5d01ae899d61777cd8a7b8e84679c913d7" /tmp/cr003_checksums.txt && pass "vagw descriptor sha256 matches manifest" || fail "vagw descriptor sha256 mismatch"

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
else
  echo "  (pinned protoc 3.25.5 not cached — run 'mvn compile' first)"
fi

# ---- 6. PayloadType registry ↔ descriptor full-name ------------------------
step 6 "PayloadType registry ↔ descriptor message full-name (gate 8)"
if [ -f "$PB_JAR" ]; then
  mkdir -p verify/out
  javac -cp "$PB_JAR" -d verify/out verify/PayloadTypeCheck.java
  java -cp "$PB_JAR:verify/out" PayloadTypeCheck provenance/vehicle-proto-baseline.yaml \
    descriptors/vehicle-common-v1.pb descriptors/vehicle-fota-v1.pb
else
  echo "  (protobuf-java not in ~/.m2 — run 'mvn install' first)"
fi

# ---- 7. Java golden producer (reference bytes) ---------------------------
step 7 "Java golden producer (reference bytes for vehicle-side C++ validation)"
# This repo generates Java only. The canonical source/DescriptorSet and these
# Java-produced reference bytes are the cross-language golden contract: the
# vehicle-side project generates C++ from the released DescriptorSet and must
# round-trip byte-identically against these reference bytes (design §5 gate 6/7).
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

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "✅ ALL VERIFY GATES PASSED"
  exit 0
else
  echo "❌ ${FAILURES} gate(s) FAILED"
  exit 1
fi
