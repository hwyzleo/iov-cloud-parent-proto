# iov-cloud-parent-proto

OpenIOV Cloud Protobuf Contract Repository - Unified IDL SSOT for cloud-side and vehicle-cloud-boundary proto contracts.

## Overview

This repository is the single source of truth (SSOT) for cloud-side Protobuf contracts and the vehicle-cloud boundary IDL. It follows a Maven multi-module structure with domain-based federation, ensuring:

- **Contract SSOT**: Eliminates cross-repo proto copy-paste drift
- **Federated Ownership**: Domain teams own their payload via CODEOWNERS
- **Per-Domain Artifacts**: Services depend on domain-specific artifacts (e.g., `proto-vmd`, `proto-vehicle-common`, `proto-fota`, `proto-vagw`), avoiding forced cross-domain upgrades
- **Compatibility Governance**: CI enforces backward compatibility via `buf lint` + `buf breaking`
- **Bootstrap & Authority Cutover**: `vehicle.common.v1` / `vehicle.fota.v1` were imported once from the frozen VEH-PROTO snapshot (see `provenance/vehicle-proto-baseline.yaml`). After cutover, PAR-PROTO is the canonical IDL authority; VEH-PROTO consumes released source / DescriptorSet and only pins compatible versions (**one-way: PAR-PROTO → VEH-PROTO**)

## Repository Structure

```text
iov-cloud-parent-proto/                     # packaging=pom, aggregator + parent POM
├── pom.xml                                 # <modules> aggregation; unified groupId/version/protobuf plugins
├── buf.yaml                                # buf v2: modules listing + lint/breaking config
├── buf.lock                                # buf v2 dependency lockfile
├── buf.gen.yaml                            # Unified code generation config
├── CODEOWNERS                              # Domain-based ownership
├── provenance/
│   └── vehicle-proto-baseline.yaml         # Donor freeze manifest + authority cutover record
├── descriptors/
│   ├── vehicle-common-v1.pb                # Normalized FileDescriptorSet (common)
│   ├── vehicle-fota-v1.pb                  # Normalized FileDescriptorSet (fota)
│   └── vagw-delivery-v1.pb                 # Normalized FileDescriptorSet (vagw cloud-internal)
│
├── iov-cloud-proto-vmd/                    # artifactId=proto-vmd, package iov.vmd.swinv.v1 (deprecated)
│   └── src/main/proto/iov/vmd/swinv/v1/software_inventory.proto
├── iov-cloud-proto-vehicle-common/         # artifactId=proto-vehicle-common, package vehicle.common.v1
│   └── src/main/proto/vehicle/common/v1/envelope.proto
├── iov-cloud-proto-fota/                   # artifactId=proto-fota, package vehicle.fota.v1
│   └── src/main/proto/vehicle/fota/v1/*.proto
└── iov-cloud-proto-vagw/                   # artifactId=proto-vagw, package vagw.v1 (cloud-internal)
    └── src/main/proto/vagw/v1/delivery.proto
```

## Modules

| Module | ArtifactId | Package | Description |
|--------|-----------|---------|-------------|
| iov-cloud-proto-vmd | `proto-vmd` | `iov.vmd.swinv.v1` | VMD domain - Software Inventory Report (deprecated, CR-005; 替代: FOTA inventory + OTA→VMD cloud event) |
| iov-cloud-proto-vehicle-common | `proto-vehicle-common` | `vehicle.common.v1` | Vehicle Cloud Boundary Envelope (`VehicleMessageEnvelope`, fields 1–16, payload=10) |
| iov-cloud-proto-fota | `proto-fota` | `vehicle.fota.v1` | FOTA contracts (TaskCheck / Consent / DownloadGrant / StageResult / InstallPermit / ExecutionEvent / Control / FinalResult / Log / Reconcile / Policy) + CR-005 EcuSoftwareModel / SoftwareUnitVersion / canonicalization-v2 |
| iov-cloud-proto-vagw | `proto-vagw` | `vagw.v1` | VAGW cloud-internal technical delivery status (`GatewayDeliveryStatus`, topic `iov.vagw.delivery.fota`) — not a vehicle-boundary contract |

## Conventions

- **groupId**: `net.hwyz.iov.cloud.proto` (unified)
- **Parent POM**: `iov-cloud-parent-proto` (packaging=pom, aggregation only)
- **Submodule = Delivery Artifact**: `proto-<domain>` with module directory `iov-cloud-proto-<domain>`
- **Cloud-internal package**: `iov.<domain>.<service>.v<major>` (e.g., vmd)
- **Vehicle-cloud-boundary package**: `vehicle.common.v1` / `vehicle.fota.v1` — must NOT be rewritten to `iov.*`
- **Directory = Package**: e.g., `iov-cloud-proto-fota/src/main/proto/vehicle/fota/v1/`
- **Cloud-internal package**: `vagw.v1` — `proto-vagw` publishes `vagw.v1.Delivery.GatewayDeliveryStatus` only for `iov.vagw.delivery.fota` (Key=VIN); it MUST NOT wrap/import/duplicate `VehicleMessageEnvelope` or any `vehicle.fota.v1` message and MUST NOT be registered as a vehicle-boundary PayloadType
- **Dependency**: `proto-fota` → `proto-vehicle-common`; VAGW → common + `proto-vagw`; IOV-OTA → common + fota. VAGW 对 FOTA 只解析 common Envelope metadata 并原样转发 payload bytes，不得引入 proto-fota 或解析 EcuVersion/SoftwareUnitVersion。OTA→VMD 云内事件不使用 Proto，不归 PAR-PROTO 管理（由 iov-ota-api 与 VMD 共同治理）。

## Bootstrap & Authority Model

1. `vehicle.common.v1` / `vehicle.fota.v1` were imported **byte-for-byte** from the frozen VEH-PROTO snapshot (donor provenance + per-file SHA-256 in `provenance/vehicle-proto-baseline.yaml`).
2. After the bootstrap release passes Java generation and the joint cross-language check (Java-produced golden reference bytes + vehicle-side C++ byte-identical round-trip), authority cuts over to PAR-PROTO (see `contract_authority: par-proto` in the manifest).
3. Post-cutover: canonical PRs originate **only** in PAR-PROTO; VEH-PROTO pins released versions and must not reverse-merge local drift.

## CR-005: ECU 软件模型 / canonicalization-v2 / swinv 退役

- `vehicle.fota.v1` 以纯字段追加扩展（PAR-PROTO-DSN-CR-005）：`EcuSoftwareModel`（每 ECU 软件治理模型，非 InventoryMode）、`SoftwareUnitVersion`（结构化 Target/Slot 单元）、`EcuVersion` 追加 6~9（SINGLE_IMAGE 只用 legacy 字段 3/5/6/7；MULTI_TARGET 只用 software_units[]）、`PackageSummary` 追加 12~13、`TaskCheckRequest` 追加 12（`inventory_canonicalization_version`）、`TaskCheckResponse` 追加 21~22、`ExecutionEvent` 追加 21~22、`EcuResult` 追加 11~12、`ErrorSummary` 追加 4~5。既有字段号/类型/presence 全部不变，`protocol_version=fota-v1` 不变。
- canonicalization-v2 使用自定义确定性 TLV（`verify/inventory-canonical-v2/` 规范性 test-vector bundle）；摘要只覆盖 ECU 硬件与规范化 software units，不包含 VIN/revision/时间；v1/v2 摘要空间独立。
- OTA→VMD 观测事件不使用 Proto、不属于 PAR-PROTO（由 iov-ota-api 与 VMD 共同治理），不新增 proto-ota module / Cloud Event Registry / Maven artifact。
- `iov.vmd.swinv.v1.SoftwareInventoryReport` 已标记 deprecated（保留兼容审计，不删除/不改号），已被 FOTA inventory + OTA→VMD cloud event 取代。

## Build

```bash
# Compile all modules
mvn clean compile

# Compile specific module
mvn clean compile -pl iov-cloud-proto-vehicle-common -am
mvn clean compile -pl iov-cloud-proto-fota -am
mvn clean compile -pl iov-cloud-proto-vagw -am
```

## Governance

- **buf lint** (STANDARD) + **buf breaking** (WIRE_JSON, against previous release tag) are hard CI gates
- **Release artifacts** per release: Maven jar/sources, canonical `.proto` source archive, normalized FileDescriptorSet, SHA-256 checksums, compatibility report, changelog
- **Generation scope**: this repo generates **Java** only (Maven + `buf generate`). C++ generation is the vehicle-side responsibility.
- **Cross-language gate (joint)**: this repo ships the canonical source / DescriptorSet plus **Java-produced golden reference bytes** (`verify/golden/expected/`, hashes in `provenance/vehicle-proto-baseline.yaml`). VEH-PROTO / vehicle builds generate C++ from the released source/DescriptorSet and must round-trip **byte-identically** against those reference bytes; they must not parse the Java jar.
- CODEOWNERS enforces domain-based review ownership:
  - `iov-cloud-proto-vehicle-common/`: `@vehicle-cloud-platform @vehicle-platform` (breaking/major changes need both approvals)
  - `iov-cloud-proto-fota/`: `@iov-ota @cgw-fota @vehicle-platform` (semantic changes need IOV-OTA + CGW-FOTA approval)
  - `provenance/`: `@vehicle-cloud-platform`
