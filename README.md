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
│   ├── vagw-delivery-v1.pb                 # Normalized FileDescriptorSet (vagw cloud-internal)
│   └── security-keyprov-v1.pb              # Normalized FileDescriptorSet (keyprov security)
│
├── iov-cloud-proto-vmd/                    # artifactId=proto-vmd, package iov.vmd.swinv.v1 (deprecated)
│   └── src/main/proto/iov/vmd/swinv/v1/software_inventory.proto
├── iov-cloud-proto-vehicle-common/         # artifactId=proto-vehicle-common, package vehicle.common.v1
│   └── src/main/proto/vehicle/common/v1/envelope.proto
├── iov-cloud-proto-fota/                   # artifactId=proto-fota, package vehicle.fota.v1
│   └── src/main/proto/vehicle/fota/v1/*.proto
├── iov-cloud-proto-vagw/                   # artifactId=proto-vagw, package vagw.v1 (cloud-internal)
│   └── src/main/proto/vagw/v1/delivery.proto
└── iov-cloud-proto-keyprov/                # artifactId=proto-keyprov, package security.keyprov.v1
    └── src/main/proto/security/keyprov/v1/key_provisioning.proto
```

## Modules

| Module | ArtifactId | Package | Description |
|--------|-----------|---------|-------------|
| iov-cloud-proto-vmd | `proto-vmd` | `iov.vmd.swinv.v1` | VMD domain - Software Inventory Report (deprecated, CR-005; 替代: FOTA inventory + OTA→VMD cloud event) |
| iov-cloud-proto-vehicle-common | `proto-vehicle-common` | `vehicle.common.v1` | Vehicle Cloud Boundary Envelope (`VehicleMessageEnvelope`, fields 1–16, payload=10) |
| iov-cloud-proto-fota | `proto-fota` | `vehicle.fota.v1` | FOTA contracts (TaskCheck / Consent / DownloadGrant / StageResult / InstallPermit / ExecutionEvent / Control / FinalResult / Log / Reconcile / Policy) + CR-005 EcuSoftwareModel / SoftwareUnitVersion / canonicalization-v2 |
| iov-cloud-proto-vagw | `proto-vagw` | `vagw.v1` | VAGW cloud-internal technical delivery status (`GatewayDeliveryStatus`, topic `iov.vagw.delivery.fota`) — not a vehicle-boundary contract |
| iov-cloud-proto-keyprov | `proto-keyprov` | `security.keyprov.v1` | V2C initial business key provisioning (`KeyProvisioningRequest`/`Response`/`Ack`/`AckResult`/`Status`) + CR-007 ECDH-ES v1 envelope (`KeyEnvelopeFormat` / `EcdhEsP256EnvelopeParametersV1` / envelopeDigest / KCV); depends on `proto-vehicle-common`; service `security.keyprov`, topics `vehicle/{ecu_uid}/up|down/keyprov` |

## Conventions

- **groupId**: `net.hwyz.iov.cloud.proto` (unified)
- **Parent POM**: `iov-cloud-parent-proto` (packaging=pom, aggregation only)
- **Submodule = Delivery Artifact**: `proto-<domain>` with module directory `iov-cloud-proto-<domain>`
- **Cloud-internal package**: `iov.<domain>.<service>.v<major>` (e.g., vmd)
- **Vehicle-cloud-boundary package**: `vehicle.common.v1` / `vehicle.fota.v1` — must NOT be rewritten to `iov.*`
- **Directory = Package**: e.g., `iov-cloud-proto-fota/src/main/proto/vehicle/fota/v1/`
- **Cloud-internal package**: `vagw.v1` — `proto-vagw` publishes `vagw.v1.Delivery.GatewayDeliveryStatus` only for `iov.vagw.delivery.fota` (Key=VIN); it MUST NOT wrap/import/duplicate `VehicleMessageEnvelope` or any `vehicle.fota.v1` message and MUST NOT be registered as a vehicle-boundary PayloadType
- **Dependency**: `proto-fota` → `proto-vehicle-common`; `proto-keyprov` → `proto-vehicle-common`; VAGW → common + `proto-vagw`; IOV-OTA → common + fota. VAGW 对 FOTA 只解析 common Envelope metadata 并原样转发 payload bytes，不得引入 proto-fota 或解析 EcuVersion/SoftwareUnitVersion。OTA→VMD 云内事件不使用 Proto，不归 PAR-PROTO 管理（由 iov-ota-api 与 VMD 共同治理）。

## Bootstrap & Authority Model

1. `vehicle.common.v1` / `vehicle.fota.v1` were imported **byte-for-byte** from the frozen VEH-PROTO snapshot (donor provenance + per-file SHA-256 in `provenance/vehicle-proto-baseline.yaml`).
2. After the bootstrap release passes Java generation and the joint cross-language check (Java-produced golden reference bytes + vehicle-side C++ byte-identical round-trip), authority cuts over to PAR-PROTO (see `contract_authority: par-proto` in the manifest).
3. Post-cutover: canonical PRs originate **only** in PAR-PROTO; VEH-PROTO pins released versions and must not reverse-merge local drift.

## CR-005: ECU 软件模型 / canonicalization-v2 / swinv 退役

- `vehicle.fota.v1` 以纯字段追加扩展（PAR-PROTO-DSN-CR-005）：`EcuSoftwareModel`（每 ECU 软件治理模型，非 InventoryMode）、`SoftwareUnitVersion`（结构化 Target/Slot 单元）、`EcuVersion` 追加 6~9（SINGLE_IMAGE 只用 legacy 字段 3/5/6/7；MULTI_TARGET 只用 software_units[]）、`PackageSummary` 追加 12~13、`TaskCheckRequest` 追加 12（`inventory_canonicalization_version`）、`TaskCheckResponse` 追加 21~22、`ExecutionEvent` 追加 21~22、`EcuResult` 追加 11~12、`ErrorSummary` 追加 4~5。既有字段号/类型/presence 全部不变，`protocol_version=fota-v1` 不变。
- canonicalization-v2 使用自定义确定性 TLV（`verify/inventory-canonical-v2/` 规范性 test-vector bundle）；摘要只覆盖 ECU 硬件与规范化 software units，不包含 VIN/revision/时间；v1/v2 摘要空间独立。
- OTA→VMD 观测事件不使用 Proto、不属于 PAR-PROTO（由 iov-ota-api 与 VMD 共同治理），不新增 proto-ota module / Cloud Event Registry / Maven artifact。
- `iov.vmd.swinv.v1.SoftwareInventoryReport` 已标记 deprecated（保留兼容审计，不删除/不改号），已被 FOTA inventory + OTA→VMD cloud event 取代。

## CR-006: proto-keyprov / security.keyprov.v1

- 新增独立模块 `iov-cloud-proto-keyprov`（`artifactId=proto-keyprov`，package `security.keyprov.v1`），依赖 `proto-vehicle-common`，以 `key_provisioning.proto` 冻结 V2C 初始业务密钥开通 canonical wire（Request/Response/Ack/AckResult/StatusRequest/StatusResponse，含 5 个枚举与 12 个 message）。
- Envelope 映射：`service=security.keyprov`，`payload_type=security.keyprov.v1.<MessageName>`（完整名，精确匹配），`protocol_version=keyprov-v1`（不透明字符串，整串 allowlist）；Topic 为 `vehicle/{ecu_uid}/up/keyprov` 与 `vehicle/{ecu_uid}/down/keyprov`（仅传输路由）。
- 单一 SSOT：TSP/TBOX-MQTT/VAGW/VMD/VEH-PROTO 只锁版消费 source bundle / DescriptorSet / 生成制品；禁止复制 Proto、私有量产 JSON codec、字段别名或反射兜底。
- 安全边界：`wrapped_key`/`parameters`（SecretCiphertext）可受控传输但禁止日志与普通持久化；`import_proof`（SecurityProof）仅短期处理；业务密钥明文、设备私钥、HSM slot、KMS keyRef 永不进入 wire。
- 门禁：`buf lint/breaking`、`descriptors/security-keyprov-v1.pb` 确定性、`verify/KeyprovContractCheck.java`（字段号/枚举/generated 类/unknown-field-enum/§4.3 大小门禁/§4.4 完整性/§5 敏感性扫描）、`verify/KeyprovGoldenProducer.java`（六类 payload + Envelope golden bytes）。
- 枚举值采用完整前缀（如 `KEY_PURPOSE_UPLINK_AEAD`、`KEY_PROVISIONING_STATUS_ACTIVE`），保持 `buf lint STANDARD` 合规。本 CR 不实现 MQTT Route/ACL、VAGW→VMD 路由、VMD/KMS 编排或 TBOX-SEC 解封装。

## CR-009: keyprov V2C wire canonical 收口（PAR-PROTO-DSN-CR-009，纯注释修订）

- 裁决：PAR-PROTO 重新收口 V2C Keyprov wire canonical。`WrappedKeyItem.envelope_digest` 与 `KeyImportItemResult.envelope_digest` 只承载 9 字段 `wireEnvelopeDigest`（`WIRE_PROFILE = PAR_PROTO_KEYPROV_ECDH_ES_P256_V1`）；FW-SEC 18 字段摘要更名为内部 `coreEnvelopeDigest`，不得写入 wire、ACK 或 Import Attestation。AAD 由版本化 `AAD_PROFILE = PAR_PROTO_KEYPROV_AAD_V1` 冻结（10 段），并必须在 AES-GCM 加密前生成使用。
- 跨端只发布一套权威 wire 向量：`verify/keyprov-ecdh-es-p256-v1/`（10 正式文件 + `negative/`，manifest 记录 source/DescriptorSet/向量/工具链 SHA-256）。VMD Java、TBOX-SEC C++ 与 VEH-PROTO 生成物直接消费同一 bundle/hash；FW-SEC core 向量仅标为内部向量。
- 字段号、消息结构、deterministic parameters、format 协商、大小门禁与 ACK 字段保持 CR-007 不变（comment-only，DescriptorSet hash 不变）；CR-006/007/008 golden 字节保持不变即为 wire 附加兼容证据。
- 发布门禁（任一不一致则 V2C ECDH-ES 保持 DOWN）：PAR-PROTO CR-009 release → VEH-PROTO lock/source + DescriptorSet + vector hash → FW-SEC AAD profile capability → VMD mapper/wire digest → TBOX-SEC vector regression → relay byte-for-byte → E2E → enable capability。REQ-009-5 原位纠正 v1 需生产审计证明不存在任何旧口径 ACTIVE/成功 ACK/SEC COMMITTED/成功 proof/已交付成功消费者，否则必须新开 v2。
- 验证：`verify/KeyprovCr009VectorProducer.java`（权威向量包 + fail-fast 自检）、`verify/KeyprovCr009VectorCheck.java`（bundle 完整性 + 边界向量 + 负面向量 + CR-007/008 golden 回归）。

## CR-010: KEYPROV-LIFECYCLE-1（KL1）生命周期规范 profile（PAR-PROTO-DSN-CR-010，协议先行）

- 裁决：新增 KEYPROV-LIFECYCLE-1 规范 profile，**不新增字段号、不改 package/service/keyprov-v1、不变密码学 profile**（descriptor 零变化）；只修正跨应用重放策略。KL1 支持由语义/profile manifest hash 证明，**不能以 descriptor 不变宣称已支持 KL1**。配套需求 PAR-PROTO-REQ-CR-010（KL-REQ-001～007），完整设计见 SPEC 设计 §8.6 与 CR-010 正文。
- 生命周期 conformance 向量：固定 case-set `keyprov-lifecycle-kl1-v1`，**24 场景组 / 57 固定子例**，T0=1800000000000ms（绝不使用执行机器时间）。向量包 `verify/keyprov-lifecycle-kl1-v1/`（JSON、oracle.py、README、reference-report、SHA256SUMS）字节级冻结，`lifecycle-vectors.json` SHA256=5226b92733a93634d9bdd11ec7090b1ba655979e3beca0399784e9db7de855e3。input/expected 均为固定语义，input_hash/expected_hash = SHA256(规范 JSON 排序去空白)。先前 48 子例预检包不作为 release 输入。
- 纯函数纪律：TTL 签发、状态/错误矩阵、时间比较全部抽成纯函数（`verify/KeyprovLifecycleDecide.java`，可注入 UTC/monotonic clock，无 sleep/真实时钟）；14 种 operation（issue/accept/ack/dedupe/budget/reconcile/stabilize/expired/transport/new_attempt/time/chain/sec_contract/store）对应 KL-REQ-001～007 的固定算法与默认值，Java 参考模型与 Python oracle.py 同语义自洽 57/57。
- 双端 CI 语义对账：云端 PAR/VMD 保存规范 JSON 和 hash；VEH-PROTO 同步 case 内容与 hash（不发布代码/artifact）；TSP/SEC 在本仓固定同输入与期望并本地 manifest 比对。本仓 CI 输出 `{case_id, input_hash, expected_hash, actual_action, counters, pass}`（`verify/out/keyprov-lifecycle-ci-report.json`），release gate 对 case ID 集合、profile 参数、输入/期望 hash 与实际结果逐项比较；禁止测试现场跨仓浮动下载、禁止手工改 expected 掩盖差异。
- 边界：本包参考 oracle（Python + Java）只验证规范内部自洽，**不代替生产实现 conformance**；实际 adapter 必须把同一输入映射到各端真实决策函数/调度/存储并输出实际副作用计数，不得调用参考 oracle 生成 actual。VMD/TSP/SEC 生产 adapter、mock/真实组件 E2E、真车验收与 DoD 签字（SPEC §8.6.7）待联合评审后由各仓执行。
- 验证：`verify/KeyprovLifecycleVectorCheck.java`（SHA256SUMS + JSON hash 5226b927… + 57 唯一子例 + LC01～LC24 覆盖 + 逐例重算 input/expected hash + Java 参考模型 57/57 + CI 报告，篡改即 fail-closed）；`run_verify.sh` 步骤 21/22；`provenance/vehicle-proto-baseline.yaml` cr010_extension 区段。

## CR-007: keyprov ECDH-ES v1 信封（兼容增量）

- 以 **纯追加** 方式扩展 `security.keyprov.v1`（PAR-PROTO-DSN-CR-007，字段号 1～9、消息名、package 与 `protocol_version=keyprov-v1` 全部不变）：新增枚举 `KeyEnvelopeFormat`、消息 `EcdhEsP256EnvelopeParametersV1`，并为 `KeyProvisioningRequest` 追加 `supported_envelope_formats=11`、`WrappedKeyItem` 追加 `envelope_digest=10`/`key_check_value=11`/`envelope_format=12`、`KeyImportItemResult` 追加 `envelope_digest=7`/`key_check_value=8`/`envelope_format=9`。
- `parameters` 的 wire type 仍为有界 `bytes`，但内容正式冻结为 `EcdhEsP256EnvelopeParametersV1` 的 **deterministic protobuf 序列化**；算法套件（`WrappingSuite`）与 envelope 参数格式（`KeyEnvelopeFormat`）分离协商，禁止仅凭 suite 猜测 bytes。
- Canonical 契约（`verify/KeyprovCanonicalV1.java` 为唯一 Java 参考实现）：
  - `wireEnvelopeDigest = SHA-256(wireDigestInput)`（WIRE_PROFILE = `PAR_PROTO_KEYPROV_ECDH_ES_P256_V1`，PAR-PROTO-DSN-CR-009 §2.1）：9 个顶层 segment `envelopeFormat / requestId / businessDomain / purpose / keyId / businessKeyVersion(uint64be 8B) / wrappingSuite / wrappedKey / parameters`，段长为 unsigned 32-bit big-endian，字符串无 BOM UTF-8、枚举最短无符号 varint、禁止 name()/ordinal()/十进制/JSON/Base64/hex 文本或 parse 后重编码 parameters。`WrappedKeyItem.envelope_digest`/`KeyImportItemResult.envelope_digest` 只承载它；FW-SEC 18 字段摘要为内部 `coreEnvelopeDigest`，不得进入 wire/ACK/proofInput；
  - `canonicalAad`（AAD_PROFILE = `PAR_PROTO_KEYPROV_AAD_V1`，CR-009 §2.2）：10 段固定顺序 `envelopeFormat / wrappingSuite / purpose / businessKeyVersion / rootKeyVersion / recipientCertificateDigest(原始32B) / requestId / businessDomain / keyId / derivationVersion`，`aad_digest = SHA-256(canonicalAad)`；云端 AES-GCM 实际 AAD 必须与 `canonical_aad` 逐字节相同，禁止加密后由 Adapter 替换；TBOX-SEC 从 outer context 重建并常量时间比较；
  - `keyCheckValue = first_3_bytes(SHA-256(businessKey))`；
  - `proofInput = lengthPrefixed("openiov|keyprov-ack|v1", requestId, businessDomain, purpose, SHA-256(UTF8(keyId)), uint64be(businessKeyVersion), envelopeDigest, keyCheckValue)`，具体 HMAC/CMAC/签名算法由 TBOX-SEC CR 与 FW-SEC test vector 冻结。
- 门禁与降级：Request 未声明 `supported_envelope_formats` 或其仅含 `UNSPECIFIED`/未知值时，云端不得下发 envelope v1；Response 双用途 item 的 suite/format 组合、参数长度、P-256 点、AAD/envelope digest 全部校验通过后才可交给 TBOX-SEC；ACK 必须精确绑定本次 Response 的 format/digest/KCV。wire 兼容不等于 capability，须叠加 DescriptorSet hash、PAR-PROTO release 与 FW-SEC Provider readiness。
- 验证：`verify/KeyprovContractCheck.java`（6 枚举 / 13 消息 / 字段号 / §6.1 协商 / §6.2 响应门禁 / §6.3 ACK 绑定 / §7 精确长度与 P-256 点 / fail-closed）、`verify/KeyprovCr007GoldenProducer.java`（deterministic parameters、envelopeDigest/AAD/KCV/proofInput、envelope v1 payload + Envelope golden bytes）、`verify/KeyprovCr007IntegrationCheck.java`（VAGW/MQTT 逐字节 relay、去掉 CR-007 字段后与 CR-006 字节完全一致的附加式降级、capability 协商、重放幂等）。CR-006 的 golden 字节保持不变即为 wire 附加兼容的证据。本 CR 不实现 FW-SEC 密码学、PKI Profile、VMD 编排或 TBOX-SEC 解封。

## Build

```bash
# Compile all modules
mvn clean compile

# Compile specific module
mvn clean compile -pl iov-cloud-proto-vehicle-common -am
mvn clean compile -pl iov-cloud-proto-fota -am
mvn clean compile -pl iov-cloud-proto-vagw -am
mvn clean compile -pl iov-cloud-proto-keyprov -am
```

## Governance

- **buf lint** (STANDARD) + **buf breaking** (WIRE_JSON, against previous release tag) are hard CI gates
- **Release artifacts** per release: Maven jar/sources, canonical `.proto` source archive, normalized FileDescriptorSet, SHA-256 checksums, compatibility report, changelog
- **Generation scope**: this repo generates **Java** only (Maven + `buf generate`). C++ generation is the vehicle-side responsibility.
- **Cross-language gate (joint)**: this repo ships the canonical source / DescriptorSet plus **Java-produced golden reference bytes** (`verify/golden/expected/`, hashes in `provenance/vehicle-proto-baseline.yaml`). VEH-PROTO / vehicle builds generate C++ from the released source/DescriptorSet and must round-trip **byte-identically** against those reference bytes; they must not parse the Java jar.
- CODEOWNERS enforces domain-based review ownership:
  - `iov-cloud-proto-vehicle-common/`: `@vehicle-cloud-platform @vehicle-platform` (breaking/major changes need both approvals)
  - `iov-cloud-proto-fota/`: `@iov-ota @cgw-fota @vehicle-platform` (semantic changes need IOV-OTA + CGW-FOTA approval)
  - `iov-cloud-proto-keyprov/`: `@vehicle-security @vmd-team @vagw-team @tbox-tsp @tbox-sec` (Envelope mapping additionally needs security payload owner + vehicle-common owner)
  - `provenance/`: `@vehicle-cloud-platform`
