# iov-cloud-parent-proto

OpenIOV Cloud Protobuf Contract Repository - Unified IDL SSOT for cloud-side proto contracts.

## Overview

This repository serves as the single source of truth (SSOT) for all cloud-side Protobuf contracts. It follows a Maven multi-module structure with domain-based federation, ensuring:

- **Contract SSOT**: Eliminates cross-repo proto copy-paste drift
- **Federated Ownership**: Domain teams own their payload via CODEOWNERS
- **Per-Domain Artifacts**: Services depend on domain-specific artifacts (e.g., `iov-cloud-proto-vmd`), avoiding forced cross-domain upgrades
- **Compatibility Governance**: CI enforces backward compatibility via `buf breaking`

## Repository Structure

```text
iov-cloud-parent-proto/                     # packaging=pom, aggregator + parent POM
├── pom.xml                                 # <modules> aggregation; unified groupId/version/protobuf plugins
├── buf.yaml                                # buf v2: modules listing + lint/breaking config
├── buf.gen.yaml                            # Unified code generation config
├── CODEOWNERS                              # Domain-based ownership
│
└── iov-cloud-proto-vmd/                    # Submodule = independent artifact
    ├── pom.xml                             # artifactId=iov-cloud-proto-vmd, parent=iov-cloud-parent-proto
    └── src/main/proto/                     # protobuf-maven-plugin source directory
        └── iov/vmd/swinv/v1/
            └── software_inventory.proto    # SoftwareInventoryReport
```

## Modules

| Module | ArtifactId | Package | Description |
|--------|-----------|---------|-------------|
| iov-cloud-proto-vmd | `iov-cloud-proto-vmd` | `iov.vmd.swinv.v1` | VMD domain - Software Inventory Report |

## Conventions

- **groupId**: `net.hwyz.iov.cloud.proto` (unified)
- **Parent POM**: `iov-cloud-parent-proto` (packaging=pom, aggregation only)
- **Submodule = Delivery Artifact**: `iov-cloud-proto-<domain>`
- **Proto Package**: `iov.<domain>.<service>.v<major>`
- **Directory = Package**: e.g., `iov-cloud-proto-vmd/src/main/proto/iov/vmd/swinv/v1/`

## Build

```bash
# Compile all modules
mvn clean compile

# Compile specific module
mvn clean compile -pl iov-cloud-proto-vmd
```

## Governance

- CI triggers `buf lint` + `buf breaking` (against previous release tag) as hard gates
- Version policy: Maven reactor unified version; services depend on specific artifacts
- CODEOWNERS enforces domain-based review ownership
