## [0.3.0] - 2026-06-20

### Added

- Rekor v2 (tiled transparency log) verification and signing, using the
  `hashedrekord` 0.0.2 entry type.
- DSSE / in-toto attestation signing (`Signer#sign_dsse`).
- Managed-key (bring-your-own-key) verification via `Verifier#verify(key:)`,
  for bundles that carry a public-key hint instead of a Fulcio certificate.
- Timestamping Authority (TSA / RFC 3161) timestamp signing, and defaulting the
  signing configuration from TUF.

### Changed

- Updated to sigstore protobuf-specs v0.5.1 / protobug 0.2.0, and added the
  `protobug_in_toto_attestation_protos` dependency. The `protobug_sigstore_protos`
  constraint is now `~> 0.2.0`.
- Updated conformance suites to sigstore-conformance v0.0.29 and
  tuf-conformance v2.4.0.

### Security

- Enforce that an RFC 3161 timestamp's message imprint covers the bundle
  signature, and that the timestamp's `gen_time` falls within the Timestamping
  Authority's validity window. Verification now fails closed when no trusted
  signing time (TSA response or log integrated time) is available.
- A managed-key DSSE bundle carried as a Rekor v1 entry now fails with a clear
  error instead of raising `NoMethodError`.

## [0.2.3] - 2026-03-10

### Security

- Fix in-toto statement verification (GHSA-mhg6-2q2v-9h2c).

### Changed

- Accept extensions for SCTs.
- Set a library-specific `User-Agent` header on outbound HTTP requests.

## [0.2.2] - 2025-10-24

### Changed

- Require Ruby >= 3.2.
- Re-implement missing JRuby functionality atop `java.security`.
- Ensure `kind_version` is set on transparency log entries after signing.
- Skip unrecognized keys when parsing.
- Enable smoke tests for fork PRs using the public OIDC beacon.

## [0.2.1] - 2024-11-19

- Fix the release automation (gem push paths; split the RubyGems release to a
  matrix).

## [0.2.0] - 2024-11-18

### Changed

- Extract the CLI into a separate gem that can be published independently.
- Improve compatibility with the sigstore-js mock server.
- Improve error handling.

## [0.1.1] - 2024-10-18

- Fix release automation

## [0.1.0] - 2024-10-18

- Initial release
