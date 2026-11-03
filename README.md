# Sigstore

A pure Ruby implementation of [sigstore](https://www.sigstore.dev/) signing and verification.
Used as a library in Ruby projects or through the `gem` subcommand for CLI verification.
Includes a TUF client for trust root distribution.

## Installation

```ruby
# Gemfile
gem "sigstore"
```

Or install directly:

```shell
gem install sigstore
```

Requires Ruby >= 3.2.0.

## CLI Usage

Verify a bundle from the command line:

```shell
gem sigstore_cosign_verify_bundle --bundle artifact.sigstore \
    --certificate-identity https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    artifact.tar.gz
```

## Library Usage

### Verify with the public Sigstore instance

```ruby
require "sigstore"

# Create a verifier using the public Sigstore trust root
verifier = Sigstore::Verifier.production

# Load the bundle (produced by cosign sign-blob --bundle)
input = Sigstore::VerificationInput.new(
  Sigstore::Verification::V1::Input.decode_json(
    File.read("artifact.sigstore.json"),
    registry: Sigstore::REGISTRY
  )
)

# Define the expected certificate identity
policy = Sigstore::Policy::Identity.new(
  identity: "https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main",
  issuer: "https://token.actions.githubusercontent.com"
)

# Verify
result = verifier.verify(input: input, policy: policy, offline: false)
if result.verified?
  puts "Verification succeeded"
else
  puts "Verification failed: #{result.reason}"
end
```

### Verify with a custom trust root

For self-hosted Sigstore infrastructure, load a trust root from a local file
instead of the public TUF repository:

```ruby
# Load trust root from a local trusted_root.json file
trust_root = Sigstore::TrustedRoot.from_file("/path/to/trusted_root.json")

# Create a verifier for your self-hosted stack
verifier = Sigstore::Verifier.for_trust_root(trust_root: trust_root)

# Verification works the same way
result = verifier.verify(input: input, policy: policy, offline: true)
```

The `trusted_root.json` file contains your Fulcio CA certificate, Rekor
public key, and CT log public key. Generate it with
`cosign trusted-root create` or assemble it from the
[protobuf specification](https://github.com/sigstore/protobuf-specs).

### Offline verification

Pass `offline: true` to skip Rekor lookups during verification. The bundle
must contain an inclusion proof or inclusion promise:

```ruby
result = verifier.verify(input: input, policy: policy, offline: true)
```

### Policy

The `Policy::Identity` class verifies that the signing certificate was issued
for a specific OIDC identity and issuer:

```ruby
# Verify a specific CI workflow identity
policy = Sigstore::Policy::Identity.new(
  identity: "https://gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
  issuer: "https://gitlab.example.com"
)
```

The identity is matched against the certificate's Subject Alternative Name,
and the issuer is matched against the OIDC issuer extension
(OID `1.3.6.1.4.1.57264.1.1` or `1.3.6.1.4.1.57264.1.8`).

## Factory Methods

| Method | Trust Root | Use Case |
|--------|-----------|----------|
| `Verifier.production` | Public Sigstore TUF root | Verify signatures from sigstore.dev |
| `Verifier.staging` | Staging Sigstore TUF root | Test against staging infrastructure |
| `Verifier.for_trust_root(trust_root:)` | Any `TrustedRoot` | Self-hosted or custom Sigstore |

| Method | Source | Use Case |
|--------|--------|----------|
| `TrustedRoot.production` | Public TUF repository | Standard verification |
| `TrustedRoot.production(offline: true)` | Cached TUF data | No network access |
| `TrustedRoot.from_file(path)` | Local JSON file | Self-hosted Sigstore |

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test-unit` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at <https://github.com/sigstore/sigstore-ruby>.

## License

The gem is available as open source under the terms of the [Apache 2](https://opensource.org/licenses/Apache-2.0).
