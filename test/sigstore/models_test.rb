# frozen_string_literal: true

require "test_helper"
require "sigstore/models"
require "sigstore/trusted_root"

class Sigstore::BundleTypeTest < Test::Unit::TestCase
  def test_from_media_type
    assert_equal(Sigstore::BundleType::BUNDLE_0_1,
                 Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.1"))
    assert_equal(Sigstore::BundleType::BUNDLE_0_2,
                 Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.2"))
    assert_equal(Sigstore::BundleType::BUNDLE_0_3,
                 Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.3"))

    assert_raise(Sigstore::Error::InvalidBundle) do
      Sigstore::BundleType.from_media_type("application/vnd.dev.sigstore.bundle+json;version=0.0")
    end
  end

  def test_verification_input_no_bundle
    verification_input = Sigstore::Verification::V1::Input.new
    e = assert_raise(ArgumentError) { Sigstore::VerificationInput.new(verification_input) }
    assert_equal("bundle must be a Sigstore::Bundle::V1::Bundle, is NilClass", e.message)
  end

  def test_verification_input_bundle_missing_media_type
    verification_input = Sigstore::Verification::V1::Input.new
    verification_input.bundle = Sigstore::Bundle::V1::Bundle.new
    e = assert_raise(Sigstore::Error::InvalidBundle) { Sigstore::VerificationInput.new(verification_input) }
    assert_equal("Unsupported bundle format: \"\"", e.message)
  end

  def test_verification_input_bundle_missing_verification_material
    verification_input = Sigstore::Verification::V1::Input.new
    verification_input.bundle = Sigstore::Bundle::V1::Bundle.new
    verification_input.bundle.media_type = Sigstore::BundleType::BUNDLE_0_3.media_type
    e = assert_raise(Sigstore::Error::InvalidBundle) { Sigstore::VerificationInput.new(verification_input) }
    assert_equal("bundle requires verification material", e.message)
  end

  DIGEST = OpenSSL::Digest.new("SHA256").update("hello world").digest

  def test_from_raw_artifact
    artifact = Sigstore::Verification::V1::Artifact.new.tap { _1.artifact = "hello world" }
    hashed = Sigstore::VerificationInput.hashed_input_for(artifact)
    assert_equal Sigstore::Common::V1::HashAlgorithm::SHA2_256, hashed.algorithm
    assert_equal DIGEST, hashed.digest
  end

  def test_from_artifact_uri
    artifact = Sigstore::Verification::V1::Artifact.new.tap do |a|
      a.artifact_uri = "sha256:#{DIGEST.unpack1("H*")}"
    end
    assert_equal DIGEST, Sigstore::VerificationInput.hashed_input_for(artifact).digest
  end

  def test_from_artifact_uri_rejects_non_sha256
    artifact = Sigstore::Verification::V1::Artifact.new.tap { _1.artifact_uri = "sha512:abcd" }
    e = assert_raise(Sigstore::Error::InvalidVerificationInput) do
      Sigstore::VerificationInput.hashed_input_for(artifact)
    end
    assert_include e.message, "must be prefixed with 'sha256:'"
  end

  # protobuf-specs v0.5.1 added the typed artifact_digest oneof variant.
  def test_from_artifact_digest
    artifact = Sigstore::Verification::V1::Artifact.new.tap do |a|
      a.artifact_digest = Sigstore::Common::V1::HashOutput.new.tap do |h|
        h.algorithm = Sigstore::Common::V1::HashAlgorithm::SHA2_256
        h.digest = DIGEST
      end
    end
    assert_equal DIGEST, Sigstore::VerificationInput.hashed_input_for(artifact).digest
  end

  def test_from_artifact_digest_rejects_non_sha256
    artifact = Sigstore::Verification::V1::Artifact.new.tap do |a|
      a.artifact_digest = Sigstore::Common::V1::HashOutput.new.tap do |h|
        h.algorithm = Sigstore::Common::V1::HashAlgorithm::SHA2_512
        h.digest = "x"
      end
    end
    e = assert_raise(Sigstore::Error::InvalidVerificationInput) do
      Sigstore::VerificationInput.hashed_input_for(artifact)
    end
    assert_include e.message, "unsupported artifact digest algorithm"
  end
end
