# frozen_string_literal: true

# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative "error"

require_relative "trusted_root"

module Sigstore
  VerificationResult = Struct.new(:success, keyword_init: true) do
    # @implements VerificationResult

    alias_method :verified?, :success
  end

  class VerificationSuccess < VerificationResult
    # @implements VerificationSuccess
    def initialize
      super(success: true)
    end
  end

  class VerificationFailure < VerificationResult
    # @implements VerificationFailure
    attr_reader :reason

    def initialize(reason)
      @reason = reason
      super(success: false)
    end
  end

  class BundleType
    include Comparable

    attr_reader :media_type

    def initialize(media_type)
      @media_type = media_type
    end

    BUNDLE_0_1 = new("application/vnd.dev.sigstore.bundle+json;version=0.1")
    BUNDLE_0_2 = new("application/vnd.dev.sigstore.bundle+json;version=0.2")
    BUNDLE_0_3 = new("application/vnd.dev.sigstore.bundle.v0.3+json")

    VERSIONS = [BUNDLE_0_1, BUNDLE_0_2, BUNDLE_0_3].freeze

    def self.from_media_type(media_type)
      case media_type
      when BUNDLE_0_1.media_type
        BUNDLE_0_1
      when BUNDLE_0_2.media_type
        BUNDLE_0_2
      when BUNDLE_0_3.media_type, "application/vnd.dev.sigstore.bundle+json;version=0.3"
        BUNDLE_0_3
      else
        raise Error::InvalidBundle, "Unsupported bundle format: #{media_type.inspect}"
      end
    end

    def <=>(other)
      VERSIONS.index(self) <=> VERSIONS.index(other)
    end
  end

  class VerificationInput < DelegateClass(Verification::V1::Input)
    attr_reader :trusted_root, :sbundle, :hashed_input

    def initialize(*)
      super
      @trusted_root = TrustedRoot.new(artifact_trust_root)
      @sbundle = SBundle.new(bundle)
      if sbundle.message_signature? && !artifact
        raise Error::InvalidVerificationInput, "bundle with message_signature requires an artifact"
      end

      case artifact.data
      when :artifact_uri
        unless artifact.artifact_uri.start_with?("sha256:")
          raise Error::InvalidVerificationInput,
                "artifact_uri must be prefixed with 'sha256:'"
        end

        @hashed_input = Common::V1::HashOutput.new.tap do |hash_output|
          hash_output.algorithm = Common::V1::HashAlgorithm::SHA2_256
          hexdigest = artifact.artifact_uri.split(":", 2).last
          hash_output.digest = Internal::Util.hex_decode(hexdigest)
        end
      when :artifact
        @hashed_input = Common::V1::HashOutput.new.tap do |hash_output|
          hash_output.algorithm = Common::V1::HashAlgorithm::SHA2_256
          hash_output.digest = OpenSSL::Digest.new("SHA256").update(artifact.artifact).digest
        end
      else
        raise Error::InvalidVerificationInput, "Unsupported artifact data: #{artifact.data}"
      end

      freeze
    end
  end

  class SBundle < DelegateClass(Bundle::V1::Bundle)
    attr_reader :bundle_type, :leaf_certificate

    def initialize(*)
      super
      @bundle_type = BundleType.from_media_type(media_type)
      validate_version!
      freeze
    end

    def self.for_cert_bytes_and_signature(cert_bytes, signature)
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type
      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = cert_bytes
      bundle.message_signature = Common::V1::MessageSignature.new
      bundle.message_signature.signature = signature
      new(bundle)
    end

    def expected_tlog_entry(hashed_input)
      case content
      when :message_signature
        expected_hashed_rekord_tlog_entry(hashed_input)
      when :dsse_envelope
        rekor_entry = verification_material.tlog_entries.first
        case JSON.parse(rekor_entry.canonicalized_body).values_at("kind", "apiVersion")
        when %w[dsse 0.0.1]
          expected_dsse_0_0_1_tlog_entry
        when %w[intoto 0.0.2]
          expected_intoto_0_0_2_tlog_entry
        else
          raise Error::InvalidRekorEntry, "Unhandled rekor entry kind/version: #{t.inspect}"
        end
      else
        raise Error::InvalidBundle, "expected either message_signature or dsse_envelope"
      end
    end

    private

    def validate_version!
      case bundle_type
      when BundleType::BUNDLE_0_1
        unless verification_material.tlog_entries.all?(&:inclusion_promise)
          raise Error::InvalidBundle,
                "bundle v0.1 requires an inclusion promise"
        end
        if verification_material.tlog_entries.any? { |t| t.inclusion_proof&.checkpoint.nil? }
          raise Error::InvalidBundle,
                "0.1 bundle contains an inclusion proof without checkpoint"
        end
      else
        unless verification_material.tlog_entries.all?(&:inclusion_proof)
          raise Error::InvalidBundle,
                "must contain an inclusion proof"
        end
        unless verification_material.tlog_entries.all? { |t| t.inclusion_proof.checkpoint.envelope }
          raise Error::InvalidBundle,
                "inclusion proof must contain a checkpoint"
        end
      end

      raise Error::InvalidBundle, "Expected one tlog entry" if verification_material.tlog_entries.size > 1

      case verification_material.content
      when :public_key
        raise Error::Unimplemented, "public_key content of bundle"
      when :x509_certificate_chain
        certs = verification_material.x509_certificate_chain.certificates.map do |cert|
          Internal::X509::Certificate.read(cert.raw_bytes)
        end

        @leaf_certificate = certs.first
        certs.each do |cert|
          raise Error::InvalidBundle, "Root CA in chain" if cert.ca?
        end
      when :certificate
        @leaf_certificate = Internal::X509::Certificate.read(verification_material.certificate.raw_bytes)
      else
        raise Error::InvalidBundle, "Unsupported bundle content: #{content}"
      end
      raise Error::InvalidBundle, "Expected leaf certificate" unless @leaf_certificate.leaf?
    end

    def expected_hashed_rekord_tlog_entry(hashed_input)
      {
        "spec" => {
          "signature" => {
            "content" => Internal::Util.base64_encode(message_signature.signature),
            "publicKey" => {
              "content" => Internal::Util.base64_encode(leaf_certificate.to_pem)
            }
          },
          "data" => {
            "hash" => {
              "algorithm" => Internal::Util.hash_algorithm_name(hashed_input.algorithm),
              "value" => Internal::Util.hex_encode(hashed_input.digest)
            }
          }
        },
        "kind" => "hashedrekord",
        "apiVersion" => "0.0.1"
      }
    end

    def expected_intoto_0_0_2_tlog_entry
      {
        "apiVersion" => "0.0.2",
        "kind" => "intoto",
        "spec" => {
          "content" => {
            "envelope" => {
              "payloadType" => dsse_envelope.payloadType,
              "payload" => Internal::Util.base64_encode(Internal::Util.base64_encode(dsse_envelope.payload)),
              "signatures" => dsse_envelope.signatures.map do |sig|
                {
                  "publicKey" =>
                    # needed because #to_pem packs the key in base64 with m*
                    Internal::Util.base64_encode(
                      "-----BEGIN CERTIFICATE-----\n" \
                      "#{Internal::Util.base64_encode(leaf_certificate.to_der)}\n" \
                      "-----END CERTIFICATE-----\n"
                    ),
                  "sig" => Internal::Util.base64_encode(Internal::Util.base64_encode(sig.sig))
                }
              end
            },
            "payloadHash" => {
              "algorithm" => "sha256",
              "value" => OpenSSL::Digest::SHA256.hexdigest(dsse_envelope.payload)
            }
          }
        }
      }
    end

    def expected_dsse_0_0_1_tlog_entry
      {
        "apiVersion" => "0.0.1",
        "kind" => "dsse",
        "spec" => {
          "payloadHash" => {
            "algorithm" => "sha256",
            "value" => OpenSSL::Digest::SHA256.hexdigest(dsse_envelope.payload)
          },
          "signatures" =>
            dsse_envelope.signatures.map do |sig|
              {
                "signature" => Internal::Util.base64_encode(sig.sig),
                "verifier" => Internal::Util.base64_encode(leaf_certificate.to_pem)
              }
            end
        }
      }
    end
  end
end
