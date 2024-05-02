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
require_relative "transparency"

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
    attr_reader :media_type

    def initialize(media_type)
      @media_type = media_type
    end

    BUNDLE_0_1 = new("application/vnd.dev.sigstore.bundle+json;version=0.1")
    BUNDLE_0_2 = new("application/vnd.dev.sigstore.bundle+json;version=0.2")
    BUNDLE_0_3 = new("application/vnd.dev.sigstore.bundle.v0.3+json")

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
  end

  VerificationMaterials = Struct.new(:hashed_input, :certificate, :signature, :offline, :rekor_entry, :input_bytes,
                                     keyword_init: true) do
    # @implements VerificationMaterials

    def initialize(input:, cert_pem:, **kwargs)
      input_bytes = input.read
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(input_bytes)
      hashed_input = digest
      certificate = OpenSSL::X509::Certificate.new(cert_pem)

      super(hashed_input: hashed_input, certificate: certificate, input_bytes: input_bytes, offline: offline, **kwargs)

      raise ArgumentError, "offline verification requires a rekor entry" if offline && !rekor_entry?
    end

    def rekor_entry?
      !!rekor_entry
    end

    def find_rekor_entry(rekor_client)
      _has_inclusion_promise = rekor_entry? && rekor_entry.inclusion_promise
      has_inclusion_proof = rekor_entry? && rekor_entry.inclusion_proof && rekor_entry.inclusion_proof.checkpoint

      # debug

      expected_entry = {
        "spec" => {
          "signature" => {
            "content" => [signature].pack("m0"),
            "publicKey" => {
              "content" => [certificate.to_pem].pack("m0")
            }
          },
          "data" => {
            "hash" => {
              "algorithm" => hashed_input.name.downcase,
              "value" => hashed_input.hexdigest
            }
          }
        },
        "kind" => "hashedrekord",
        "apiVersion" => "0.0.1"
      }

      entry = if offline
                # debug
                rekor_entry
              elsif !has_inclusion_proof
                # debug
                rekor_client.log.entries.retrieve.post(expected_entry)
              else # rubocop:disable Lint/DuplicateBranch
                rekor_entry
              end

      raise Error::MissingRekorEntry, "Rekor entry not found" unless entry

      # debug

      actual_body = JSON.parse(entry.body.unpack1("m0"))
      if actual_body != expected_entry.to_h
        raise Error::InvalidRekorEntry, "Invalid rekor entry: expected #{expected_entry.to_h}, got #{actual_body}"
      end

      entry
    end

    def self.from_bundle(input:, bundle:, offline:)
      media_type = BundleType.from_media_type(bundle.media_type)

      case media_type
      when BundleType::BUNDLE_0_3
        leaf_cert = OpenSSL::X509::Certificate.new(bundle.verification_material.certificate.raw_bytes)
      when BundleType::BUNDLE_0_1, BundleType::BUNDLE_0_2
        certs = bundle.verification_material.x509_certificate_chain.certificates.map do |cert|
          OpenSSL::X509::Certificate.new(cert.raw_bytes)
        end
        raise Error::InvalidBundle, "Expected certificate chain" if certs.empty?

        leaf_cert = certs.shift
        raise Error::InvalidBundle, "Expected leaf certificate" unless cert_is_leaf?(leaf_cert)

        certs.each do |cert|
          raise Error::InvalidBundle, "Root CA in chain" if cert_is_root_ca?(cert)
        end
      else
        raise Error::InvalidBundle, "Unsupported bundle format: #{media_type}"
      end

      case bundle.content
      when :message_signature
        signature = bundle.message_signature.signature
      when :dsse_envelope
        # TODO: handle DSSE envelope
        raise Error::Unimplemented,
              "DSSE envelope verification not yet supported: #{JSON.pretty_generate bundle.as_json}"
      else
        raise Error::Unimplemented, "Unsupported bundle content: #{bundle.content}"
      end

      tlog_entries = bundle.verification_material.tlog_entries
      raise Error::InvalidBundle, "Expected one tlog entry" if tlog_entries.size != 1

      tlog_entry = tlog_entries.first

      if media_type == BundleType::BUNDLE_0_1
        raise Error::InvalidBundle, "bundle v0.1 requires an inclusion promise" unless tlog_entry.inclusion_promise
        if tlog_entry.inclusion_proof && !tlog_entry.inclusion_proof.checkpoint.envelope
          raise Error::InvalidBundle, "0.1 bundle contains an inclusion proof without checkpoint"
        end
      else
        raise Error::InvalidBundle, "must contain an inclusion proof" unless tlog_entry.inclusion_proof
        raise Error::InvalidBundle, "must contain a checkpoint" unless tlog_entry.inclusion_proof.checkpoint.envelope
      end

      if tlog_entry.inclusion_proof&.checkpoint&.envelope
        parsed_inclusion_proof = Sigstore::Transparency::InclusionProof.new(
          checkpoint: tlog_entry.inclusion_proof.checkpoint.envelope,
          hashes: tlog_entry.inclusion_proof.hashes.map { |h| h.unpack1("H*") },
          log_index: tlog_entry.inclusion_proof.log_index,
          root_hash: tlog_entry.inclusion_proof.root_hash.unpack1("H*"),
          tree_size: tlog_entry.inclusion_proof.tree_size
        )
      end

      entry = Sigstore::Transparency::LogEntry.new(
        uuid: nil,
        body: [tlog_entry.canonicalized_body].pack("m0"),
        integrated_time: tlog_entry.integrated_time,
        log_id: tlog_entry.log_id.key_id.unpack1("H*"),
        log_index: tlog_entry.log_index,
        inclusion_proof: parsed_inclusion_proof,
        inclusion_promise: [tlog_entry.inclusion_promise.signed_entry_timestamp].pack("m0")
      )

      new(
        input: input,
        cert_pem: leaf_cert.to_pem,
        signature: signature,
        offline: offline,
        rekor_entry: entry
      )
    end

    def self.cert_is_leaf?(cert)
      raise Error::InvalidCertificate, "invalid X.509 version: #{cert.version.inspect}" if cert.version != 2 # v3

      return false if cert_is_ca?(cert)

      key_usage = cert.find_extension("keyUsage") || raise(Error::InvalidCertificate,
                                                           "no keyUsage in #{cert.extensions.map(&:to_h)}")
      digital_signature = key_usage&.value&.include?("Digital Signature") # TODO: proper inclusion checking

      unless digital_signature
        raise Error::InvalidCertificate,
              "invalid certificate for Sigstore purposes: missing digital signature usage: #{key_usage.to_h}"
      end

      extended_key_usage = cert.find_extension("extendedKeyUsage")
      extended_key_usage&.value&.include?("Code Signing") # TODO: proper inclusion checking
    end

    def self.cert_is_ca?(cert)
      raise Error::InvalidCertificate, "invalid X.509 version: #{cert.version.inspect}" if cert.version != 2 # v3

      basic_constraints = cert.find_extension("basicConstraints")
      return false unless basic_constraints

      unless basic_constraints.critical?
        raise Error::InvalidCertificate,
              "invalid X.509 certificate: non-critical BasicConstraints in CA"
      end

      seq = OpenSSL::ASN1.decode(basic_constraints.value_der)
      unless seq.is_a?(OpenSSL::ASN1::Sequence)
        raise Error::InvalidCertificate,
              "invalid X.509 certificate: BasicConstraints is not a sequence"
      end

      ca, _path_len = seq.value
      unless ca.is_a?(OpenSSL::ASN1::Boolean)
        raise Error::InvalidCertificate,
              "invalid X.509 certificate: ca is not a boolean"
      end

      ca = ca.value

      key_usage = cert.find_extension("keyUsage")
      raise Error::InvalidCertificate, "invalid X.509 certificate: missing keyUsage" unless key_usage

      key_usage_bs = OpenSSL::ASN1.decode(key_usage.value_der)
      unless key_usage_bs.is_a?(OpenSSL::ASN1::BitString)
        raise Error::InvalidCertificate, "invalid X.509 certificate: keyUsage is not a bit string"
      end

      key_sign_cert = key_usage_bs.value.getbyte(0).allbits?(0b00000100) # KeyUsage.keyCertSign, bit 5

      return true if ca && key_sign_cert

      return false unless ca || key_sign_cert

      raise Error::InvalidCertificate, "invalid certificate states: KeyUsage.keyCertSign"
    end
  end
end
