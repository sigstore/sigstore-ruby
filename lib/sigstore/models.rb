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
                                     :dsse_envelope, :timestamp_verification_data,
                                     keyword_init: true) do
    include Loggable
    # @implements VerificationMaterials

    def initialize(input:, cert_pem:, **kwargs)
      input_bytes = input.read.freeze
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(input_bytes)
      hashed_input = digest.freeze
      certificate = Internal::X509::Certificate.read(cert_pem)

      super(hashed_input: hashed_input, certificate: certificate, input_bytes: input_bytes, offline: offline, **kwargs)

      return unless offline && !rekor_entry?

      raise ArgumentError,
            "offline verification requires a rekor entry"
    end

    def rekor_entry?
      !!rekor_entry
    end

    def find_rekor_entry(rekor_client)
      has_inclusion_promise = rekor_entry? && rekor_entry.inclusion_promise
      has_inclusion_proof = rekor_entry? && rekor_entry.inclusion_proof && rekor_entry.inclusion_proof.checkpoint

      logger.debug do
        "Looking for rekor entry, " \
          "has_inclusion_promise=#{!!has_inclusion_promise} has_inclusion_proof=#{!!has_inclusion_proof}" # rubocop:disable Style/DoubleNegation
      end

      if signature
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
      elsif dsse_envelope
        raise "need rekor entry for DSSE verification" unless rekor_entry?

        case t = JSON.parse(rekor_entry.body.unpack1("m0")).values_at("kind", "apiVersion")
        when %w[dsse 0.0.1]
          expected_entry = {
            "apiVersion" => "0.0.1",
            "kind" => "dsse",
            "spec" => {
              "payloadHash" => {
                "algorithm" => "sha256",
                "value" => OpenSSL::Digest::SHA256.hexdigest(dsse_envelope.payload)
              },
              "signatures" => dsse_envelope.signatures.map do |sig|
                {
                  "signature" => [sig.sig].pack("m0"),
                  "verifier" => [certificate.to_pem].pack("m0")
                }
              end
            }
          }

        when %w[intoto 0.0.2]
          expected_entry = {
            "apiVersion" => "0.0.2",
            "kind" => "intoto",
            "spec" => {
              "content" => {
                "envelope" => {
                  "payloadType" => dsse_envelope.payloadType,
                  "payload" => [[dsse_envelope.payload].pack("m0")].pack("m0"),
                  "signatures" => dsse_envelope.signatures.map do |sig|
                    {
                      "publicKey" => [
                        # needed because #to_pem packs the key in base64 with m*
                        "-----BEGIN CERTIFICATE-----\n#{[certificate.to_der].pack("m0")}\n-----END CERTIFICATE-----\n"
                      ].pack("m0"),
                      "sig" => [[sig.sig].pack("m0")].pack("m0")
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
        else
          raise Error::InvalidRekorEntry, "Unhandled rekor entry kind/version: #{t.inspect}"
        end
      else
        raise Error::InvalidBundle,
              "expected either signature xor in-toto payload"
      end

      entry = if offline
                logger.debug { "Offline verification, skipping rekor" }
                rekor_entry
              elsif !has_inclusion_proof
                logger.debug { "No inclusion proof, searching rekor" }
                rekor_client.log.entries.retrieve.post(expected_entry)
              else
                logger.debug { "Using rekor entry in sigstore bundle" }
                rekor_entry
              end

      raise Error::MissingRekorEntry, "Rekor entry not found" unless entry

      logger.debug { "Found rekor entry: #{entry}" }

      actual_body = JSON.parse(entry.body.unpack1("m0"))
      if dsse_envelope
        # since the hash is over the uncanonicalized envelope, we need to remove it
        #
        # NOTE(sigstore-python): This is very slightly weaker than the consistency check
        # for hashedrekord entries, due to how inclusion is recorded for DSSE:
        # the included entry for DSSE includes an envelope hash that we
        # *cannot* verify, since the envelope is uncanonicalized JSON.
        # Instead, we manually pick apart the entry body below and verify
        # the parts we can (namely the payload hash and signature list).
        case actual_body["kind"]
        when "intoto"
          actual_body["spec"]["content"].delete("hash")
        when "dsse"
          actual_body["spec"].delete("envelopeHash")
        else
          raise Error::InvalidRekorEntry, "Unknown kind: #{actual_body["kind"]}"
        end
      end

      if actual_body != expected_entry
        json_hash_diff = lambda do |a, b|
          return if a == b

          return [a, b] if a.class != b.class

          case a
          when Hash
            (a.keys | b.keys).to_h do |k|
              [k, json_hash_diff[a[k], b[k]]]
            end.compact
          when Array
            a.zip(b).map { |x, y| json_hash_diff[x, y] }.compact
          when String
            begin
              require "base64"
              da = a.unpack1("m0")
              db = b.unpack1("m0")

              [{
                "decoded" => da,
                "base64" => a
              },
               {
                 "decoded" => db,
                 "base64" => b
               }]
            rescue ArgumentError
              [a, b]
            end
          else
            [a, b]
          end
        end

        require "pp"
        raise Error::InvalidRekorEntry, "Invalid rekor entry:\n\n" \
                                        "Envelope:\n#{dsse_envelope.pretty_inspect}\n\n" \
                                        "Diff:\n#{json_hash_diff[expected_entry, actual_body].pretty_inspect}"
      end

      entry
    end

    def self.from_bundle(input:, bundle:, offline:)
      media_type = BundleType.from_media_type(bundle.media_type)

      case media_type
      when BundleType::BUNDLE_0_3
        leaf_cert = Internal::X509::Certificate.read(bundle.verification_material.certificate.raw_bytes)
      when BundleType::BUNDLE_0_1, BundleType::BUNDLE_0_2
        certs = bundle.verification_material.x509_certificate_chain.certificates.map do |cert|
          Internal::X509::Certificate.read(cert.raw_bytes)
        end
        raise Error::InvalidBundle, "Expected certificate chain" if certs.empty?

        leaf_cert = certs.shift
        raise Error::InvalidBundle, "Expected leaf certificate" unless leaf_cert.leaf?

        certs.each do |cert|
          raise Error::InvalidBundle, "Root CA in chain" if cert.ca?
        end
      else
        raise Error::InvalidBundle, "Unsupported bundle format: #{media_type}"
      end

      case bundle.content
      when :message_signature
        signature = bundle.message_signature.signature
      when :dsse_envelope
        dsse_envelope = bundle.dsse_envelope
      else
        raise Error::Unimplemented, "Unsupported bundle content: #{bundle.content}"
      end

      tlog_entries = bundle.verification_material.tlog_entries
      raise Error::InvalidBundle, "Expected one tlog entry" if tlog_entries.size != 1

      tlog_entry = tlog_entries.first

      if media_type == BundleType::BUNDLE_0_1
        unless tlog_entry.inclusion_promise
          raise Error::InvalidBundle,
                "bundle v0.1 requires an inclusion promise"
        end
        if tlog_entry.inclusion_proof && !tlog_entry.inclusion_proof.checkpoint.envelope
          raise Error::InvalidBundle,
                "0.1 bundle contains an inclusion proof without checkpoint"
        end
      else
        unless tlog_entry.inclusion_proof
          raise Error::InvalidBundle,
                "must contain an inclusion proof"
        end
        unless tlog_entry.inclusion_proof.checkpoint.envelope
          raise Error::InvalidBundle,
                "must contain a checkpoint"
        end
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
        dsse_envelope: dsse_envelope,
        offline: offline,
        rekor_entry: entry,
        timestamp_verification_data: bundle.verification_material.timestamp_verification_data
      )
    end
  end
end
