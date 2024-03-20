# frozen_string_literal: true

require "sigstore/trusted_root"
require "sigstore/internal/merkle"
require "sigstore/internal/set"
require "sigstore/rekor/checkpoint"

module Sigstore
  class Verifier
    def initialize(rekor_client:, fulcio_cert_chain:)
      @rekor_client = rekor_client
      @fulcio_cert_chain = fulcio_cert_chain
    end

    def self.production(trust_root: TrustedRoot.production)
      new(
        rekor_client: Rekor::Client.production(trust_root: trust_root),
        fulcio_cert_chain: trust_root.fulcio_cert_chain
      )
    end

    def verify(materials:, policy:)
      store = OpenSSL::X509::Store.new

      @fulcio_cert_chain.each do |cert|
        store.add_cert(cert)
      end

      sign_date = materials.certificate.not_before
      cert_ossl = OpenSSL::X509::Certificate.new(materials.certificate)

      store.time = sign_date

      store_ctx = OpenSSL::X509::StoreContext.new(store, cert_ossl)

      store_ctx.verify

      usage_ext = materials.certificate.find_extension("keyUsage")
      unless usage_ext.value == "Digital Signature"
        return VerificationFailure.new("Key usage is not of type `digital signature`")
      end

      extended_key_usage = materials.certificate.find_extension("extendedKeyUsage")
      unless extended_key_usage.value == "Code Signing"
        return VerificationFailure.new("Extended key usage is not of type `code signing`")
      end

      policy_check = policy.verify(materials.certificate)
      return policy_check unless policy_check.verified?

      signing_key = materials.certificate.public_key

      raise "missing hashed input" unless materials.hashed_input
      raise "missing signature" unless materials.signature
      raise "missing input bytes" unless materials.input_bytes

      verified = signing_key.verify(materials.hashed_input.name, materials.signature,
                                    materials.input_bytes)
      return VerificationFailure.new("Signature verification failed") unless verified

      entry = materials.find_rekor_entry(@rekor_client)
      if entry.inclusion_proof&.checkpoint
        Internal::Merkle.verify_merkle_inclusion(entry)
        Rekor::Checkpoint.verify_checkpoint(@rekor_client, entry)
      elsif !materials.offline
        return VerificationFailure.new("Missing Rekor inclusion proof")
      else
        warn "inclusion proof not present in bundle: skipping due to offline verification"
      end

      Internal::SET.verify_set(client: @rekor_client, entry: entry) if entry.inclusion_promise

      integrated_time = Time.at(entry.integrated_time).utc
      if integrated_time < materials.certificate.not_before || integrated_time > materials.certificate.not_after
        return VerificationFailure.new("invalid signing cert: expired at time of Rekor entry")
      end

      VerificationSuccess.new
    end
  end
end
