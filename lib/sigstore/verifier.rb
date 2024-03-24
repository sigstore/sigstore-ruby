# frozen_string_literal: true

require "sigstore/trusted_root"
require "sigstore/internal/merkle"
require "sigstore/internal/set"
require "sigstore/rekor/checkpoint"

module Sigstore
  class Verifier
    def initialize(rekor_client:, fulcio_cert_chain:)
      @rekor_client = rekor_client
      @fulcio_cert_chain = fulcio_cert_chain.map { |cert| OpenSSL::X509::Certificate.new(cert) }
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

      unless store_ctx.verify
        return VerificationFailure.new(
          "failed to validate certification from fulcio cert chain: #{store_ctx.error_string}"
        )
      end

      chain = store_ctx.chain || raise
      chain.drop(1)

      _sct = precertificate_signed_certificate_timestamps(materials.certificate)[0]
      # verify_sct(
      #   sct,
      #   materials.certificate,
      #   chain,
      #   @rekor_client._ct_keyring
      # )

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

    private

    def precertificate_signed_certificate_timestamps(certificate)
      # this is cursed. can't always find_extension(oid) because #oid can return a string or an OID
      oid = OpenSSL::X509::Extension.new("1.3.6.1.4.1.11129.2.4.2", "").oid
      precert_scts_extension = certificate.find_extension(oid)
      unless precert_scts_extension
        raise "No PrecertificateSignedCertificateTimestamps (#{oid.inspect}) found for the certificate #{certificate.extensions.join("\n")}"
      end

      # TODO: parse the extension properly
      # https://github.com/pierky/sct-verify/blob/master/sct-verify.py

      os1 = OpenSSL::ASN1.decode(precert_scts_extension.value_der)

      len = os1.value.unpack1("n")
      string = os1.value[2..]
      raise "os1: len=#{len} #{os1.value.inspect}" unless string && string.size == len

      len = string.unpack1("n")
      string = string[2..]
      raise "os1: len=#{len} #{string.inspect}" unless string && string.size == len

      sct_version, sct_log_id, sct_timestamp, sct_extensions_len, sct_signature_alg_hash,
      sct_signature_alg_sign, sct_signature_len, sct_signature_bytes = string.unpack("Ca32QnCCna*")
      raise "sct extensions not supported" unless sct_extensions_len.zero?
      unless sct_signature_bytes.bytesize == sct_signature_len
        raise "sct_signature_bytes: #{sct_signature_bytes.inspect} sct_signature_len: #{sct_signature_len}"
      end

      # TODO: parse the SCT properly
      [nil]
    end
  end
end
