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

require "sigstore/trusted_root"
require "sigstore/internal/merkle"
require "sigstore/internal/set"
require "sigstore/rekor/checkpoint"
require "sigstore/internal/x509"

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

      chain = store_ctx.chain || raise(Error::InvalidCertificate, "no valid cert chain found")
      chain.shift # remove the cert itself

      sct_list = Internal::X509::Certificate
                 .new(materials.certificate)
                 .extension(Internal::X509::Extension::PrecertificateSignedCertificateTimestamps)
                 .signed_certificate_timestamps
      raise Error::InvalidCertificate, "no SCTs found" if sct_list.empty?

      sct_list.each do |sct|
        verified = verify_sct(
          sct,
          materials.certificate,
          chain,
          @rekor_client.ct_keyring
        )
        return VerificationFailure.new("SCT verification failed") unless verified
      end

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

      raise Error::InvalidBundle, "missing hashed input" unless materials.hashed_input
      raise Error::InvalidBundle, "missing signature" unless materials.signature # TODO: handle DSSE envelope
      raise Error::InvalidBundle, "missing input bytes" unless materials.input_bytes

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

    def verify_sct(sct, certificate, chain, ct_keyring)
      # TODO: validate hash & signature algorithm match the key in the keyring
      hash = sct.hash_algorithm
      signature_algorithm = sct.signature_algorithm
      unless hash == "sha256" && signature_algorithm == "ecdsa"
        # TODO: support more algorithms
        raise Error::Unimplemented, "only sha256 edcsa supported, got #{hash} #{signature_algorithm}"
      end

      issuer_key_id = nil
      if sct.entry_type == 1
        issuer_cert = find_issuer_cert(chain)
        issuer_pubkey = issuer_cert.public_key
        unless VerificationMaterials.cert_is_ca?(issuer_cert)
          raise Error::InvalidCertificate, "Invalid issuer pubkey basicConstraint (not a CA): #{issuer_cert.to_text}"
        end
        raise Error::InvalidCertificate, "unsupported issuer pubkey" unless case issuer_pubkey
                                                                            when OpenSSL::PKey::RSA, OpenSSL::PKey::EC
                                                                              true
                                                                            else
                                                                              false
                                                                            end

        issuer_key_id = OpenSSL::Digest::SHA256.digest(issuer_pubkey.public_to_der)
      end

      digitally_signed = pack_digitally_signed(sct, certificate, issuer_key_id).b

      ct_keyring.verify(key_id: sct.log_id, signature: sct.signature, data: digitally_signed)
    end

    def pack_digitally_signed(sct, certificate, issuer_key_id = nil)
      # https://datatracker.ietf.org/doc/html/rfc6962#section-3.4
      # https://datatracker.ietf.org/doc/html/rfc6962#section-3.5
      #
      #   digitally-signed struct {
      #     Version sct_version;
      #     SignatureType signature_type = certificate_timestamp;
      #     uint64 timestamp;
      #     LogEntryType entry_type;
      #     select(entry_type) {
      #         case x509_entry: ASN.1Cert;
      #         case precert_entry: PreCert;
      #     } signed_entry;
      #    CtExtensions extensions;
      # };

      signed_entry =
        case sct.entry_type
        when 0 # x509_entry
          cert_der = certificate.to_public_der
          cert_len = cert_der.bytesize
          unused, len1, len2, len3 = [cert_len].pack("N").unpack("C4")
          raise Error::InvalidCertificate, "invalid cert_len #{cert_len} #{cert_der.inspect}" if unused != 0

          [len1, len2, len3, cert_der].pack("CCC a#{cert_len}")
        when 1 # precert_entry
          unless issuer_key_id&.bytesize == 32
            raise Error::InvalidCertificate,
                  "issuer_key_id must be 32 bytes for precert, given #{issuer_key_id.inspect}"
          end

          tbs_cert = tbs_certificate_der(certificate)
          tbs_cert_len = tbs_cert.bytesize
          unused, len1, len2, len3 = [tbs_cert_len].pack("N").unpack("C4")
          raise Error::InvalidCertificate, "invalid tbs_cert_len #{tbs_cert_len} #{tbs_cert.inspect}" if unused != 0

          [issuer_key_id, len1, len2, len3, tbs_cert].pack("a32 CCC a#{tbs_cert_len}")
        else
          raise Error::Unimplemented, "only x509_entry and precert_entry supported, given #{sct[:entry_type].inspect}"
        end

      [sct.version, 0, sct.timestamp, sct.entry_type, signed_entry, 0].pack(<<~PACK)
        C # version
        C # signature_type
        Q> # timestamp
        n # entry_type
        a#{signed_entry.bytesize} # signed_entry
        n # extensions length
      PACK
    end

    def tbs_certificate_der(certificate)
      oid = OpenSSL::X509::Extension.new("1.3.6.1.4.1.11129.2.4.2", "").oid
      certificate.extensions.find do |ext|
        ext.oid == oid
      end || raise(Error::InvalidCertificate,
                   "No PrecertificateSignedCertificateTimestamps (#{oid.inspect}) found for the certificate")

      # This uglyness is needed because there is no way to force modifying an X509 certificate
      # in a way that it will be serialized with the modifications.
      seq = OpenSSL::ASN1.decode(certificate.to_der).value[0]
      seq.value = seq.value.map do |v|
        next v unless v.tag == 3

        v.value = v.value.map do |v2|
          v2.value = v2.value.map do |v3|
            next if v3.first.oid == "1.3.6.1.4.1.11129.2.4.2"

            v3
          end.compact!
          v2
        end
        v
      end

      seq.to_der
    end

    if RUBY_VERSION >= "3.1"
      def unpack_at(string, format, offset:)
        string.unpack(format, offset: offset)
      end

      def unpack1_at(string, format, offset:)
        string.unpack1(format, offset: offset)
      end
    else
      def unpack_at(string, format, offset:)
        string[offset..].unpack(format)
      end

      def unpack1_at(string, format, offset:)
        string[offset..].unpack1(format)
      end
    end

    def find_issuer_cert(chain)
      issuer = chain[0]
      issuer = chain[1] if preissuer?(issuer)
      raise Error::InvalidCertificate, "no issuer certificate found" unless issuer

      issuer
    end

    def preissuer?(cert)
      return false unless (eku = cert.find_extension("extendedKeyUsage"))

      values = OpenSSL::ASN1.decode(eku.value_der).value
      raise values.inspect unless values.is_a?(Array)

      values.any? do |value|
        value.oid == "1.3.6.1.4.1.11129.2.4.4"
      end
    end
  end
end
