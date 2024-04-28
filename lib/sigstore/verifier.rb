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

      chain = store_ctx.chain || raise("no chain found")
      chain.shift # remove the cert itself

      sct_list = precertificate_signed_certificate_timestamps(materials.certificate)
      raise "no SCTs found" if sct_list.empty?

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

      raise "missing hashed input" unless materials.hashed_input
      raise "missing signature" unless materials.signature # TODO: handle DSSE envelope
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

    def verify_sct(sct, certificate, chain, ct_keyring)
      # TODO: validate hash & signature algorithm match the key in the keyring
      hash = sct.fetch(:hash)
      signature_algorithm = sct.fetch(:signature_algorithm)
      unless hash == "sha256" && signature_algorithm == "ecdsa"
        # TODO: support more algorithms
        raise "only sha256 edcsa supported, got #{hash} #{signature_algorithm}"
      end

      issuer_key_id = nil
      if sct[:entry_type] == 1
        issuer_cert = find_issuer_cert(chain)
        issuer_pubkey = issuer_cert.public_key
        unless VerificationMaterials.cert_is_ca?(issuer_cert)
          raise "Invalid issuer pubkey basicConstraint (not a CA): #{issuer_cert.to_text}"
        end
        raise "unsupported issuer pubkey" unless case issuer_pubkey
                                                 when OpenSSL::PKey::RSA, OpenSSL::PKey::EC
                                                   true
                                                 else
                                                   false
                                                 end

        issuer_key_id = OpenSSL::Digest::SHA256.digest(issuer_pubkey.public_to_der)
      end

      digitally_signed = pack_digitally_signed(sct, certificate, issuer_key_id).b

      ct_keyring.verify(key_id: sct[:log_id], signature: sct[:signature], data: digitally_signed)
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
        case sct[:entry_type]
        when 0 # x509_entry
          cert_der = certificate.to_public_der
          cert_len = cert_der.bytesize
          unused, len1, len2, len3 = [cert_len].pack("N").unpack("C4")
          raise "invalid cert_len #{cert_len} #{cert_der.inspect}" if unused != 0

          [len1, len2, len3, cert_der].pack("CCC a#{cert_len}")
        when 1 # precert_entry
          unless issuer_key_id&.bytesize == 32
            raise "issuer_key_id must be 32 bytes for precert, given #{issuer_key_id.inspect}"
          end

          tbs_cert = tbs_certificate_der(certificate)
          tbs_cert_len = tbs_cert.bytesize
          unused, len1, len2, len3 = [tbs_cert_len].pack("N").unpack("C4")
          raise "invalid tbs_cert_len #{tbs_cert_len} #{tbs_cert.inspect}" if unused != 0

          [issuer_key_id, len1, len2, len3, tbs_cert].pack("a32 CCC a#{tbs_cert_len}")
        else
          raise "only x509_entry and precert_entry supported, given #{sct[:entry_type].inspect}"
        end

      [sct[:version], 0, sct[:timestamp], sct[:entry_type], signed_entry, 0].pack(<<~PACK)
        C # version
        C # signature_type
        Q> # timestamp
        n # entry_type
        a#{signed_entry.bytesize} # signed_entry
        n # extensions length
      PACK
    end

    def tbs_certificate_der(certificate)
      tbs_cert = certificate.dup
      oid = OpenSSL::X509::Extension.new("1.3.6.1.4.1.11129.2.4.2", "").oid
      tbs_cert.extensions = tbs_cert.extensions.reject do |ext|
        ext.oid == oid
      end
      # ensure the underlying certificate is marked as modified
      tbs_cert.serial = tbs_cert.serial + 1
      tbs_cert.serial = tbs_cert.serial - 1

      raise "no #{oid} extension found" unless certificate.extensions.size == tbs_cert.extensions.size + 1

      OpenSSL::ASN1.decode(tbs_cert.to_der).value[0].to_der.b
    end

    # https://letsencrypt.org/2018/04/04/sct-encoding.html
    def precertificate_signed_certificate_timestamps(certificate)
      # this is cursed. can't always find_extension(oid) because #oid can return a string or an OID
      oid = OpenSSL::X509::Extension.new("1.3.6.1.4.1.11129.2.4.2", "").oid
      precert_scts_extension = certificate.find_extension(oid)

      unless precert_scts_extension
        raise "No PrecertificateSignedCertificateTimestamps (#{oid.inspect}) found for the certificate #{certificate.to_text}"
      end

      # TODO: parse the extension properly
      # https://github.com/pierky/sct-verify/blob/master/sct-verify.py

      os1 = OpenSSL::ASN1.decode(precert_scts_extension.value_der)

      len = os1.value.unpack1("n")
      string = os1.value.byteslice(2..)
      raise "os1: len=#{len} #{os1.value.inspect}" unless string && string.bytesize == len

      len = string.unpack1("n")
      string = string.byteslice(2..)
      raise "os2: len=#{len} #{string.inspect}" unless string && string.bytesize == len

      list = unpack_sct_list(string)

      list.map! do |sct|
        hash = {
          0 => "none",
          1 => "md5",
          2 => "sha1",
          3 => "sha224",
          4 => "sha256",
          5 => "sha384",
          6 => "sha512",
          255 => "unknown"
        }.fetch(sct[:sct_signature_alg_hash], "unknown")

        signature_algorithm = {
          0 => "anonymous",
          1 => "rsa",
          2 => "dsa",
          3 => "ecdsa",
          255 => "unknown"
        }.fetch(sct[:sct_signature_alg_sign], "unknown")

        {
          version: sct[:sct_version],
          log_id: sct[:sct_log_id].unpack1("H*"),
          timestamp: sct[:sct_timestamp],
          signature: sct[:sct_signature_bytes],
          hash: hash,
          signature_algorithm: signature_algorithm,
          entry_type: 1 # precert_entry
        }
      end
    end

    def unpack_sct_list(string)
      offset = 0
      len = string.bytesize
      list = []
      while offset < len
        sct_version, sct_log_id, sct_timestamp, sct_extensions_len = string.unpack("Ca32Q>n", offset: offset)
        offset += 1 + 32 + 8 + 2 + sct_extensions_len
        raise "expect sct version to be 0, got #{sct_version}" unless sct_version.zero?
        raise "sct_extensions_len=#{sct_extensions_len} not supported" unless sct_extensions_len.zero?

        sct_signature_alg_hash, sct_signature_alg_sign, sct_signature_len = string.unpack("CCn", offset: offset)
        offset += 1 + 1 + 2
        sct_signature_bytes = string.unpack1("a#{sct_signature_len}", offset: offset).b
        offset += sct_signature_len
        list << {
          sct_version: sct_version,
          sct_log_id: sct_log_id,
          sct_timestamp: sct_timestamp,
          sct_extensions_len: sct_extensions_len,
          sct_signature_alg_hash: sct_signature_alg_hash,
          sct_signature_alg_sign: sct_signature_alg_sign,
          sct_signature_len: sct_signature_len,
          sct_signature_bytes: sct_signature_bytes
        }
      end
      raise "offset=#{offset} len=#{len}" unless offset == len

      list
    end

    def find_issuer_cert(chain)
      issuer = chain[0]
      issuer = chain[1] if preissuer?(issuer)
      raise "issuer not found" unless issuer

      issuer
    end

    def preissuer?(cert)
      return false unless (eku = cert.find_extension("extendedKeyUsage"))

      values = OpenSSL::ASN1.decode(eku.value_der).value
      raise values.inspect unless values.is_a?(Array)

      values.any? do
        _1.oid == "1.3.6.1.4.1.11129.2.4.4"
      end
    end
  end
end
