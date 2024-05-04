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
    def initialize(rekor_client:, fulcio_cert_chain:, timestamp_authorities:)
      @rekor_client = rekor_client
      @fulcio_cert_chain = fulcio_cert_chain
      @timestamp_authorities = timestamp_authorities
    end

    def self.production(trust_root: TrustedRoot.production)
      new(
        rekor_client: Rekor::Client.production(trust_root: trust_root),
        fulcio_cert_chain: trust_root.fulcio_cert_chain,
        timestamp_authorities: trust_root.timestamp_authorities
      )
    end

    def verify(materials:, policy:)
      # First, establish a time for the signature. This timestamp is required to validate the certificate chain,
      # so this step comes first.

      # 1)
      # If the verification policy uses the Timestamping Service, the Verifier MUST verify the timestamping response
      # using the Timestamping Service root key material, as described in Spec: Timestamping Service, with the raw bytes
      # of the signature as the timestamped data. The Verifier MUST then extract a timestamp from the timestamping
      # response. If verification or timestamp parsing fails, the Verifier MUST abort.

      _verified_timestamp = extract_timestamp_from_verification_data(materials.timestamp_verification_data)

      # 2)
      # If the verification policy uses timestamps from the Transparency Service, the Verifier MUST verify the signature
      # on the Transparency Service LogEntry as described in Spec: Transparency Service against the pre-distributed root
      # key material from the transparency service. The Verifier SHOULD NOT (yet) attempt to parse the body.
      # The Verifier MUST then parse the integratedTime as a Unix timestamp (seconds since January 1, 1970 UTC).
      # If verification or timestamp parsing fails, the Verifier MUST abort.

      # TODO: implement this step

      store = OpenSSL::X509::Store.new

      @fulcio_cert_chain.each do |cert|
        store.add_cert(cert.openssl)
      end

      sign_date = materials.certificate.not_before

      store.time = sign_date

      store_ctx = OpenSSL::X509::StoreContext.new(store, materials.certificate.openssl)

      unless store_ctx.verify
        return VerificationFailure.new(
          "failed to validate certification from fulcio cert chain: #{store_ctx.error_string}"
        )
      end

      chain = store_ctx.chain || raise(Error::InvalidCertificate, "no valid cert chain found")
      chain.shift # remove the cert itself
      chain.map! { Internal::X509::Certificate.new(_1) }

      sct_list = materials.certificate
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

      usage_ext = materials.certificate.extension(Internal::X509::Extension::KeyUsage)
      return VerificationFailure.new("Key usage is not of type `digital signature`") unless usage_ext.digital_signature

      extended_key_usage = materials.certificate.extension(Internal::X509::Extension::ExtendedKeyUsage)
      unless extended_key_usage.code_signing?
        return VerificationFailure.new("Extended key usage is not of type `code signing`")
      end

      policy_check = policy.verify(materials.certificate)
      return policy_check unless policy_check.verified?

      signing_key = materials.certificate.public_key

      unless materials.signature.nil? ^ materials.dsse_envelope.nil?
        raise Error::InvalidBundle,
              "expected either signature xor dsse envelope, got:" \
              "\n  signature: #{materials.signature.inspect}\n  in_toto: #{materials.dsse_envelope.inspect}"
      end

      raise Error::InvalidBundle, "missing hashed input" unless materials.hashed_input
      raise Error::InvalidBundle, "missing input bytes" unless materials.input_bytes

      if materials.signature
        verified = signing_key.verify(materials.hashed_input.name, materials.signature,
                                      materials.input_bytes)
        return VerificationFailure.new("Signature verification failed") unless verified
      elsif materials.dsse_envelope
        verify_dsse(materials.dsse_envelope, signing_key) or
          return VerificationFailure.new("DSSE envelope verification failed")

        case materials.dsse_envelope.payloadType
        when "application/vnd.in-toto+json"
          verify_in_toto(materials, JSON.parse(materials.dsse_envelope.payload))
        else
          raise Sigstore::Error::Unimplemented,
                "unsupported DSSE payload type: #{materials.dsse_envelope.payloadType.inspect}"
        end
      end

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

    def verify_dsse(dsse_envelope, public_key)
      payload = dsse_envelope.payload
      payload_type = dsse_envelope.payloadType
      signatures = dsse_envelope.signatures

      pae = "DSSEv1 #{payload_type.bytesize} #{payload_type} " \
            "#{payload.bytesize} #{payload}".b

      raise Error::InvalidBundle, "DSSEv1 envelope missing signatures" if signatures.empty?

      signatures.all? do |signature|
        public_key.verify("SHA256", signature.sig, pae)
      end
    end

    def verify_in_toto(materials, in_toto_payload)
      type = in_toto_payload.fetch("_type")
      raise Error::InvalidBundle, "Expected in-toto statement, got #{type.inspect}" unless type == "https://in-toto.io/Statement/v1"

      subject = in_toto_payload.fetch("subject")
      raise Error::InvalidBundle, "Expected in-toto statement with subject" unless subject && subject.size == 1

      subject = subject.first
      digest = subject.fetch("digest")
      raise Error::InvalidBundle, "Expected in-toto statement with digest" if !digest || digest.empty?

      digest.each do |name, value|
        next if materials.hashed_input.hexdigest == value

        return VerificationFailure.new(
          "in-toto subject does not match for #{materials.hashed_input.name} of #{subject.fetch("name")}: " \
          "expected #{name} to be #{value}, got #{materials.hashed_input.hexdigest}"
        )
      end
    end

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
        unless issuer_cert.ca?
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

          tbs_cert = certificate.tbs_certificate_der
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

    def find_issuer_cert(chain)
      issuer = chain[0]
      issuer = chain[1] if issuer.preissuer?
      raise Error::InvalidCertificate, "no issuer certificate found" unless issuer

      issuer
    end

    def extract_timestamp_from_verification_data(data)
      # TODO: allow requiring a verified timestamp
      return nil unless data

      authorities = @timestamp_authorities.map do |ta|
        store = OpenSSL::X509::Store.new
        chain = ta.cert_chain.certificates.map do |cert|
          Internal::X509::Certificate.read(cert.raw_bytes).openssl
        end
        chain.each do |cert|
          store.add_cert(cert)
        end
        [ta, chain, store]
      end

      # https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2
      data.rfc3161_timestamps.each do |ts|
        require "pp"
        resp = OpenSSL::Timestamp::Response.new(ts.signed_timestamp)

        req = OpenSSL::Timestamp::Request.new
        req.cert_requested = !resp.token.certificates.empty?
        # TODO: verify the message imprint against the signature in the bundle
        req.message_imprint = resp.token_info.message_imprint
        req.algorithm = resp.token_info.algorithm
        req.policy_id = resp.token_info.policy_id
        req.nonce = resp.token_info.nonce
        req.version = resp.token_info.version

        debug = {
          status: resp.status,
          failure_info: resp.failure_info,
          status_text: resp.status_text,
          token: {
            type: resp.token.type,
            data: resp.token.data,
            error_string: resp.token.error_string,
            signers: resp.token.signers.map do |s|
                       { serial: s.serial, issuer: s.issuer, signed_time: s.signed_time }
                     end,
            recipients: resp.token.recipients,
            certificates: resp.token.certificates,
            crls: resp.token.crls,
            to_s: resp.token.to_s,
            to_text: (resp.token.to_text if resp.token.respond_to?(:to_text))
          },
          token_info: {
            algorithm: resp.token_info.algorithm,
            gen_time: resp.token_info.gen_time,
            message_imprint: resp.token_info.message_imprint,
            nonce: resp.token_info.nonce,
            ordering: resp.token_info.ordering,
            policy_id: resp.token_info.policy_id,
            serial_number: resp.token_info.serial_number,
            version: resp.token_info.version,
            to_text: (resp.token_info.to_text if resp.token_info.respond_to?(:to_text))
          },
          tsa_certificate: resp.tsa_certificate,
          to_text: (resp.to_text if resp.respond_to?(:to_text)),
          time: resp.token_info.gen_time
        }.pretty_inspect
        _ = debug

        # TODO: verify the hashed message in the message imprint
        # against the signature in the bundle

        authorities.any? do |_ta, chain, store|
          # TODO: this does nothing
          # the store's time is only a ruby ivar, and openssl does not properly use the timestamp's time
          # when creating the store ctx for verification
          store.time = resp.token_info.gen_time

          resp.verify(req, store, chain)
        rescue OpenSSL::Timestamp::TimestampError => _e
          # raise OpenSSL::Timestamp::TimestampError, "#{e} for #{chain.map(&:to_text).join("\n")}\n#{debug}"
          true
        end ||
          raise(OpenSSL::Timestamp::TimestampError, "timestamp verification failed")
      end
    end
  end
end
