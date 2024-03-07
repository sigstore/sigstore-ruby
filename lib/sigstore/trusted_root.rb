# frozen_string_literal: true

require "delegate"
require "json"
require "sigstore_protobuf_specs"
require "google/protobuf/well_known_types"
require "openssl"

require_relative "internal/tuf"

module Sigstore
  class TrustedRoot < DelegateClass(Sigstore::TrustRoot::V1::TrustedRoot)
    def self.production(offline: false)
      from_tuf(Sigstore::Internal::TUF::DEFAULT_TUF_URL, offline)
    end

    def self.from_tuf(url, offline)
      path = Internal::TUF::TrustUpdater.new(url, offline).trusted_root_path
      from_file(path)
    end

    def self.from_file(path)
      contents = Gem.read_binary(path)
      new Sigstore::TrustRoot::V1::TrustedRoot.decode_json(contents)
    end

    def rekor_keys
      keys = tlog_keys(tlogs).to_a
      raise "Did not find one active Rekor key" if keys.size != 1

      keys
    end

    def ctfe_keys
      keys = tlog_keys(ctlogs).to_a
      raise "Did not find one active CT key" if keys.size != 1

      keys
    end

    def fulcio_cert_chain
      certs = ca_keys(certificate_authorities, allow_expired: true).flat_map { OpenSSL::X509::Certificate.load(_1) }
      raise "Fulcio certificates not found in trusted root" if certs.empty?

      certs
    end

    private

    def tlog_keys(tlogs)
      return enum_for(__method__, tlogs) unless block_given?

      tlogs.each do |key|
        next unless timerange_valid?(key.public_key.valid_for, allow_expired: false)

        key_bytes = key.public_key.raw_bytes
        yield key_bytes if key_bytes
      end
    end

    def ca_keys(certificate_authorities, allow_expired:)
      return enum_for(__method__, certificate_authorities, allow_expired: allow_expired) unless block_given?

      certificate_authorities.each do |ca|
        next unless timerange_valid?(ca.valid_for, allow_expired: allow_expired)

        ca.cert_chain.certificates.each do |cert|
          yield cert.raw_bytes
        end
      end
    end

    def timerange_valid?(period, allow_expired:)
      now = Time.now.utc
      return true unless period
      return false if now < period.start.to_time
      return true if allow_expired
      return false if period.end && now > period.end.to_time

      true
    end
  end
end
