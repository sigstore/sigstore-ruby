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

require "delegate"
require "openssl"

require "protobug_sigstore_protos"

require_relative "tuf"

module Sigstore
  REGISTRY = Protobug::Registry.new do |registry|
    Sigstore::TrustRoot::V1.register_sigstore_trustroot_protos(registry)
    Sigstore::Bundle::V1.register_sigstore_bundle_protos(registry)
  end
  class TrustedRoot < DelegateClass(Sigstore::TrustRoot::V1::TrustedRoot)
    def self.production(offline: false)
      from_tuf(TUF::DEFAULT_TUF_URL, offline)
    end

    def self.staging(offline: false)
      from_tuf(TUF::STAGING_TUF_URL, offline)
    end

    def self.from_tuf(url, offline)
      path = TUF::TrustUpdater.new(url, offline).trusted_root_path
      from_file(path)
    end

    def self.from_file(path)
      contents = Gem.read_binary(path)
      new Sigstore::TrustRoot::V1::TrustedRoot.decode_json(contents, registry: REGISTRY)
    end

    def rekor_keys
      keys = tlog_keys(tlogs).to_a
      raise "Did not find one Rekor key" if keys.size != 1

      keys
    end

    def ctfe_keys
      keys = tlog_keys(ctlogs).to_a
      raise "Did not find any CTFE keys" if keys.empty?

      keys
    end

    def fulcio_cert_chain
      certs = ca_keys(certificate_authorities, allow_expired: true).flat_map do |raw_bytes|
        Internal::X509::Certificate.read(raw_bytes)
      end
      raise "Fulcio certificates not found in trusted root" if certs.empty?

      certs
    end

    def tlogs_for_signing
      tlogs.select do |ctlog|
        timerange_valid?(ctlog.public_key.valid_for, allow_expired: false)
      end
    end

    def certificate_authority_for_signing
      certificate_authorities.find do |ca|
        timerange_valid?(ca.valid_for, allow_expired: false)
      end
    end

    private

    # TODO: why not return the whole Sigstore::TrustRoot::V1::TransparencyLogInstance ?
    # it has the log id, hash algorithm, public key, and validity range
    def tlog_keys(tlogs)
      return enum_for(__method__, tlogs) unless block_given?

      tlogs.each do |transparency_log_instance|
        key = transparency_log_instance.public_key
        yield Internal::Key.from_key_details(key.key_details, key.raw_bytes)
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
