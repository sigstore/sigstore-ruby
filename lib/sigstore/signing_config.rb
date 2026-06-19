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

require "protobug_sigstore_protos"

require_relative "error"

module Sigstore
  # Parses a SigningConfig (signingconfig.v0.2) document and selects the
  # services (Fulcio CA, OIDC provider, Rekor transparency log, Timestamping
  # Authority) a client should use to sign.
  #
  # The document is decoded through the protobuf-specs SigningConfig message
  # (shipped since protobug_sigstore_protos 0.2.0). The service-selection
  # algorithm mirrors sigstore-python's SigningConfig._get_valid_services: per
  # kind, keep services whose major API version is supported and whose validity
  # window covers now, collapse to one service per operator (highest supported
  # version), then apply the ServiceConfiguration selector (ANY/EXACT/ALL).
  class SigningConfig
    MEDIA_TYPE = "application/vnd.dev.sigstore.signingconfig.v0.2+json"

    REGISTRY = Protobug::Registry.new do |registry|
      Sigstore::TrustRoot::V1.register_sigstore_trustroot_protos(registry)
    end

    Selector = Sigstore::TrustRoot::V1::ServiceSelector

    REKOR_VERSIONS = [1, 2].freeze
    TSA_VERSIONS = [1].freeze
    FULCIO_VERSIONS = [1].freeze
    OIDC_VERSIONS = [1].freeze

    def self.from_file(path)
      from_json(Gem.read_binary(path))
    end

    def self.from_json(contents)
      new(Sigstore::TrustRoot::V1::SigningConfig.decode_json(contents, registry: REGISTRY))
    rescue Protobug::Error => e
      raise Error::InvalidSigningConfig, "invalid signing config: #{e.message}"
    end

    def initialize(config)
      unless config.media_type == MEDIA_TYPE
        raise Error::InvalidSigningConfig, "unsupported signing config format: #{config.media_type.inspect}"
      end

      @fulcios = select_services(config.ca_urls, FULCIO_VERSIONS, nil)
      raise Error::InvalidSigningConfig, "No valid Fulcio CA found in signing config" if @fulcios.empty?

      @oidcs = select_services(config.oidc_urls, OIDC_VERSIONS, nil)

      @tlogs = select_services(config.rekor_tlog_urls, REKOR_VERSIONS, config.rekor_tlog_config)
      raise Error::InvalidSigningConfig, "No valid Rekor transparency log found in signing config" if @tlogs.empty?

      @tsas = select_services(config.tsa_urls, TSA_VERSIONS, config.tsa_config)
    end

    # The Rekor transparency log to submit the signing metadata to.
    def tlog
      @tlogs.first
    end

    def fulcio
      @fulcios.first
    end

    def oidc_url
      @oidcs.first&.url
    end

    # The Timestamping Authority URLs to request RFC 3161 timestamps from.
    def tsa_urls
      @tsas.map(&:url)
    end

    private

    def select_services(services, supported_versions, config)
      by_operator = Hash.new { |h, k| h[k] = [] }
      services.each do |service|
        next unless supported_versions.include?(service.major_api_version)
        next unless timerange_valid?(service.valid_for)

        by_operator[service.operator] << service
      end

      # One service per operator, preferring the highest supported version.
      result = by_operator.values.map do |op_services|
        op_services.max_by(&:major_api_version)
      end

      # An absent ServiceConfiguration (or the ALL selector) imposes no count
      # constraint, so every per-operator service is returned.
      return result if config.nil? || config.selector == Selector::ALL

      if config.selector == Selector::EXACT
        count = config.count
        unless count.is_a?(Integer) && count.positive?
          raise Error::InvalidSigningConfig,
                "EXACT selector requires a positive integer count, got #{count.inspect}"
        end

        # EXACT means exactly `count` services must remain after filtering and
        # per-operator collapsing; neither too few nor too many is acceptable.
        unless result.size == count
          raise Error::InvalidSigningConfig, "Expected #{count} services in signing config, found #{result.size}"
        end

        return result
      end

      result.first(1)
    end

    def timerange_valid?(period)
      return true unless period

      now = Time.now.utc
      return false if period.start && now < period.start.to_time
      return false if period.end && now > period.end.to_time

      true
    end
  end
end
