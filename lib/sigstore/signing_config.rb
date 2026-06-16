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

require "json"
require "time"

require_relative "error"

module Sigstore
  # Parses a SigningConfig (signingconfig.v0.2) document and selects the
  # services (Fulcio CA, OIDC provider, Rekor transparency log, Timestamping
  # Authority) a client should use to sign.
  #
  # The protobuf-specs gem does not yet ship the v0.2 SigningConfig message
  # (only the obsolete v0.1 flat-URL form), so this parses the JSON directly.
  # The service-selection algorithm mirrors sigstore-python's
  # SigningConfig._get_valid_services: per kind, keep services whose major API
  # version is supported and whose validity window covers now, collapse to one
  # service per operator (highest supported version), then apply the
  # ServiceConfiguration selector (ANY/EXACT/ALL).
  class SigningConfig
    MEDIA_TYPE = "application/vnd.dev.sigstore.signingconfig.v0.2+json"

    REKOR_VERSIONS = [1, 2].freeze
    TSA_VERSIONS = [1].freeze
    FULCIO_VERSIONS = [1].freeze
    OIDC_VERSIONS = [1].freeze

    Service = Struct.new(:url, :major_api_version, :valid_for, :operator)

    def self.from_file(path)
      from_json(Gem.read_binary(path))
    end

    def self.from_json(contents)
      new(JSON.parse(contents))
    end

    def initialize(raw)
      media_type = raw["mediaType"]
      unless media_type == MEDIA_TYPE
        raise Error::InvalidSigningConfig, "unsupported signing config format: #{media_type.inspect}"
      end

      @fulcios = select_services(raw["caUrls"], FULCIO_VERSIONS, nil)
      raise Error::InvalidSigningConfig, "No valid Fulcio CA found in signing config" if @fulcios.empty?

      @oidcs = select_services(raw["oidcUrls"], OIDC_VERSIONS, nil)

      @tlogs = select_services(raw["rekorTlogUrls"], REKOR_VERSIONS, raw["rekorTlogConfig"])
      raise Error::InvalidSigningConfig, "No valid Rekor transparency log found in signing config" if @tlogs.empty?

      @tsas = select_services(raw["tsaUrls"], TSA_VERSIONS, raw["tsaConfig"])
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
      services = parse_services(services)

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

      selector = config && config["selector"]
      return result if selector.nil? || selector == "ALL"

      if selector == "EXACT"
        count = exact_count(config)
        # EXACT means exactly `count` services must remain after filtering and
        # per-operator collapsing; neither too few nor too many is acceptable.
        unless result.size == count
          raise Error::InvalidSigningConfig, "Expected #{count} services in signing config, found #{result.size}"
        end

        return result
      end

      result.first(1)
    end

    def exact_count(config)
      Integer(config["count"])
    rescue TypeError, ArgumentError
      raise Error::InvalidSigningConfig,
            "EXACT selector requires an integer count, got #{config["count"].inspect}"
    end

    def parse_services(services)
      Array(services).map do |service|
        valid_for = service["validFor"]
        Service.new(
          url: service.fetch("url"),
          major_api_version: service["majorApiVersion"] || 0,
          valid_for: valid_for && {
            start: valid_for["start"] && Time.iso8601(valid_for["start"]),
            end: valid_for["end"] && Time.iso8601(valid_for["end"])
          },
          operator: service["operator"] || ""
        )
      end
    end

    def timerange_valid?(period)
      return true unless period

      now = Time.now.utc
      return false if period[:start] && now < period[:start]
      return false if period[:end] && now > period[:end]

      true
    end
  end
end
