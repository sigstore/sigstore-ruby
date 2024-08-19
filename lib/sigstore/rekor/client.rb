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

require "net/http"
require_relative "../transparency"
require_relative "../internal/keyring"

module Sigstore
  module Rekor
    class Client
      DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

      attr_reader :rekor_keyring, :ct_keyring

      def initialize(url:, rekor_keyring:, ct_keyring:)
        @url = URI.join(url, "api/v1/")
        @rekor_keyring = rekor_keyring
        @ct_keyring = ct_keyring

        net = defined?(Gem::Net) ? Gem::Net : Net
        @session = net::HTTP.new(@url.host, @url.port)
        @session.use_ssl = true
      end

      def self.production(trust_root:)
        new(
          url: DEFAULT_REKOR_URL,
          rekor_keyring: Internal::Keyring.new(keys: trust_root.rekor_keys),
          ct_keyring: Internal::Keyring.new(keys: trust_root.ctfe_keys)
        )
      end

      def log
        Log.new(URI.join(@url, "log/"), session: @session)
      end
    end

    class Log
      def initialize(url, session:)
        @url = url
        @session = session
      end

      def entries
        Entries.new(URI.join(@url, "entries/"), session: @session)
      end
    end

    class Entries
      def initialize(url, session:)
        @url = url
        @session = session
      end

      def retrieve
        Retrieve.new(URI.join(@url, "retrieve/"), session: @session)
      end

      class Retrieve
        def initialize(url, session:)
          @url = url
          @session = session
        end

        def post(expected_entry)
          data = { entries: [expected_entry] }
          resp = @session.post2(@url.path, data.to_json,
                                { "Content-Type" => "application/json", "Accept" => "application/json" })
          resp.value # TODO: rescue 404

          results = JSON.parse(resp.body)

          results.map do |result|
            Transparency::LogEntry.from_response(result)
          end.min_by(&:integrated_time)
        end
      end
    end
  end
end
