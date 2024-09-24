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

require "rubygems/command"
require_relative "../../sigstore/command_options"

module Gem
  module Commands
    class SigstoreSignBundleCommand < Gem::Command
      include Sigstore::CommandOptions

      def initialize
        require "sigstore"
        require "sigstore/rekor/client"
        require "sigstore/trusted_root"
        require "sigstore/signer"

        super("sigstore-sign", "Sign an artifact with sigstore",
          rekor_url: Sigstore::Rekor::Client::DEFAULT_REKOR_URL)

        add_option("--staging") do |_, options|
          options[:trusted_root] = Sigstore::TrustedRoot.staging
        end

        add_option("--identity-token TOKEN", "id token") do |token, options|
          options[:identity_token] = token
        end

        add_option("--bundle PATH") do |bundle, options|
          options[:bundle] = bundle
        end
      end

      def execute
        raise Gem::CommandLineError, "must provide one artifact to sign" if options[:args].size != 1

        options[:trusted_root] ||= Sigstore::TrustedRoot.production

        contents = File.binread(options[:args].first)
        bundle = Sigstore::Signer.new(
          jwt: options[:identity_token],
          trusted_root: options[:trusted_root]
        ).sign(contents)

        File.binwrite(options[:bundle], bundle.to_json)
      end
    end
  end
end
