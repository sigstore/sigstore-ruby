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
    class SigstoreSignCommand < Gem::Command
      include Sigstore::CommandOptions

      def initialize
        require "sigstore"
        require "sigstore/rekor/client"
        require "sigstore/trusted_root"
        require "sigstore/signer"

        super("sigstore-sign", "Sign an artifact with sigstore",
          rekor_url: Sigstore::Rekor::Client::DEFAULT_REKOR_URL)

        add_option("--identity-token TOKEN", "id token") do |token, options|
          options[:identity_token] = token
        end

        add_option("--signature SIG", "signature path") do |sig, options|
          options[:signature] = sig
        end

        add_option("--certificate CERT",
                   "path to the public certificate. " \
                   "The certificate will be verified against the Fulcio roots if the " \
                   "--certificate-chain option is not passed.") do |key, options|
          options[:certificate] = key
        end

        add_option("--staging") do |_, options|
          options[:trusted_root] = Sigstore::TrustedRoot.staging
        end

        add_option("--trusted-root ROOT", "path to the trusted root certificate") do |root, options|
          options[:trusted_root] = Sigstore::TrustedRoot.from_file(root)
        end

        # add_option("--rekor-url URL", "URL of the Rekor server") do |url, options|
        #   options[:rekor_url] = url
        # end

        # add_option("--[no-]offline", "Do not fetch the latest timestamp from the Rekor server") do |offline, options|
        #   options[:offline] = offline
        # end
      end

      def execute
        raise Gem::CommandLineError, "must provide one artifact to sign" if options[:args].size != 1

        options[:trusted_root] ||= Sigstore::TrustedRoot.production

        sig, leaf, = Sigstore::Signer.new(
          jwt: options[:identity_token],
          trusted_root: options[:trusted_root]
        ).sign(File.binread(options[:args].first))
        File.binwrite(options[:signature], [sig].pack("m0"))
        File.binwrite(options[:certificate], leaf.to_pem)
      end
    end
  end
end
