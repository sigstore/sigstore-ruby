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

        add_option("--identity-token TOKEN", "id token") do |token, options|
          options[:identity_token] = token
        end

        add_option("--bundle PATH") do |bundle, options|
          options[:bundle] = bundle
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

        contents = File.binread(options[:args].first)
        sig, _, result = Sigstore::Signer.new(
          jwt: options[:identity_token],
          trusted_root: options[:trusted_root]
        ).sign(contents)

        bundle = Sigstore::Bundle::V1::Bundle.new
        bundle.media_type = "application/vnd.dev.sigstore.bundle.v0.3+json"
        bundle.verification_material = result
        # for a 0.3 bundle
        bundle.verification_material.certificate =
          bundle.verification_material.x509_certificate_chain.certificates.first
        bundle.message_signature = Sigstore::Common::V1::MessageSignature.new.tap do |ms|
          ms.message_digest = Sigstore::Common::V1::HashOutput.new
          ms.message_digest.algorithm = Sigstore::Common::V1::HashAlgorithm::SHA2_256
          ms.message_digest.digest = OpenSSL::Digest("SHA256").digest(contents)
          ms.signature = sig
        end

        File.binwrite(options[:bundle], bundle.to_json)
      end
    end
  end
end
