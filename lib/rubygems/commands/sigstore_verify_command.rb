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
    class SigstoreVerifyCommand < Gem::Command
      include Sigstore::CommandOptions

      def initialize
        require "sigstore"
        require "sigstore/rekor/client"
        require "sigstore/trusted_root"
        require "sigstore/models"

        super("sigstore-verify", "Display the contents of the installed gems",
          rekor_url: Sigstore::Rekor::Client::DEFAULT_REKOR_URL)

        add_verify_command_options

        add_option("--signature SIG", "signature content or path or remote URL") do |sig, options|
          options[:signature] = sig
        end

        add_option("--certificate CERT",
                   "path to the public certificate. " \
                   "The certificate will be verified against the Fulcio roots if the " \
                   "--certificate-chain option is not passed.") do |key, options|
          options[:certificate] = key
        end

        add_option("--[no-]offline", "Do not fetch the latest timestamp from the Rekor server") do |offline, options|
          options[:offline] = offline
        end
      end

      def execute
        require "sigstore/verifier"
        require "sigstore/models"
        require "sigstore/policy"

        verifier, files_with_materials = collect_verification_state
        policy = Sigstore::Policy::Identity.new(
          identity: options[:certificate_identity],
          issuer: options[:certificate_oidc_issuer]
        )

        verified = files_with_materials.all? do |file, input|
          result = verifier.verify(input: input, policy: policy, offline: options[:offline])

          if result.verified?
            say "OK: #{file}"
            true
          else
            say "FAIL: #{file}"
            say "\t#{result.reason}"
            false
          end
        end
        terminate_interaction 1 unless verified
      end

      private

      def collect_verification_state
        if (options[:certificate] || options[:signature] || options[:bundle]) && options[:args].size > 1
          raise Gem::CommandLineError, "Too many arguments"
        end

        if options[:bundle] && (options[:certificate] || options[:signature])
          raise Gem::CommandLineError, "Cannot specify both --bundle and --certificate or --signature"
        end

        options[:trusted_root] ||= Sigstore::TrustedRoot.production

        input_map = {}

        if options[:rekor_url] == Sigstore::Rekor::Client::STAGING_REKOR_URL
          verifier = Sigstore::Verifier.staging(trust_root: options[:trusted_root])
        elsif options[:rekor_url] == Sigstore::Rekor::Client::DEFAULT_REKOR_URL
          verifier = Sigstore::Verifier.production(trust_root: options[:trusted_root])
        end

        all_materials = []

        options[:args].each do |file|
          raise Gem::CommandLineError, "File not found: #{file}" unless File.exist?(file)

          sig = options[:signature]
          cert = options[:certificate]
          bundle = options[:bundle]

          directory = File.dirname(file)

          sig ||= File.join(directory, "#{file}.sig")
          cert ||= File.join(directory, "#{file}.cert")
          bundle = File.join(directory, "#{file}.sigstore.json") if bundle.nil?

          missing = []

          if options[:signature] || options[:certificate]
            missing << sig unless File.exist?(sig)
            missing << cert unless File.exist?(cert)
            input_map[file] = { cert: cert, sig: sig }
          else
            missing << bundle unless File.exist?(bundle)
            input_map[file] = { bundle: bundle }
          end

          raise Gem::CommandLineError, "Missing files: #{missing.join(", ")}" if missing.any?
        end

        input_map.each do |file, inputs|
          artifact = Sigstore::Verification::V1::Artifact.new
          artifact.artifact = File.binread(file)

          verification_input = Sigstore::Verification::V1::Input.new
          verification_input.artifact = artifact

          if inputs[:bundle]
            bundle_bytes = Gem.read_binary(inputs[:bundle])
            verification_input.bundle = Sigstore::Bundle::V1::Bundle.decode_json(bundle_bytes,
                                                                                 registry: Sigstore::REGISTRY)
          else
            cert_pem = Gem.read_binary(inputs[:cert])
            b64_sig = Gem.read_binary(inputs[:sig])
            signature = b64_sig.unpack1("m")

            verification_input.bundle = Sigstore::SBundle.for_cert_bytes_and_signature(cert_pem, signature)
          end

          say "Verifying #{file}..."
          all_materials << [file, Sigstore::VerificationInput.new(verification_input)]
        end

        [verifier, all_materials]
      end
    end
  end
end
