# frozen_string_literal: true

require "rubygems/command"
require_relative "../../sigstore/cosign/verify/command_options"

module Gem
  module Commands
    class SigstoreCosignVerifyCommand < Gem::Command
      include Sigstore::Cosign::Verify::CommandOptions

      def initialize
        require "sigstore/rekor/client"
        require "sigstore/trusted_root"

        super("sigstore-cosign-verify", "Display the contents of the installed gems",
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

        add_option("--rekor-url URL", "URL of the Rekor server") do |url, options|
          options[:rekor_url] = url
        end
      end

      def execute
        require "sigstore/cosign/verify/verifier"
        require "sigstore/cosign/verify/models"
        require "sigstore/cosign/verify/policy"

        verifier, files_with_materials = collect_verification_state
        policy = Sigstore::Cosign::Verify::Policy::Identity.new(
          identity: options[:certificate_identity],
          issuer: options[:certificate_oidc_issuer]
        )

        verified = files_with_materials.all? do |file, materials|
          result = verifier.verify(materials: materials, policy: policy)

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

        if options[:staging]
          verifier = Sigstore::Cosign::Verify::Verifier.staging(trust_root: options[:trusted_root])
        elsif options[:rekor_url] == Sigstore::Rekor::Client::DEFAULT_REKOR_URL
          verifier = Sigstore::Cosign::Verify::Verifier.production(trust_root: options[:trusted_root])
        else
          unless options[:certificate_chain]
            raise Gem::CommandLineError,
                  "Custom Rekor URL used without --certificate-chain"
          end

          cert_chain = load_pem_x509_certificates(File.read(options[:certificate_chain]))

          # TODO: rekor_root_pubkey

          verifier = Sigstore::Cosign::Verify::Verifier.new(
            rekor_client: Sigstore::Rekor::Client.new(
              url: options[:rekor_url],
              rekor_keyring: Sigstore::Internal::Keyring.new(keys: trust_root.rekor_keys),
              ct_keyring: Sigstore::Internal::Keyring.new(keys: trusted_root.ctfe_keys)
            ),
            fulcio_cert_chain: cert_chain
          )
        end

        all_materials = []

        options[:args].each do |file|
          raise Gem::CommandLineError, "File not found: #{file}" unless File.exist?(file)

          sig = options[:signature]
          cert = options[:certificate]
          bundle = options[:bundle]

          sig ||= File.dirname(file) + "/#{file}.sig"
          cert ||= File.dirname(file) + "/#{file}.cert"

          bundle = File.dirname(file) + "/#{file}.sigstore.json" if bundle.nil?

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
          rekor_entry = nil
          materials = File.open(file, "rb") do |input|
            if inputs[:bundle]
              bundle_bytes = Gem.read_binary(inputs[:bundle])
              bundle = Sigstore::Bundle::V1::Bundle.decode_json(bundle_bytes)

              Sigstore::Cosign::Verify::VerificationMaterials.from_bundle(input: input, bundle: bundle,
                                                                          offline: options[:offline])
            else
              cert_pem = Gem.read_binary(inputs[:cert])
              b64_sig = Gem.read_binary(inputs[:sig])
              signature = b64_sig.unpack1("m")

              Sigstore::Cosign::Verify::VerificationMaterials.new(
                input: input,
                cert_pem: cert_pem,
                signature: signature, rekor_entry: rekor_entry,
                offline: options[:offline]
              )
            end
          end

          say "Verifying #{file}..."
          all_materials << [file, materials]
        end

        [verifier, all_materials]
      end
    end
  end
end
