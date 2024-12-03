# frozen_string_literal: true

require "thor"
require "sigstore"

module Sigstore
  class CLI < Thor
    def self.exit_on_failure?
      true
    end

    def self.start(given_args = ARGV, config = {})
      super
    rescue Sigstore::Error => e
      raise if config[:debug] || ENV["THOR_DEBUG"] == "1"

      detailed_message = e.respond_to?(:detailed_message) ? e.detailed_message : e.message
      config[:shell].error(detailed_message)

      exit(false)
    end

    class ShellWrapper
      def initialize(shell)
        @shell = shell
      end

      def close
        @shell.close
      end

      def write(...)
        @shell.say(...)
      end
    end

    def initialize(*)
      super
      Sigstore.logger.reopen ShellWrapper.new(shell)
      Sigstore.logger.level = options[:debug] ? Logger::DEBUG : Logger::INFO
    end

    package_name "sigstore-cli"

    desc "verify FILE", "Verify a signature"
    option :staging, type: :boolean, desc: "Use the staging trusted root"
    option :signature, type: :string, desc: "Path to the signature file"
    option :certificate, type: :string, desc: "Path to the public certificate"
    option :certificate_identity, type: :string, desc: "The identity of the certificate"
    option :certificate_oidc_issuer, type: :string, desc: "The OIDC issuer of the certificate"
    option :offline, type: :boolean, desc: "Do not fetch the latest timestamp from the Rekor server"
    option :bundle, type: :string, desc: "Path to the signed bundle"
    option :trusted_root, type: :string, desc: "Path to the trusted root"
    option :update_trusted_root, type: :boolean, desc: "Update the trusted root", default: true
    exclusive :bundle, :signature
    exclusive :bundle, :certificate
    def verify(*files)
      verifier, files_with_materials = collect_verification_state(files)
      policy = Sigstore::Policy::Identity.new(
        identity: options[:certificate_identity],
        issuer: options[:certificate_oidc_issuer]
      )

      verified = files_with_materials.all? do |file, input|
        result = verifier.verify(input:, policy:, offline: options[:offline])

        if result.verified?
          say "OK: #{file}"
          true
        else
          say "FAIL: #{file}"
          say "\t#{result.reason}"
          false
        end
      end
      exit(false) unless verified
    end
    map "verify-bundle" => :verify

    desc "sign ARTIFACT", "Sign a file"
    option :staging, type: :boolean, desc: "Use the staging trusted root"
    option :identity_token, type: :string, desc: "Identity token to use for signing"
    option :bundle, type: :string, desc: "Path to write the signed bundle to"
    option :signature, type: :string, desc: "Path to write the signature to"
    option :certificate, type: :string, desc: "Path to the public certificate"
    option :trusted_root, type: :string, desc: "Path to the trusted root"
    option :update_trusted_root, type: :boolean, desc: "Update the trusted root", default: true
    def sign(file)
      self.options = options.merge(identity_token: IdToken.detect_credential).freeze if options[:identity_token].nil?
      unless options[:identity_token]
        raise Error::InvalidIdentityToken,
              "Failed to detect an ambient identity token, please provide one via --identity-token"
      end

      contents = File.binread(file)
      bundle = Sigstore::Signer.new(
        jwt: options[:identity_token],
        trusted_root:
      ).sign(contents)

      File.binwrite(options[:bundle], bundle.to_json) if options[:bundle]
      if options[:signature]
        File.binwrite(options[:signature], Internal::Util.base64_encode(bundle.message_signature.signature))
      end
      File.binwrite(options[:certificate], bundle.verification_material.certificate.raw_bytes) if options[:certificate]
    end
    map "sign-bundle" => :sign

    desc "display", "Display sigstore bundle(s)"
    def display(*files)
      files.each do |file|
        bundle_bytes = Gem.read_binary(file)
        bundle = SBundle.new Bundle::V1::Bundle.decode_json(bundle_bytes, registry: Sigstore::REGISTRY)

        say "--- Bundle #{file} ---"
        say "Media Type: #{bundle.media_type}"
        say bundle.leaf_certificate.to_text

        case bundle.content
        when :message_signature
          say "Signature over: #{bundle.message_signature.message_digest.algorithm} " \
              "#{Internal::Util.hex_encode bundle.message_signature.message_digest.digest}"
        when :dsse_envelope
          say bundle.dsse_envelope.payloadType
          say bundle.dsse_envelope.payload
        else raise Error::InvalidBundle, "expected either message_signature or dsse_envelope"
        end
      end
    end

    class TUF < Thor
      def self.exit_on_failure?
        true
      end

      desc "download-target TARGET...", "Download a target from a TUP repo"
      option :metadata_url, type: :string, desc: "URL to the metadata", required: true
      option :metadata_dir, type: :string, desc: "Directory to store the metadata", required: true
      option :targets_dir, type: :string, desc: "Directory to store the targets", required: true
      option :cached, type: :boolean, desc: "Return cached targets only"
      option :target_base_url, type: :string, desc: "Base URL for the targets"
      def download_target(*targets)
        trust_updater = Sigstore::TUF::TrustUpdater.new(
          options[:metadata_url], false,
          metadata_dir: options[:metadata_dir], targets_dir: options[:targets_dir],
          target_base_url: options[:target_base_url]
        )
        trust_updater.refresh

        targets.each do |target|
          target_info = trust_updater.updater.get_targetinfo(target)
          raise Sigstore::TUF::Error, "No such target: #{target}" unless target_info

          path = if @cached
                   trust_updater.updater.find_cached_target(target_info)
                 else
                   trust_updater.updater.download_target(target_info)
                 end
          say "Downloaded #{target} to #{path}"
        end
      end

      desc "init ROOT", "Initialize a TUF repo"
      option :metadata_dir, type: :string, desc: "Directory to store the metadata", required: true
      def init(root)
        FileUtils.mkdir_p(options[:metadata_dir])
        FileUtils.cp(root, File.join(options[:metadata_dir], "root.json"))
      end

      desc "refresh", "Refresh the metadata"
      option :metadata_url, type: :string, desc: "URL to the metadata", required: true
      option :metadata_dir, type: :string, desc: "Directory to store the metadata", required: true
      def refresh
        Sigstore::TUF::TrustUpdater.new(
          options[:metadata_url], false,
          metadata_dir: options[:metadata_dir]
        ).refresh
      end
    end

    register TUF, "tuf", "tuf SUBCOMMAND", "TUF commands"

    private

    def trusted_root
      return Sigstore::TrustedRoot.from_file(options[:trusted_root]) if options[:trusted_root]

      if options[:staging]
        Sigstore::TrustedRoot.staging(offline: !options[:update_trusted_root])
      else
        Sigstore::TrustedRoot.production(offline: !options[:update_trusted_root])
      end
    end

    def collect_verification_state(files)
      if (options[:certificate] || options[:signature] || options[:bundle]) && files.size > 1
        raise Thor::InvocationError, "Too many files specified: #{files.inspect}"
      end

      if options[:bundle] && (options[:certificate] || options[:signature])
        raise Thor::InvocationError, "Cannot specify both --bundle and --certificate or --signature"
      end

      input_map = {}

      verifier = Sigstore::Verifier.for_trust_root(trust_root: trusted_root)

      all_materials = []

      files.each do |file|
        raise Thor::InvocationError, "File not found: #{file}" unless File.exist?(file) || file.start_with?("sha256:")

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
          input_map[file] = { cert:, sig: }
        else
          missing << bundle unless File.exist?(bundle)
          input_map[file] = { bundle: }
        end

        raise Thor::InvocationError, "Missing files: #{missing.join(", ")}" if missing.any?
      end

      input_map.each do |file, inputs|
        artifact = Sigstore::Verification::V1::Artifact.new
        case file
        when /\Asha256:/
          artifact.artifact_uri = file
        else
          artifact.artifact = File.binread(file)
        end

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

          verification_input.bundle = Sigstore::SBundle.for_cert_bytes_and_signature(cert_pem, signature).__getobj__
        end

        say "Verifying #{file}..."
        all_materials << [file, Sigstore::VerificationInput.new(verification_input)]
      end

      [verifier, all_materials]
    end
  end
end

require "sigstore/cli/id_token"
