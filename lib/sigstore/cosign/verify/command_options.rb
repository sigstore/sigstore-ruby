# frozen_string_literal: true

module Sigstore::Cosign::Verify::CommandOptions
  def add_verify_command_options
    add_option("--certificate-identity ID",
               "The identity to check for in the certificate's Subject Alternative Names") do |identity, options|
      options[:certificate_identity] = identity
    end

    add_option("--certificate-oidc-issuer ISSUER", "The OpenID Connect issuer to use") do |issuer, options|
      options[:certificate_oidc_issuer] = issuer
    end

    add_option("--trusted-root ROOT", "path to the trusted root certificate") do |root, options|
      options[:trusted_root] = Sigstore::TrustedRoot.from_file(root)
    end

    add_option "--bundle PATH", "Path to the signature bundle" do |value, options|
      options[:bundle] = value
    end
  end
end
