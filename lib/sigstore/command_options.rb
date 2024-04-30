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

module Sigstore::CommandOptions
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
