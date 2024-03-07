# frozen_string_literal: true

require_relative "lib/sigstore/cosign/verify/version"

Gem::Specification.new do |spec|
  spec.name = "sigstore-cosign-verify"
  spec.version = Sigstore::Cosign::Verify::VERSION
  spec.authors = ["Samuel Giddins"]
  spec.email = ["segiddins@segiddins.me"]

  spec.summary = "A pure-ruby implementation of the sigstore cosign verify command"
  spec.homepage = "https://github.com/segiddins/sigstore-cosign-verify"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "sigstore_protobuf_specs", "~> 0.3.0" # TODO: DELETE

  spec.metadata["rubygems_mfa_required"] = "true"
end
