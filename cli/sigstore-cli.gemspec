# frozen_string_literal: true

require_relative "../lib/sigstore/version"

Gem::Specification.new do |spec|
  spec.name = "sigstore-cli"
  spec.version = Sigstore::VERSION
  spec.authors = ["The Sigstore Authors", "Samuel Giddins"]
  spec.email = [nil, "segiddins@segiddins.me"]

  spec.summary = "A CLI interface to the sigstore ruby client"
  spec.homepage = "https://github.com/sigstore/sigstore-ruby"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = IO.popen(["git", "-C", __dir__, "ls-files", "-z"], &:read).split("\x0").reject do |f|
    (File.expand_path(f) == __FILE__) ||
      f.start_with?(*%w[bin/ test/ spec/ features/ fixtures/ . Rakefile Gemfile])
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "sigstore", spec.version
  spec.add_dependency "thor"

  spec.metadata["rubygems_mfa_required"] = "true"
end
