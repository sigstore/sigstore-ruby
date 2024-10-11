#!/usr/bin/env ruby
# frozen_string_literal: true

ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)
require "bundler/setup"

require "json"
require "rake"
require "base64"
require "tmpdir"
require "uri"
require "digest"
require "pathname"
require "xdg"
require "literal"
require "sigstore"
require "sigstore/cedar"

include FileUtils # rubocop:disable Style/MixinUsage

chdir Dir.mktmpdir

mkdir_p ["index"]

sh "curl", "--fail", "--silent", "http://localhost:8000/targets/trusted_root.json", "-o", "trusted_root.json"

def id_token(**claims)
  claims.merge!(iss: "http://foo.com", aud: "sigstore", sub: "http://github.com/foo/workflow.yml@refs/heads/main",
                iat: 0, exp: 9_999_999_999, nbf: 0)
  claims[:email] = claims[:sub]

  [
    "",
    JSON.dump(claims),
    ""
  ].map { Base64.strict_encode64(_1).chomp }.join(".")
end

def publish(name, version)
  artifact = JSON.dump(name:, version:)
  full_name = URI.encode_www_form({ name:, version: })
  index = begin
    JSON.parse File.read("index.json")
  rescue Errno::ENOENT
    []
  end
  index << { name:, version:, full_name:, sha256: Digest::SHA256.hexdigest(artifact) }
  File.write "index.json", JSON.dump(index)
  File.write "index/#{full_name}", artifact
  sign("index/#{full_name}", bundle: "index/#{full_name}.sigstore.jsonl")
end

def sign(file, bundle:, **kwargs)
  sh "/Users/segiddins/Development/github.com/sigstore/sigstore-ruby/bin/sigstore-ruby", "sign",
     "--trusted-root", "trusted_root.json", "--identity-token=#{id_token(**kwargs)}", "--bundle=#{bundle}",
     file
end

publish "rails", "1.0"

module PolicyConstraint
  def self.from_json(constraint)
    Literal.check(actual: constraint, expected: Hash)
    keys = constraint.keys
    if keys == ["all"]
      all = constraint["all"]
      Literal.check(actual: all, expected: Array)
      AllOf.new(all.map { from_json(_1) })
    else
      ID.new(**constraint)
    end
  end
end

class ID < Literal::Struct
  include PolicyConstraint
  prop :matchers, _Hash(
    _Union(String), _Union(String, Integer)
  ), :**
end

class AllOf < Literal::Struct
  include PolicyConstraint
  prop :of, _Array(PolicyConstraint), :positional
end

class AtLeast < Literal::Struct
  include PolicyConstraint
  prop :count, Integer, :positional, default: 1
  prop :of, _Array(PolicyConstraint)
end

class Policy < Literal::Struct
  prop :name, String
  prop :min, _String?
  prop :max, _String?
  prop :source, _String?
  prop :platform, _String?
  prop :expected, _Array(PolicyConstraint)

  def self.from_json(json)
    new(
      name: json["name"],
      min: json["min"],
      max: json["max"],
      expected: json["expected"].map do |constraint|
        PolicyConstraint.from_json(constraint)
      end
    )
  end
end

require "yaml"
pp Policy.from_json(YAML.load(<<~YAML).dig("rubygems", 0))
  rubygems:
    - name: rails
      min: 0.0.0
      max: 7.0.0
      source: "https://rubygems.org"
      expected:
        - issuer: "https://token.actions.githubusercontent.com"
        - all:
          - Issuer: "https://token.actions.githubusercontent.com"
            Build Config Digest: "sha256:1234"
YAML

class Installer
  attr_reader :home, :dir

  def initialize(machine, project, requirements = {})
    @machine = machine
    @project = project
    @requirements = requirements

    @dir = Pathname("projects") / @project
    @home = Pathname(@machine).join("home")
    [@dir, @home].each(&:mkpath)
    @xdg = XDG::Environment.new(environment: { "HOME" => @home.to_s })
  end

  def self.call(...)
    new(...).call
  end

  def call
    installed = install(resolve)
    lock(installed)
  end

  def resolve
    index = JSON.parse File.read("index.json")
    index.select! do |artifact|
      @requirements[artifact["name"]] == artifact["version"]
    end

    raise StandardError, "Missing artifacts" unless index.size == @requirements.size

    index
  end

  def install(resolve)
    # 1) check if existing signatures satisfy the policy
    # 2) if not, download the signatures and verify it
    # 2) download artifact if missing from the cache, verifying checksum
    # 3) copy artifact to the project's directory

    resolve.map do |artifact|
      signatures = JSON.parse File.read("index/#{artifact["full_name"]}.sigstore.jsonl")
      { artifact:, attestations: [signatures] }
    end

    # policy_set = Sigstore::Cedar::PolicySet.parse <<~CEDAR
    #   @Foo("bar")
    #   permit (
    #     principal,
    #     action,
    #     resource in package::"name=rails"
    #   )
    #   when { resource }
    #   // when { resource.version.greaterThanOrEqual(gem_version("1.0")) }
    #   // when { resource.version.lessThan(gem_version("2.0")) }
    #     ;
    # CEDAR
    # entities = Sigstore::Cedar::Authorizer::Entities.new(packages.map do |pkg|
    #   parents = pkg[:attestations].flat_map do |a|
    #     pp a
    #   end
    #   Sigstore::Cedar::Entity.new(
    #     uid: Sigstore::Cedar::Entity::UID.new(type: "package", id: pkg[:artifact]["full_name"]),
    #     parents: [
    #       Sigstore::Cedar::Entity::UID.new(type: "package", id: "name=#{pkg[:artifact].fetch("name")}"),
    #       Sigstore::Cedar::Entity::UID.new(type: "sigstore::issuer", id: "https://token.actions.githubusercontent.com")
    #     ],
    #     attrs: {}
    #   )
    # end)
    # authorizer = Sigstore::Cedar::Authorizer.new(policy_set:, entities:)

    # unverified = packages.reject do |package|
    #   resp.verb == "allow"
    # end
    # # pp authorizer
    # # pp unverified
  end

  def signatures_path(artifact)
    purl = "pkg:demo/#{artifact["name"]}"
    @xdg.state_home / "signatures" / "#{URI.encode_uri_component(purl)}.jsonl"
  end

  def lock(installed)
    File.write dir / "requirements.json", JSON.dump(@requirements)
    File.write dir / "requirements.lock.json", JSON.dump(installed.map do |i|
      i[:artifact]
    end)
  end
end

Installer.call("machine_1", "a", { "rails" => "1.0" })

# sh "code", "."
