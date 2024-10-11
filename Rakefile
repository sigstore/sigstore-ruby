# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"

directory "pkg"
namespace "cli" do
  Bundler::GemHelper.install_tasks(dir: "cli")
  task build: "pkg" do # rubocop:disable Rake/Desc
    FileUtils.cp_r FileList["cli/pkg/*"], "pkg"
  end
end
task "build" => "cli:build" # rubocop:disable Rake/Desc

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"]
end

require "rubocop/rake_task"

RuboCop::RakeTask.new

task default: %i[test conformance_staging conformance conformance_tuf rubocop]

require "openssl"
# Checks for https://github.com/ruby/openssl/pull/770
xfail = OpenSSL::X509::Store.new.instance_variable_defined?(:@time) ? "test_verify_rejects_bad_tsa_timestamp" : ""

desc "Run the conformance tests"
task conformance: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" => xfail },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}",
     chdir: "test/sigstore-conformance")
end

desc "Run the conformance tests against staging"
task conformance_staging: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" => xfail },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}",
     "--staging",
     chdir: "test/sigstore-conformance")
end

desc "Run the TUF conformance tests"
task conformance_tuf: %w[tuf_conformance:setup] do
  sh("env/bin/pytest", "tuf_conformance", "--entrypoint", File.expand_path("bin/tuf-conformance-entrypoint"),
     chdir: "test/tuf-conformance")
end

namespace :conformance do
  file "test/sigstore-conformance/env/pyvenv.cfg" => :sigstore_conformance do
    sh "make", "dev", chdir: "test/sigstore-conformance"
  end
  task setup: "test/sigstore-conformance/env/pyvenv.cfg" # rubocop:disable Rake/Desc
end

task :find_action_versions do # rubocop:disable Rake/Desc
  require "yaml"
  gh = YAML.load_file(".github/workflows/ci.yml")
  actions = gh.fetch("jobs").flat_map { |_, job| job.fetch("steps", []).filter_map { |step| step.fetch("uses", nil) } }
              .uniq.map { |x| x.split("@", 2) }
              .group_by(&:first).transform_values { |v| v.map(&:last) }
  if actions.any? { |_, v| v.size > 1 }
    raise StandardError, "conflicts: #{actions.select { |_, v| v.size > 1 }.inspect}"
  end

  @action_versions = actions.transform_values(&:first)
end

task test: %w[sigstore_conformance cedar_integration_tests]

desc "Update the vendored data files"
task :update_data do
  require "sigstore"
  require "sigstore/trusted_root"
  {
    prod: Sigstore::TUF::DEFAULT_TUF_URL,
    staging: Sigstore::TUF::STAGING_TUF_URL
  }.each do |name, url|
    Dir.mktmpdir do |dir|
      updater = Sigstore::TUF::TrustUpdater.new(url, false, metadata_dir: dir, targets_dir: dir).updater
      updater.refresh
      updater.download_target(updater.get_targetinfo("trusted_root.json"))
      cp File.join(dir, "trusted_root.json"), "data/_store/#{name}/trusted_root.json"
      cp File.join(dir, "root.json"), "data/_store/#{name}/root.json"
    end
  end
end

require "open3"

class GitRepo < Rake::Task
  attr_accessor :path, :url
  attr_writer :commit

  include FileUtils

  def initialize(*)
    super

    @actions << method(:clone_repo)
    @actions << method(:checkout)
  end

  def needed?
    !correct_remote? || !correct_commit?
  end

  def correct_remote?
    return false unless File.directory?(@path)

    out, status = Open3.capture2(*%w[git remote get-url origin], chdir: path)
    status.success? && out.strip == url
  end

  def correct_commit?
    head, status = Open3.capture2(*%w[git rev-parse HEAD], chdir: path)
    head.strip!
    return true if status.success? && head == commit

    desired, status = Open3.capture2(*%w[git rev-parse], "#{commit}^{commit}", "--", chdir: path)
    desired.strip!
    status.success? && desired == head
  end

  def clone_repo(_, _)
    return if correct_remote?

    rm_rf path
    sh "git", "clone", url, path
  end

  def checkout(_, _)
    return if correct_commit?

    sh "git", "-C", path, "switch", "--detach", commit do |ok, _|
      unless ok
        sh "git", "-C", path, "fetch", "origin", "#{commit}:#{commit}"
        sh "git", "-C", path, "switch", "--detach", commit
      end
    end
  end

  def commit
    case @commit
    when String
      @commit
    when ->(c) { c.respond_to?(:call) }
      @commit.call
    else
      raise StandardError, "unexpected commit type: #{@commit.inspect}"
    end
  end
end

GitRepo.define_task(sigstore_conformance: %w[find_action_versions]).tap do |task|
  task.path = "test/sigstore-conformance"
  task.url = "https://github.com/sigstore/sigstore-conformance.git"
  task.commit = -> { @action_versions.fetch("sigstore/sigstore-conformance") }
end

GitRepo.define_task(tuf_conformance: %w[find_action_versions]).tap do |task|
  task.path = "test/tuf-conformance"
  task.url = "https://github.com/theupdateframework/tuf-conformance.git"
  task.commit = -> { @action_versions.fetch("theupdateframework/tuf-conformance") }
end

GitRepo.define_task(cedar_integration_tests: []).tap do |task|
  task.path = "test/cedar-integration-tests"
  task.url = "https://github.com/cedar-policy/cedar-integration-tests.git"
  task.commit = "3903b933e29fd60f2c40d779b250cd4ffb150f5d"
end

namespace :tuf_conformance do
  file "test/tuf-conformance/env/pyvenv.cfg" => :tuf_conformance do
    sh "make", "dev", chdir: "test/tuf-conformance"
  end
  task setup: "test/tuf-conformance/env/pyvenv.cfg" # rubocop:disable Rake/Desc
end
