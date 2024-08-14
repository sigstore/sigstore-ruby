# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"]
end

require "rubocop/rake_task"

RuboCop::RakeTask.new

task default: %i[test conformance conformance_staging conformance_tuf rubocop]

require "openssl"
# Checks for https://github.com/ruby/openssl/pull/770
xfail = OpenSSL::X509::Store.new.instance_variable_defined?(:@time) ? "test_verify_rejects_bad_tsa_timestamp" : ""

desc "Run the conformance tests"
task conformance: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" => xfail },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}", "--skip-signing",
     chdir: "test/sigstore-conformance")
end

desc "Run the conformance tests against staging"
task conformance_staging: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" => xfail },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}", "--skip-signing",
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

task test: %w[sigstore_conformance]

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
      updater.download_target(updater.get_targetinfo("trusted_root.json"))
      cp File.join(dir, "trusted_root.json"), "data/_store/#{name}/trusted_root.json"
      cp File.join(dir, "root.json"), "data/_store/#{name}/root.json"
    end
  end
end

require "open3"

class GitRepo < Rake::Task
  attr_accessor :path, :url, :commit

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
end

GitRepo.define_task(:sigstore_conformance).tap do |task|
  task.path = "test/sigstore-conformance"
  task.url = "https://github.com/sigstore/sigstore-conformance.git"
  task.commit = "52311dc3b1d7aba6fb2c4b468791fbb119e7f022"
end

GitRepo.define_task(:tuf_conformance).tap do |task|
  task.path = "test/tuf-conformance"
  task.url = "https://github.com/theupdateframework/tuf-conformance.git"
  task.commit = "refs/pull/149/head"
end

namespace :tuf_conformance do
  file "test/tuf-conformance/env/pyvenv.cfg" => :tuf_conformance do
    sh "make", "dev", chdir: "test/tuf-conformance"
  end
  task setup: "test/tuf-conformance/env/pyvenv.cfg" # rubocop:disable Rake/Desc
end
