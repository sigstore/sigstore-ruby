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

desc "Run the conformance tests"
task conformance: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" =>
       "test_verify_dsse_bundle_with_trust_root" },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}", "--skip-signing",
     chdir: "test/sigstore-conformance")
end

desc "Run the conformance tests against staging"
task conformance_staging: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" =>
       "test_verify_dsse_bundle_with_trust_root" },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}", "--skip-signing",
     "--staging",
     chdir: "test/sigstore-conformance")
end

desc "Run the TUF conformance tests"
task conformance_tuf: %w[tuf_conformance:setup] do
  sh("test/tuf-conformance/env/bin/tuf-conformance", "bin/tuf-conformance-entrypoint")
end

namespace :conformance do
  file "test/sigstore-conformance/env/pyvenv.cfg" => :sigstore_conformance do
    sh "make", "dev", chdir: "test/sigstore-conformance"
  end
  task setup: "test/sigstore-conformance/env/pyvenv.cfg" # rubocop:disable Rake/Desc
end

task test: %w[sigstore_conformance]

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

    desired, status = Open3.capture2(*%w[git rev-parse], "#{commit}^{commit}", chdir: path)
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
        sh "git", "-C", path, "fetch", "origin", commit
        sh "git", "-C", path, "switch", "--detach", commit
      end
    end
  end
end

GitRepo.define_task(:sigstore_conformance).tap do |task|
  task.path = "test/sigstore-conformance"
  task.url = "https://github.com/sigstore/sigstore-conformance.git"
  task.commit = "0a0196b"
end

GitRepo.define_task(:tuf_conformance).tap do |task|
  task.path = "test/tuf-conformance"
  task.url = "https://github.com/jku/tuf-conformance.git"
  task.commit = "3072fdb346ce27210e5125b30c6626a9f6b34fc0"
end

namespace :tuf_conformance do
  file "test/tuf-conformance/env/pyvenv.cfg" => :tuf_conformance do
    sh "make", "dev", chdir: "test/tuf-conformance"
  end
  task setup: "test/tuf-conformance/env/pyvenv.cfg" # rubocop:disable Rake/Desc
end
