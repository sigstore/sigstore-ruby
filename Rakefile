# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"]
end

require "rubocop/rake_task"

RuboCop::RakeTask.new

task default: %i[test conformance rubocop]

desc "Run the conformance tests"
task conformance: %w[conformance:setup] do
  sh({ "GHA_SIGSTORE_CONFORMANCE_XFAIL" =>
       "test_verify_trust_root_with_invalid_ct_keys test_verify_dsse_bundle_with_trust_root" },
     File.expand_path("test/sigstore-conformance/env/bin/pytest"), "test",
     "--entrypoint=#{File.join(__dir__, "bin", "conformance-entrypoint")}", "--skip-signing",
     chdir: "test/sigstore-conformance")
end

namespace :conformance do
  file "test/sigstore-conformance/.git/config" do
    rm_rf "test/sigstore-conformance"
    sh "git", "clone", "https://github.com/sigstore/sigstore-conformance", chdir: "test"
  end
  file "test/sigstore-conformance/.git/HEAD" => %w[test/sigstore-conformance/.git/config] do
    sh "git", "checkout", "main", chdir: "test/sigstore-conformance"
  end
  file "test/sigstore-conformance/.git/rake-version" => %w[test/sigstore-conformance/.git/HEAD] do
    sh "git", "describe", "--tags", "--always", chdir: "test/sigstore-conformance",
                                                out: "test/sigstore-conformance/.git/rake-version"
  end
  file "test/sigstore-conformance/env/pyvenv.cfg" => "test/sigstore-conformance/.git/rake-version" do
    sh "make", "dev", chdir: "test/sigstore-conformance"
  end
  task setup: "test/sigstore-conformance/env/pyvenv.cfg" # rubocop:disable Rake/Desc
end

task test: %w[test/sigstore-conformance/.git/rake-version]
