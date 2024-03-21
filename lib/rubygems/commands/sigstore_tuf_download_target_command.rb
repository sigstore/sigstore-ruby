# frozen_string_literal: true

require "rubygems/command"
require_relative "../../sigstore/tuf"

module Gem
  module Commands
    class SigstoreTufDownloadTargetCommand < Gem::Command
      def initialize
        super("sigstore-tuf-download-target", "download a target from a TUP repo")

        add_option("--metadata-url url", String) do |v|
          @metadata_url = v
        end

        add_option("--metadata-dir dir", String) do |dir|
          @metadata_dir = dir
        end

        add_option("--targets-dir dir", String) do |dir|
          @targets_dir = dir
        end
        add_option("--cached") do |cached|
          @cached = cached
        end
        add_option("--target-base-url url", String, "base url for target download") do |url|
          @target_base_url = url
        end
      end

      def execute
        raise Gem::CommandLineError, "metadata-url is required" unless @metadata_url
        raise Gem::CommandLineError, "metadata-dir is required" unless @metadata_dir
        raise Gem::CommandLineError, "targets-dir is required" unless @targets_dir

        kwargs = {}
        kwargs[:target_base_url] = @target_base_url if @target_base_url
        trust_updater = Sigstore::TUF::TrustUpdater.new(@metadata_url, false, metadata_dir: @metadata_dir,
                                                                              targets_dir: @targets_dir, **kwargs)

        options[:args].each do |target|
          target_info = trust_updater.updater.get_targetinfo(target)
          path = if @cached
                   trust_updater.updater.find_cached_target(target_info)
                 else
                   trust_updater.updater.download_target(target_info)
                 end
          say "Downloaded #{target} to #{path}"
        end
      end
    end
  end
end
