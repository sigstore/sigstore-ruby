# frozen_string_literal: true

require "rubygems/command"
require_relative "../../sigstore/tuf"

module Gem
  module Commands
    class SigstoreTufRefreshCommand < Gem::Command

      def initialize
        super("sigstore-tuf-refresh", "refresh a TUF repo")

        add_option("--metadata-url url", String) do |v|
          @metadata_url = v
        end

        add_option("--metadata-dir dir", String) do |dir|
          @metadata_dir = dir
        end
      end

      def execute
        raise Gem::CommandLineError, "metadata-url is required" unless @metadata_url
        raise Gem::CommandLineError, "metadata-dir is required" unless @metadata_dir
        raise Gem::CommandLineError, "no args accepted" unless options[:args].empty?

        trust_updater = Sigstore::TUF::TrustUpdater.new(@metadata_url, false, metadata_dir: @metadata_dir)
      end
    end
  end
end
