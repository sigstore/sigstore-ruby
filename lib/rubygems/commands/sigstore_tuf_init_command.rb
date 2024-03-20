# frozen_string_literal: true

require "rubygems/command"
require_relative "../../sigstore/command_options"

module Gem
  module Commands
    class SigstoreTufInitCommand < Gem::Command

      def initialize
        super("sigstore-tuf-init", "initialize a TUF client")

        add_option("--metadata-url url", String) do |v|
          @metadata_url = v
        end

        add_option("--metadata-dir dir", String) do |dir|
          @metadata_dir = dir
        end
      end

      def execute
        raise Gem::CommandLineError, "--metadata-url is required" unless @metadata_url
        raise Gem::CommandLineError, "--metadata-dir is required" unless @metadata_dir
        raise Gem::CommandLineError, "provide a trusted TUF root" unless options[:args].size == 1 && File.exist?(options[:args].first)

        FileUtils.mkdir_p(@metadata_dir)
        FileUtils.cp(options[:args].first, File.join(@metadata_dir, "root.json"))
      end
    end
  end
end
