# frozen_string_literal: true

# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
        raise Gem::CommandLineError, "--metadata-dir is required" unless @metadata_dir

        unless options[:args].size == 1 && File.exist?(options[:args].first)
          raise Gem::CommandLineError,
                "provide a trusted TUF root"
        end

        FileUtils.mkdir_p(@metadata_dir)
        FileUtils.cp(options[:args].first, File.join(@metadata_dir, "root.json"))
      end
    end
  end
end
