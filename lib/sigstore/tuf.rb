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

require_relative "tuf/updater"
require "tempfile"
require "uri"
require "net/http"

module Sigstore
  module TUF
    DEFAULT_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
    STAGING_TUF_URL = "https://tuf-repo-cdn.sigstage.dev"

    class TrustUpdater
      include Loggable

      attr_reader :updater

      def initialize(metadata_url, offline, metadata_dir: nil, targets_dir: nil, target_base_url: nil)
        @repo_url = metadata_url

        default_metadata_dir, default_targets_dir = get_dirs(metadata_url) unless metadata_dir && targets_dir
        @metadata_dir = metadata_dir || default_metadata_dir
        @targets_dir = targets_dir || default_targets_dir

        @offline = offline

        rsrc_prefix = if @repo_url == DEFAULT_TUF_URL
                        "prod"
                      elsif @repo_url == STAGING_TUF_URL
                        "staging"
                      end

        FileUtils.mkdir_p @metadata_dir
        FileUtils.mkdir_p @targets_dir

        if rsrc_prefix
          tuf_root = File.join(@metadata_dir, "root.json")

          unless File.exist?(tuf_root)
            File.open(tuf_root, "wb") do |f|
              File.open(File.expand_path("../../data/_store/#{rsrc_prefix}/root.json", __dir__), "rb") do |r|
                IO.copy_stream(r, f)
              end
            end
          end

          trusted_root_target = File.join(@targets_dir, "trusted_root.json")

          unless File.exist?(trusted_root_target)
            File.open(trusted_root_target, "wb") do |f|
              File.open(File.expand_path("../../data/_store/#{rsrc_prefix}/trusted_root.json", __dir__),
                        "rb") do |r|
                IO.copy_stream(r, f)
              end
            end
          end
        end

        return if offline

        repo_url = URI.parse(@repo_url)

        @updater = Updater.new(
          metadata_dir: @metadata_dir,
          metadata_base_url: @repo_url,
          target_base_url: (target_base_url && URI.parse(target_base_url)) ||
                           URI.join("#{@repo_url.to_s.chomp("/")}/", "targets/"),
          target_dir: @targets_dir,
          fetcher: Net::HTTP.new(repo_url.host, repo_url.port).tap { _1.use_ssl = true if repo_url.scheme != "http" }
        )

        begin
          @updater.refresh
        rescue StandardError => e
          raise "Failed to refresh TUF metadata: #{e.class} #{e.full_message}"
        end
      end

      def get_dirs(url)
        app_name = "sigstore-ruby"
        app_author = "segiddins"

        repo_base = encode_uri_component(url)
        home = Dir.home

        data_home = ENV.fetch("XDG_DATA_HOME", File.join(home, ".local", "share"))
        cache_home = ENV.fetch("XDG_CACHE_HOME", File.join(home, ".cache"))
        tuf_data_dir = File.join(data_home, app_name, app_author, "tuf")
        tuf_cache_dir = File.join(cache_home, app_name, app_author, "tuf")

        [File.join(tuf_data_dir, repo_base), File.join(tuf_cache_dir, repo_base)]
      end

      def encode_uri_component(str)
        if URI.respond_to?(:encode_uri_component)
          URI.encode_uri_component(str)
        else
          URI.encode_www_form_component(str).gsub("+", "%20")
        end
      end

      def trusted_root_path
        unless @updater
          logger.info { "Offline mode: using cached trusted root" }
          return File.join(@targets_dir, "trusted_root.json")
        end

        root_info = @updater.get_targetinfo("trusted_root.json")
        raise "Unsupported TUF configuration: no trusted_root.json" unless root_info

        path = @updater.find_cached_target(root_info)
        path ||= @updater.download_target(root_info)

        path
      end
    end
  end
end
