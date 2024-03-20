# frozen_string_literal: true

require_relative "tuf/trusted_metadata_set"
require_relative "tuf/root"
require_relative "tuf/snapshot"
require_relative "tuf/targets"
require_relative "tuf/timestamp"
require "tempfile"
require "uri"
require "net/http"

module Sigstore
  module TUF
    DEFAULT_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
    STAGING_TUF_URL = "https://tuf-repo-cdn.sigstage.dev"

    class TrustUpdater
      def initialize(url, offline, metadata_dir: nil, targets_dir: nil)
        @repo_url = url

        default_metadata_dir, default_targets_dir = get_dirs(url) unless metadata_dir && targets_dir
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

        repo_url = URI.parse(url)

        @updater = Updater.new(
          metadata_dir: @metadata_dir,
          metadata_base_url: @repo_url,
          target_base_url: URI.join("#{@repo_url}/", "targets/"),
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

        # TODO: encode_uri_component not on 3.0
        repo_base = URI.encode_uri_component(url)

        data_home = ENV.fetch("XDG_DATA_HOME", File.join(Dir.home, ".local", "share"))
        cache_home = ENV.fetch("XDG_CACHE_HOME", File.join(Dir.home, ".cache"))
        tuf_data_dir = File.join(data_home, app_name, app_author, "tuf")
        tuf_cache_dir = File.join(cache_home, app_name, app_author, "tuf")

        [File.join(tuf_data_dir, repo_base), File.join(tuf_cache_dir, repo_base)]
      end

      def trusted_root_path
        unless @updater
          # debug
          return File.join(@targets_dir, "trusted_root.json")
        end

        root_info = @updater.get_targetinfo("trusted_root.json")
        raise "Unsupported TUF configuration: no trusted_root.json" unless root_info

        path = @updater.find_cached_target(root_info)
        path ||= @updater.download_target(root_info)

        # debug
        path
      end
    end

    class Updater
      def initialize(metadata_dir:, metadata_base_url:, target_base_url:, target_dir:, fetcher:)
        @dir = metadata_dir
        @metadata_base_url = "#{metadata_base_url.to_s.chomp("/")}/"
        @target_dir = target_dir
        @target_base_url = target_base_url && "#{target_base_url.to_s.chomp("/")}/"

        @fetcher = fetcher

        begin
          data = load_local_metadata("root")
          @trusted_set = TrustedMetadataSet.new(data, "metadata")
        rescue ::JSON::ParserError => e # JSON::ParseError
          raise "Invalid JSON in #{File.join(@dir, "root.json")}: #{e.class} #{e}"
        end
      end

      def refresh
        load_root
        load_timestamp
        load_snapshot
        load_targets(Targets::TYPE, Root::TYPE)
      end

      def get_targetinfo(target_path)
        refresh unless @trusted_set.include? Targets::TYPE
        preorder_depth_first_walk(target_path)
      end

      def find_cached_target(target_info, filepath = nil)
        filepath ||= generate_target_file_path(target_info)

        begin
          data = File.binread(filepath)
          target_info.verify_length_and_hashes(data)
        rescue Errno::ENOENT
          nil
        end
      end

      def download_target(target_info, filepath = nil, target_base_url = nil)
        target_base_url ||= @target_base_url
        raise "No target_base_url set" unless target_base_url

        filepath ||= generate_target_file_path(target_info)

        target_filepath = target_info.path
        consistent_snapshot = @trusted_set.root.consistent_snapshot

        if consistent_snapshot # TODO: config.prefix_targets_with_hash
          hashes = target_info.hashes.values
          dir, sep, basename = target_filepath.rpartition("/")
          target_filepath = "#{dir}#{sep}#{hashes.first}.#{basename}"
        end

        full_url = URI.join(target_base_url, target_filepath)

        @fetcher.get2(full_url) do |resp|
          resp.value
          target_info.verify_length_and_hashes(resp.body)

          File.binwrite(filepath, resp.body)
        rescue Net::HTTPClientException => e
          raise "Failed to download target #{target_filepath.inspect} from #{full_url}: #{e.message}"
        end
        # debug
        filepath
      end

      private

      def debug(*_args, **_kwargs); end

      def load_local_metadata(role_name)
        encoded_name = URI.encode_www_form_component(role_name)

        File.binread(File.join(@dir, "#{encoded_name}.json"))
      end

      def load_root
        lower_bound = @trusted_set.root.version + 1
        upper_bound = lower_bound + 100 # TODO: make this configurable

        lower_bound.upto(upper_bound) do |version|
          data = download_metadata("root", version)
          @trusted_set.root = data
          persist_metadata("root", data)
        rescue Net::HTTPClientException => e
          break if %w[403 404].include? e.response.code

          raise
        end
      end

      def load_timestamp
        begin
          data = load_local_metadata(Timestamp::TYPE)
        rescue Errno::ENOENT => e
          debug "Local timestamp not valid as final: #{e.class} #{e.message}"
        else
          @trusted_set.timestamp = data
        end

        data = download_metadata(Timestamp::TYPE, nil)

        begin
          @trusted_set.timestamp = data
        rescue EqualVersionNumberError
          return
        end

        persist_metadata(Timestamp::TYPE, data)
      end

      def load_snapshot
        data = load_local_metadata(Snapshot::TYPE)
        @trusted_set.snapshot = data
        debug "Loaded snapshot from local metadata"
      rescue Errno::ENOENT => e
        debug "Local snapshot not valid as final: #{e.class} #{e.message}"

        snapshot_meta = @trusted_set.timestamp.snapshot_meta
        version = snapshot_meta.version if @trusted_set.root.consistent_snapshot

        data = download_metadata(Snapshot::TYPE, version)
        @trusted_set.snapshot = data
        persist_metadata(Snapshot::TYPE, data)
      end

      def load_targets(role, parent_role)
        return @trusted_set[role] if @trusted_set.include?(role)

        begin
          data = load_local_metadata(role)
          @trusted_set.update_delegated_targets(data, role, parent_role)

          # debug
        rescue Errno::ENOENT
          # debug

          snapshot = @trusted_set.snapshot
          metainfo = snapshot.meta.fetch("#{role}.json")
          raise "No metadata for role: #{role}" unless metainfo

          version = metainfo.version if @trusted_set.root.consistent_snapshot
          data = download_metadata(role, version)
          delegated_targets = @trusted_set.update_delegated_targets(data, role, parent_role)
          persist_metadata(role, data)
          delegated_targets
        end
      end

      def download_metadata(role_name, version)
        encoded_name = URI.encode_www_form_component(role_name)
        url = if version.nil?
                URI.join(@metadata_base_url, "#{encoded_name}.json")
              else
                URI.join(@metadata_base_url, "#{version}.#{encoded_name}.json")
              end

        resp = @fetcher.get(url)
        resp.value

        resp.body
      end

      def persist_metadata(role_name, data)
        encoded_name = URI.encode_www_form_component(role_name)
        filename = File.join(@dir, "#{encoded_name}.json")
        Tempfile.create("", @dir) do |f|
          f.binmode
          f.write(data)
          f.close

          File.rename(f.path, filename)
        end
      end

      def preorder_depth_first_walk(target_path)
        # TODO
        delegations_to_visit = [[Targets::TYPE, Root::TYPE]]
        visited_role_names = Set.new

        while delegations_to_visit.any? && visited_role_names.size < 100 # TODO: make this configurable
          role_name, parent_role = delegations_to_visit.shift
          next if visited_role_names.include?(role_name)

          targets = load_targets(role_name, parent_role)
          target = targets.targets.fetch(target_path, nil)

          return target if target

          visited_role_names.add(role_name)

          next unless targets.delegations.any?

          child_roles_to_visit = []

          targets.delegations.roles_for_target(target_path).each do |child_name, terminating|
            child_roles_to_visit << [child_name, role_name]
            next unless terminating

            # debug
            delegations_to_visit.clear
            break
          end

          delegations_to_visit.concat child_roles_to_visit.reverse
        end

        if delegations_to_visit.any?
          # debug
        end

        nil
      end

      def generate_target_file_path(target_info)
        raise "target_dir not set" unless @target_dir

        filename = URI.encode_www_form_component(target_info.path)
        File.join(@target_dir, filename)
      end
    end
  end
end
