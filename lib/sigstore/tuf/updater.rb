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

require_relative "config"
require_relative "trusted_metadata_set"
require_relative "root"
require_relative "snapshot"
require_relative "targets"
require_relative "timestamp"

module Sigstore::TUF
  class Updater
    include Sigstore::Loggable

    def initialize(metadata_dir:, metadata_base_url:, target_base_url:, target_dir:, fetcher:,
                   config: UpdaterConfig.new)
      @dir = metadata_dir
      @metadata_base_url = "#{metadata_base_url.to_s.chomp("/")}/"
      @target_dir = target_dir
      @target_base_url = target_base_url && "#{target_base_url.to_s.chomp("/")}/"

      @fetcher = fetcher
      @config = config

      unless %i[metadata simple].include? @config.envelope_type
        raise ArgumentError, "Unsupported envelope type: #{@config[:envelope_type].inspect}"
      end

      begin
        data = load_local_metadata("root")
        @trusted_set = TrustedMetadataSet.new(data, "metadata")
      rescue ::JSON::ParserError => e
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
        filepath
      rescue Errno::ENOENT, Error::LengthOrHashMismatch => e
        logger.debug { "No cached target at #{filepath}: #{e.class} #{e.message}" }
        nil
      end
    end

    def download_target(target_info, filepath = nil, target_base_url = nil)
      target_base_url ||= @target_base_url
      raise ArgumentError, "No target_base_url set" unless target_base_url

      filepath ||= generate_target_file_path(target_info)

      target_filepath = target_info.path
      consistent_snapshot = @trusted_set.root.consistent_snapshot

      if consistent_snapshot && @config.prefix_targets_with_hash
        hashes = target_info.hashes.values
        dir, sep, basename = target_filepath.rpartition("/")
        target_filepath = "#{dir}#{sep}#{hashes.first}.#{basename}"
      end

      full_url = URI.join(target_base_url, target_filepath)

      @fetcher.get2(full_url) do |resp|
        resp.value
        target_info.verify_length_and_hashes(resp.body)

        # TODO: atomic write
        File.binwrite(filepath, resp.body)
      rescue Net::HTTPClientException => e
        raise "Failed to download target #{target_info.inspect} #{target_filepath.inspect} from #{full_url}: " \
              "#{e.message}"
      end
      logger.info { "Downloaded #{target_filepath} to #{filepath}" }
      filepath
    end

    private

    def load_local_metadata(role_name)
      encoded_name = URI.encode_www_form_component(role_name)

      File.binread(File.join(@dir, "#{encoded_name}.json"))
    end

    def load_root
      lower_bound = @trusted_set.root.version + 1
      upper_bound = lower_bound + @config.max_root_rotations

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
        logger.debug "Local timestamp not valid as final: #{e.class} #{e.message}"
      else
        @trusted_set.timestamp = data
      end

      data = download_metadata(Timestamp::TYPE, nil)

      begin
        @trusted_set.timestamp = data
      rescue Error::EqualVersionNumber
        logger.debug "Timestamp version did not increase"
        return
      end

      persist_metadata(Timestamp::TYPE, data)
    end

    def load_snapshot
      data = load_local_metadata(Snapshot::TYPE)
      @trusted_set.snapshot = data
      logger.debug "Loaded snapshot from local metadata"
    rescue Errno::ENOENT => e
      logger.debug "Local snapshot not valid as final: #{e.class} #{e.message}"

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
        @trusted_set.update_delegated_targets(data, role, parent_role).tap do
          logger.debug { "Loaded targets for #{role} from local metadata" }
        end
      rescue Errno::ENOENT
        logger.debug { "No local targets for #{role}, fetching" }

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

      logger.debug { "Downloading metadata for #{role_name} from #{url}" }

      resp = @fetcher.get(url)
      resp.value

      resp.body
    end

    def persist_metadata(role_name, data)
      logger.debug { "Persisting metadata for #{role_name}" }

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
      logger.debug { "Searching for target #{target_path}" }

      delegations_to_visit = [[Targets::TYPE, Root::TYPE]]
      visited_role_names = Set.new

      while delegations_to_visit.any? && visited_role_names.size < @config.max_delegations
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

          logger.debug { "Terminating delegation found for #{child_name}" }
          delegations_to_visit.clear
          break
        end

        delegations_to_visit.concat child_roles_to_visit.reverse
      end

      logger.warn { "Max delegations reached, stopping search" } if delegations_to_visit.any?

      nil
    end

    def generate_target_file_path(target_info)
      raise ArgumentError, "target_dir not set" unless @target_dir

      filename = URI.encode_www_form_component(target_info.path)
      File.join(@target_dir, filename)
    end
  end
end
