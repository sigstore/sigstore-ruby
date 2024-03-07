# frozen_string_literal: true

module Sigstore::Internal::TUF
  class Timestamp
    TYPE = "timestamp"

    attr_reader :version, :spec_version, :expires, :snapshot_meta, :unrecognized_fields

    def initialize(data)
      type = data.fetch("_type")
      raise "Expected type to be #{TYPE}, got #{type.inspect}" unless type == TYPE

      @version = data.fetch("version")
      @spec_version = data.fetch("spec_version")
      @expires = Time.iso8601 data.fetch("expires")
      @snapshot_meta = Snapshot::Meta.new(data.dig("meta", "snapshot.json") || { "version" => 1 })
      @unrecognized_fields = data.fetch("unrecognized_fields", {})
    end

    def expired?(reference_time)
      @expires < reference_time
    end
  end
end
