# frozen_string_literal: true

module Sigstore::Internal::TUF
  # The class for the Snapshot role
  class Snapshot
    TYPE = "snapshot"

    attr_reader :version, :meta

    def initialize(data)
      type = data.fetch("_type")
      raise "Expected type to be #{TYPE}, got #{type.inspect}" unless type == TYPE

      @version = data.fetch("version")
      @expires = Time.iso8601 data.fetch("expires")
      @meta = data.fetch("meta").transform_values { Meta.new(_1) }
    end

    def expired?(reference_time)
      @expires < reference_time
    end

    class Meta
      attr_reader :version

      def initialize(data)
        @version = data.fetch("version", 1)
        @length = data.fetch("length", nil)
        @hashes = data.fetch("hashes", nil)
        @unrecognized_fields = data.fetch("unrecognized_fields", {})

        raise ArguementError, "version must be positive" if @version <= 0

        validate_length(@length) unless @length.nil?
        validate_hashes(@hashes) unless @hashes.nil?
      end

      def verify_length_and_hashes(data)
        verify_length(data, @length) if @length
        verify_hashes(data, @hashes) if @hashes
      end

      def verify_length(data, length)
        # TODO
      end

      def verify_hashes(data, hashes)
        # TODO
      end

      def validate_length(length)
        # todo
      end

      def validate_hashes(hashes)
        # todo
      end
    end
  end
end
