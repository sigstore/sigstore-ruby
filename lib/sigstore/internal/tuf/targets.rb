# frozen_string_literal: true

module Sigstore::Internal::TUF
  class Targets
    TYPE = "targets"

    attr_reader :version, :targets

    def initialize(data)
      type = data.fetch("_type")
      raise "Expected type to be #{TYPE}" unless type == TYPE

      @version = data.fetch("version")
      @expires = Time.iso8601 data.fetch("expires")
      @targets = data.fetch("targets").to_h { |k, v| [k, Target.new(v, k)] }
      @delegations = data.fetch("delegations")
      @unrecognized_fields = data.fetch("unrecognized_fields", {})
    end

    def expired?(reference_time)
      @expires < reference_time
    end

    class Target
      attr_reader :path, :hashes

      def initialize(data, path)
        @path = path
        @length = data.fetch("length")
        @hashes = data.fetch("hashes")
      end

      def verify_length_and_hashes(data)
        # TODO
      end
    end
  end
end
