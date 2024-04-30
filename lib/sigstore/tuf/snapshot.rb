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

module Sigstore::TUF
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

        raise ArgumentError, "version must be positive" if @version <= 0

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
