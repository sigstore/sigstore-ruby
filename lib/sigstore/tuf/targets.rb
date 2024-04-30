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
  class Targets
    TYPE = "targets"

    attr_reader :version, :targets, :delegations

    def initialize(data)
      type = data.fetch("_type")
      raise "Expected type to be #{TYPE}, got #{type.inspect}" unless type == TYPE

      @version = data.fetch("version")
      @expires = Time.iso8601 data.fetch("expires")
      @targets = data.fetch("targets").to_h { |k, v| [k, Target.new(v, k)] }
      @delegations = data.fetch("delegations", {})
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
