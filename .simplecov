# frozen_string_literal: true

SimpleCov.root(__dir__)

if ENV["COVERAGE"]
  SimpleCov.start do
    enable_coverage :branch unless RUBY_ENGINE == "truffleruby"
  end
end
