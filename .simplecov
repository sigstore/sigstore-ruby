# frozen_string_literal: true

SimpleCov.root(__dir__)

SimpleCov.start do
  enable_coverage :branch unless RUBY_ENGINE == "truffleruby"
end
