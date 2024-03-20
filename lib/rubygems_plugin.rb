# frozen_string_literal: true

require "rubygems/command_manager"

Gem::CommandManager.instance.register_command :sigstore_verify
Gem::CommandManager.instance.register_command :sigstore_verify_bundle
