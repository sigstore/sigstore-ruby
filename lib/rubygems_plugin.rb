# frozen_string_literal: true

require "rubygems/command_manager"

Gem::CommandManager.instance.register_command :sigstore_cosign_verify
Gem::CommandManager.instance.register_command :sigstore_cosign_verify_bundle
