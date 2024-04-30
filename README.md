# Sigstore

This is a pure Ruby implementation of the `sigstore verify` command from the [sigstore/cosign](https://sigstore.dev/projects/cosign) project. It is intended to be used as a library in other Ruby projects, in additional to a `gem` subcommand. The project also contains a TUF client implementation, given TUF is a part of the sigstore verification flow.

## Usage

```shell
$ gem sigstore_cosign_verify_bundle --bundle a.txt.sigstore \
    --certificate-identity https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    a.txt
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test-unit` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at <https://github.com/sigstore/sigstore-ruby>.

## License

The gem is available as open source under the terms of the [Apache 2](https://opensource.org/licenses/Apache-2.0).
