# Okta::Jwt

Verify Okta JWT tokens using cached JWKs.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'okta-jwt'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install okta-jwt

## Usage

Configure the client to sign in user (optional):

```ruby
# client for resource owner password flow
Okta::Jwt.configure_client!(
	issuer_url:     'https://organization.oktapreview.com,
	auth_server_id: 'auth_server_id,
	client_id:      'client_id,
	client_secret:  'client_secret,
	slogger:         Logger.new(STDOUT) # optional
)
```

Sign in user to get tokens (default scope is openid):

```ruby
auth_response = Okta::Jwt.sign_in(username: 'user@example.org', password: 'password', scope: 'openid my_scope')
parsed_auth_response = JSON.parse(auth_response.body)
```

Verify tokens:

```ruby
verified_id_token = Okta::Jwt.verify_token(parsed_auth_response['id_token'])
verified_access_token = Okta::Jwt.verify_token(parsed_auth_response['access_token'])
```
NOTE: tokens are validated using data from header and payload: kid, iss and cid/aud. If you are just verifying the tokens there is no need to store anything at the client side. 

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/damir/okta-jwt. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Okta::Jwt project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/okta-jwt/blob/master/CODE_OF_CONDUCT.md).
