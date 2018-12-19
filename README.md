# Okta::Jwt

Verify Okta JWT access tokens using cached JWKs.

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
Require the library:

```ruby
require 'okta/jwt'
```

### Getting the tokens

Configuration:

```ruby
Okta::Jwt.configure!(
  issuer: 'https://<org>.oktapreview.com/oauth2<auth_server_id>'
)
```
NOTE: this step is optional, you don't need it for token verification.

#### Resource owner password flow

Sign in user to get access token (default scope is openid):

```ruby
auth_response = Okta::Jwt.sign_in_user(
  username: 'user@example.org',
  password: 'password',
  client_id: 'client_id',
  client_secret: 'client_secret',
  scope: 'openid my_scope'
)
access_token = JSON.parse(auth_response.body)['access_token']
```

#### Client credentials flow

Sign in client to get access token (provide at least one custom scope):

```ruby
auth_response = Okta::Jwt.sign_in_client(
  client_id: 'client_id',
  client_secret: 'client_secret',
  scope: 'my_scope'
)
access_token = JSON.parse(auth_response.body)['access_token']
```

### Verify the token
  
Verify access token (signature + claims):

```ruby
Okta::Jwt.logger = Logger.new(STDOUT) # set optional logger
verified_access_token = Okta::Jwt.verify_token(
  access_token,
  issuer: 'https://<org>.oktapreview.com/oauth2<auth_server_id>',
  audience: 'development',
  client_id: 'client_id'
)
```
NOTE: You can pass multiple client ids as an array if needed.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/damir/okta-jwt. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Okta::Jwt project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/okta-jwt/blob/master/CODE_OF_CONDUCT.md).
