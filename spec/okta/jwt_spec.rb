RSpec.describe Okta::Jwt do

  issuer        = ENV["OKTA_ISSUER"]
  audience      = ENV["OKTA_AUDIENCE"]
  client_ids    = ENV["OKTA_CLIENT_IDS"].split(',') # [resource_owner_token, implicit_token]
  client_secret = ENV["OKTA_CLIENT_SECRET"]

  # client to sign in users with resource owner flow
  Okta::Jwt.configure_client! issuer:         issuer,
                              client_id:      client_ids.first,
                              client_secret:  client_secret

  auth_response         = Okta::Jwt.sign_in(username: 'test@example.org', password: 'Password123', scope: 'openid profile')
  parsed_auth_response  = JSON.parse(auth_response.body)
  access_token          = parsed_auth_response['access_token']
  
  it "has a version number" do
    expect(Okta::Jwt::VERSION).not_to be nil
  end

  it "fails if invalid issuer" do
    expect{Okta::Jwt.verify_token(access_token,
      issuer:     'invalid',
      audience:   audience,
      client_id:  client_ids 
    )}.to raise_error(Okta::Jwt::InvalidToken, 'Invalid issuer')
  end

  it "fails if invalid audience" do
    expect{Okta::Jwt.verify_token(access_token,
      issuer:     issuer,
      audience:   'invalid',
      client_id:  client_ids 
    )}.to raise_error(Okta::Jwt::InvalidToken, 'Invalid audience')
  end

  it "fails if invalid client" do
    expect{Okta::Jwt.verify_token(access_token,
      issuer:     issuer,
      audience:   audience,
      client_id:  'invalid' 
    )}.to raise_error(Okta::Jwt::InvalidToken, 'Invalid client')
  end

  it "fails if expired token" do
    header, payload, sig = access_token.split('.')
    decoded_payload = JSON.parse(Base64.decode64(payload))
    decoded_payload['exp'] = Time.now.to_i - 1000
    encoded_payload = Base64.strict_encode64(decoded_payload.to_json)
    expired_token = [header, encoded_payload, sig].join('.')

    expect{Okta::Jwt.verify_token(expired_token,
      issuer:     issuer,
      audience:   audience,
      client_id:  client_ids 
    )}.to raise_error(Okta::Jwt::InvalidToken, 'Token is expired')
  end

  it "does validate access_token" do
    Okta::Jwt.logger = Logger.new(STDOUT)
    expect(Okta::Jwt.verify_token(access_token,
      issuer:     issuer,
      audience:   audience,
      client_id:  client_ids
    )['exp']).to be_truthy
  end

  it "does have cached jwk" do
    expect(Okta::Jwt::JWKS_CACHE.keys.size).to eq(1)
  end
end
