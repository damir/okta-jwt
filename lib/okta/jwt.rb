require 'okta/jwt/version'
require 'json'
require 'base64'
require 'faraday'
require 'json/jwt'

module Okta
  module Jwt
    module_function

    # keys are cached under their kid value
    JWKS_CACHE  = {}
  
    class << self
      attr_accessor :issuer_url, :auth_server_id, :client_id, :client_secret, :public_key_ttl, :client, :logger
    end
  
    # configure the client
    def configure!(issuer_url:, auth_server_id:, client_id:, public_key_ttl: 0, client_secret: nil, logger: Logger.new(IO::NULL))
      @issuer_url     = issuer_url
      @auth_server_id = auth_server_id
      @client_id      = client_id
      @public_key_ttl = public_key_ttl
      @client_secret  = client_secret
      @logger         = logger
  
      @client = Faraday.new(url: issuer_url) do |f|
        f.use Faraday::Adapter::NetHttp
        f.headers['Accept'] = 'application/json'
      end
    end
  
    # sign in user to get tokens
    def sign_in(username:, password:)
      client.post do |req|
        req.url "/oauth2/#{auth_server_id}/v1/token"
        req.headers['Content-Type']   = 'application/x-www-form-urlencoded'
        req.headers['Authorization']  = 'Basic: ' + Base64.strict_encode64("#{client_id}:#{client_secret}")
        req.body = URI.encode_www_form username: username, password: password, scope: 'openid', grant_type: 'password'
      end
    end
  
    # validate the token
    def verify_token(token)
      kid = JSON.parse(Base64.decode64(token.split('.').first))['kid']
      jwk = JSON::JWK.new(get_jwk(kid))
      JSON::JWT.decode(token, jwk.to_key)
    end
  
    # extract public key from metadata's jwks_uri
    def get_jwk(kid)
      return JWKS_CACHE[kid] if JWKS_CACHE[kid] # cache hit
  
      logger.info("[Okta::Jwt] Fetching public key: kid => #{kid} ...")
      jwks_response = client.get do |req|
        req.url get_metadata['jwks_uri']
      end
      jwk = JSON.parse(jwks_response.body)['keys'].find do |key|
        key.dig('kid') == kid
      end
  
      # cache and return the key
      jwk.tap{JWKS_CACHE[kid] = jwk}
    end
  
    # fetch metadata
    def get_metadata
      metadata_response = client.get do |req|
        req.url "/oauth2/#{auth_server_id}/.well-known/oauth-authorization-server?client_id=#{client_id}"
      end
      JSON.parse(metadata_response.body)
    end
  end
end
