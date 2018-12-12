require 'okta/jwt/version'
require 'json'
require 'base64'
require 'faraday'
require 'json/jwt'

module Okta
  module Jwt
    module_function

    class InvalidToken < Exception; end 

    # keys are cached under their kid value
    JWKS_CACHE  = {}
  
    class << self
      attr_accessor :issuer, :auth_server_id, :client_id, :client_secret, :logger
    end
  
    # configure the client for signing in
    def configure_client!(issuer:, client_id:, client_secret:)
      @issuer         = issuer
      @client_id      = client_id
      @client_secret  = client_secret
      @auth_server_id = issuer.split('/').last
    end
  
    # sign in user to get tokens
    def sign_in(username:, password:, scope: 'openid')
      client(issuer).post do |req|
        req.url "/oauth2/#{auth_server_id}/v1/token"
        req.headers['Content-Type']   = 'application/x-www-form-urlencoded'
        req.headers['Authorization']  = 'Basic: ' + Base64.strict_encode64("#{client_id}:#{client_secret}")
        req.body = URI.encode_www_form username: username, password: password, scope: scope, grant_type: 'password'
      end
    end
  
    # validate the token
    def verify_token(token, issuer:, audience:, client_id:)
      header, payload = token.split('.').first(2).map{|encoded| JSON.parse(Base64.decode64(encoded))}

      # validate claims
      raise InvalidToken.new('Invalid issuer')    if payload['iss'] != issuer
      raise InvalidToken.new('Invalid audience')  if payload['aud'] != audience
      raise InvalidToken.new('Invalid client')    if !Array(client_id).include?(payload['cid'])
      raise InvalidToken.new('Token is expired')  if payload['exp'].to_i <= Time.now.to_i

      # validate signature
      jwk = JSON::JWK.new(get_jwk(header, payload))
      JSON::JWT.decode(token, jwk.to_key)
    end
  
    # extract public key from metadata's jwks_uri using kid
    def get_jwk(header, payload)
      kid = header['kid']

      # cache hit
      return JWKS_CACHE[kid] if JWKS_CACHE[kid]
  
      # fetch jwk
      logger.info("[Okta::Jwt] Fetching public key: kid => #{kid} ...") if logger
      jwks_response = client(payload['iss']).get do |req|
        req.url get_metadata(payload)['jwks_uri']
      end
      jwk = JSON.parse(jwks_response.body)['keys'].find do |key|
        key.dig('kid') == kid
      end
  
      # cache and return the key
      jwk.tap{JWKS_CACHE[kid] = jwk}
    end
  
    # fetch client metadata using cid/aud
    def get_metadata(payload)
      auth_server_id    = payload['iss'].split('/').last # iss: "https://<org>.oktapreview.com/oauth2/<auth_server_id>"
      client_id         = payload['cid']
      metadata_response = client(payload['iss']).get do |req|
        req.url "/oauth2/#{auth_server_id}/.well-known/oauth-authorization-server?client_id=#{client_id}"
      end
      JSON.parse(metadata_response.body)
    end

    # init client
    def client(issuer)
      Faraday.new(url: issuer) do |f|
        f.use Faraday::Adapter::NetHttp
        f.headers['Accept'] = 'application/json'
      end
    end
  end
end
