require 'warden-oauth2'
require 'base64'

module Warden
  module OAuth2
    module Strategies
      class Client < Base
        attr_reader :client, :client_id, :client_secret

        def authenticate!
          @client = client_from_request_params || client_from_http_basic

          if client
            fail('invalid_scope') && return if scope && client.respond_to?(:scope) && !client.scope?(scope)
            client_authenticated
          else
            fail 'invalid_client'
          end
        end

        def client_from_http_basic
          return nil unless (env.keys & Rack::Auth::AbstractRequest::AUTHORIZATION_KEYS).any?
          @client_id, @client_secret = *Rack::Auth::Basic::Request.new(env).credentials
          model.locate(client_id, client_secret)
        end

        def client_from_request_params
          @client_id, @client_secret = params['client_id'], params['client_secret']
          return nil unless client_id
          model.locate(@client_id, @client_secret)
        end

        def public_client?
          client && !client_secret
        end

        def error_status
          case message
          when 'invalid_client', 'invalid_token' then 401
          when 'invalid_scope' then 403
          else 400
          end
        end

        def model
          fail 'Model should be defined in a child strategy'
        end

        def client_authenticated
          success! client
        end
      end
    end
  end
end
