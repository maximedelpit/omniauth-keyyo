require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Keyyo < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, "keyyo"

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        site: 'https://ssl.keyyo.com/',
        authorize_url: 'https://ssl.keyyo.com/oauth2/authorize.php',
        token_url: 'https://api.keyyo.com/oauth2/token.php'
      }

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info['id'] }

      info do
        {
          name: raw_info['name'],
          email: raw_info['email']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      # { "access_token":"<Your access token>","expires_in":3600,"token_type":"bearer","scope":"a.user o.w.voipprofile","refresh_token":"<Your refresh token>" }

      def raw_info
        binding.pry
        @raw_info ||= access_token.get('/').parsed
      end
    end
  end
end
