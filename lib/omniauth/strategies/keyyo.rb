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

      # option :token_params, {grant_type: 'authorization_code'}
      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.

      # uid { raw_info['id'] }

      info do
        {
          token: raw_info.token,
          refresh_token: raw_info.refresh_token,
          expires_at: raw_info.expires_at,
          expires_in: raw_info.expires_in
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

       # Fixes regression in omniauth-oauth2 v1.4.0 by https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
      def callback_url
        options[:callback_url] || (full_host + script_name + callback_path)
      end

      def raw_info
        @raw_info ||= access_token
      end
    end
  end
end
