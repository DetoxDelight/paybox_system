# frozen_string_literal: true

require 'time'
require 'openssl'
require 'base64'
require 'rack'
require 'pathname'

require 'paybox_system/version'
require 'paybox_system/config'

module PayboxSystem
  HASH_METHOD = 'SHA512'
  PUBLIC_KEY_PATH = Pathname.new(__dir__).join('..', 'docs', 'pubkey.pem')
  PUBLIC_KEY = OpenSSL::PKey::RSA.new(File.read(PUBLIC_KEY_PATH))

  SERVERS = {
    test:        'https://preprod-tpeweb.paybox.com',
    live:        'https://tpeweb.paybox.com',
    live_backup: 'https://tpeweb1.paybox.com'
  }.freeze

  CURRENCY_CODES = {
    'AUD' => '036',
    'CAD' => '124',
    'CZK' => '203',
    'DKK' => '208',
    'HKD' => '344',
    'ICK' => '352',
    'JPY' => '392',
    'NOK' => '578',
    'SGD' => '702',
    'SEK' => '752',
    'CHF' => '756',
    'GBP' => '826',
    'USD' => '840',
    'EUR' => '978'
  }.freeze

  class Error < StandardError; end
  class MissingSecretKey < Error; end
  class MissingEnvironment < Error; end

  class << self
    attr_accessor :config

    def classical_url(options = {})
      server_url('/cgi/MYchoix_pagepaiement.cgi', options)
    end

    def light_url(options = {})
      server_url('/cgi/MYframepagepaiement_ip.cgi', options)
    end

    def mobile_url(options = {})
      server_url('/cgi/ChoixPaiementMobile.cgi', options)
    end

    def termination_url(options = {})
      server_url('/cgi-bin/ResAbon.cgi', options)
    end

    def formatted_query(options = {})
      format_query(formatted_params(options))
    end

    def formatted_params(options = {})
      return {} if options.empty?

      params = generate_base_params(options)
      params['PBX_HASH'] = HASH_METHOD
      params['PBX_TIME'] = Time.now.utc.iso8601
      params['PBX_HMAC'] = compute_hmac_signature(params, params['PBX_HASH'].downcase)
      params
    end

    def valid_response?(params, sign)
      digest = OpenSSL::Digest::SHA1.new
      PUBLIC_KEY.verify(digest, Base64.decode64(Rack::Utils.unescape(sign)), params)
    end

  protected

    def generate_base_params(options)
      params = options.each_with_object({}) do |(k, v), h|
        unless v.nil? || v.to_s =~ /\A[[:space:]]*\z/
          h["PBX_#{k == :tds ? '3DS' : k.to_s.upcase}"] = v
        end
      end
      params['PBX_SITE'] ||= config.site if config.site?
      params['PBX_RANG'] ||= config.rank if config.rank?
      params['PBX_IDENTIFIANT'] ||= config.identifier if config.identifier?
      params['PBX_DEVISE'] ||= config.currency if config.currency?
      params
    end

    def compute_hmac_signature(params, hash_method)
      raise MissingSecretKey, 'Missing secret_key' unless config.secret_key

      base_params_query = format_query(params)
      binary_key = [config.secret_key].pack('H*')
      signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new(hash_method), binary_key, base_params_query)
      signature.upcase
    end

    def format_query(params)
      params.map { |k, v| k.to_s + '=' + v.to_s }.join('&')
    end

    def server_url(path, options = {})
      base_url = SERVERS[config.environment]
      unless base_url
        raise MissingEnvironment, 'Missing or invalid environment'
      end

      return base_url + path if options.empty?

      base_url + path + '?' + formatted_query(options)
    end
  end

  self.config = Config.new
end
