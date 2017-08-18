require 'securerandom'
require 'base64'

module Kafka
  class SaslScramAuthenticator
    def initialize(username, password, mechanism: 'SHA-256')
      @username = username
      @password = password
      @mechanism = mechanism
    end

    def authenticate!(connection, logger)
      @logger = logger
      @connection = connection
      response = @connection.send_request(Kafka::Protocol::SaslHandshakeRequest.new('SCRAM-' + @mechanism))

      unless response.error_code == 0 && response.enabled_mechanisms.include?('SCRAM-' + @mechanism)
        raise Kafka::Error, "SCRAM-#{@mechanism} is not supported."
      end

      @logger.debug "authenticating #{@username} with scram, mechanism: #{@mechanism}"

      @encoder = @connection.encoder
      @decoder = @connection.decoder

      msg = first_message
      @logger.debug "client first message: #{msg}"
      @encoder.write_bytes(msg)

      @server_first_message = @decoder.bytes
      @logger.debug "server first msg: #{@server_first_message}"

      msg = final_message
      @logger.debug "client final message: #{msg}"
      @encoder.write_bytes(msg)

      response = parse_response(@decoder.bytes)
      @logger.debug "server final msg: #{response}"

      raise FailedScramAuthentication, response['e'] if response['e']
      raise FailedScramAuthentication, 'Invalid server signature' if response['v'] != @server_signature
    rescue FailedScramAuthentication
      raise
    rescue StandardError => e
      @logger.error "authentication error #{e.inspect}\n\n#{e.backtrace.join("\n")}"
      raise FailedScramAuthentication, 'Authentication failed: Unknown reason'
    end

    def first_message
      "n,,#{first_message_bare}"
    end

    def first_message_bare
      "n=#{encoded_username},r=#{nonce}"
    end

    def auth_message
      [first_message_bare, @server_first_message, final_message_without_proof].join(',')
    end

    def final_message_without_proof
      data = parse_response(@server_first_message)
      "c=biws,r=#{data['r']}"
    end

    def final_message
      data = parse_response(@server_first_message)
      salt = Base64.strict_decode64(data['s'])
      iterations = data['i'].to_i

      salted_password = hi(@password, salt, iterations)
      client_key = hmac(salted_password, 'Client Key')
      stored_key = h(client_key)
      client_signature = hmac(stored_key, auth_message)
      client_proof = xor(client_key, client_signature)
      server_key = hmac(salted_password, 'Server Key')
      @server_signature = Base64.strict_encode64(hmac(server_key, auth_message))

      proof = Base64.strict_encode64(client_proof)
      "#{final_message_without_proof},p=#{proof}"
    end

    def h(str)
      digest.digest(str)
    end

    def hi(str, salt, iterations)
      OpenSSL::PKCS5.pbkdf2_hmac(
        str,
        salt,
        iterations,
        digest.size,
        digest)
    end

    def hmac(data, key)
      OpenSSL::HMAC.digest(digest, data, key)
    end

    def xor(first, second)
      first.bytes.zip(second.bytes).map{ |(a,b)| (a ^ b).chr }.join('')
    end

    def parse_response(data)
      data.split(',').map { |s| s.split('=', 2) }.to_h
    end

    def encoded_username
      safe_str(@username.encode(Encoding::UTF_8))
    end

    def nonce
      @nonce ||= SecureRandom.urlsafe_base64(32)
    end

    def digest
      @digest ||= case @mechanism
                  when 'SHA-256'
                    OpenSSL::Digest::SHA256.new.freeze
                  when 'SHA-512'
                    OpenSSL::Digest::SHA512.new.freeze
                  else
                    raise StandardError, 'Unknown mechanism'
                  end
    end

    def safe_str(val)
      val.gsub('=', '=3D').gsub(',', '=2C')
    end
  end
end
Kafka::Protocol::SaslHandshakeRequest::SUPPORTED_MECHANISMS << 'SCRAM-SHA-256'
Kafka::Protocol::SaslHandshakeRequest::SUPPORTED_MECHANISMS << 'SCRAM-SHA-512'
