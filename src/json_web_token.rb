require 'base64'
require 'json'
require 'openssl'

#
# JSON Web Token Class
#
class JsonWebToken
  public

  def encode(header_array, payload_array, secret)
    header  = urlsafe_encode(JSON.generate(header_array)).gsub('=', '')
    payload = urlsafe_encode(JSON.generate(payload_array)).gsub('=', '')
    ssl = convert_algorithm(header_array[:alg])
    signature = urlsafe_encode(OpenSSL::HMAC.hexdigest(ssl, secret, header + '.' + payload))
    [header, payload, signature].join('.')
  end

  def decode(jwt, secret)
    fail 'require jwt of string type.' unless jwt.is_a?(String)

    header, payload, signature = jwt.split('.')

    fail 'require jwt format.' if header.nil? || payload.nil? || signature.nil?

    header_array  = JSON.parse(urlsafe_decode(header))
    payload_array = JSON.parse(urlsafe_decode(payload))

    ssl = convert_algorithm(header_array['alg'])
    header  = urlsafe_encode(JSON.generate(header_array)).gsub('=', '')
    payload = urlsafe_encode(JSON.generate(payload_array)).gsub('=', '')
    verify_signature = urlsafe_encode(OpenSSL::HMAC.hexdigest(ssl, secret, header + '.' + payload))
    fail 'invalid signature.' if signature != verify_signature

    [header_array, payload_array]
  end

  private

  def urlsafe_encode(data)
    Base64.urlsafe_encode64(data).gsub('=', '')
  end

  def urlsafe_decode(data)
    lack = data.length % 4
    if lack != 0
      padding = 4 - lack
      data << '=' * padding
    end
    Base64.urlsafe_decode64(data)
  end

  def convert_algorithm(alg)
    if alg == 'HS256'
      OpenSSL::Digest::SHA256.new
    elsif alg == 'HS384'
      OpenSSL::Digest::SHA384.new
    elsif alg == 'HS512'
      OpenSSL::Digest::SHA512.new
    else
      fail "'#{alg}' is unsupported algorithm."
    end
  end
end
