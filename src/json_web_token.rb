require 'base64'
require 'json'
require 'openssl'
include OpenSSL::PKey

#
# JSON Web Token Class
#
class JsonWebToken
  public

  def encode(header_array, payload_array, secret)
    header  = urlsafe_encode(JSON.generate(header_array)).gsub('=', '')
    payload = urlsafe_encode(JSON.generate(payload_array)).gsub('=', '')

    if /^HS/ =~ header_array[:alg]
      signature = sign_hmac(header_array[:alg], header + '.' + payload, secret)
    elsif /^RS/ =~ header_array[:alg]
      signature = sign_rsa(header_array[:alg], header + '.' + payload, secret)
    else
      fail "'#{alg}' is unsupported algorithm."
    end
    [header, payload, signature].join('.')
  end

  def decode(jwt, secret)
    fail 'require jwt of string type.' unless jwt.is_a?(String)
    header, payload, signature = jwt.split('.')
    fail 'require jwt format.' if header.nil? || payload.nil? || signature.nil?
    header_array  = JSON.parse(urlsafe_decode(header))
    payload_array = JSON.parse(urlsafe_decode(payload))
    header  = urlsafe_encode(JSON.generate(header_array)).gsub('=', '')
    payload = urlsafe_encode(JSON.generate(payload_array)).gsub('=', '')

    if /^HS/ =~ header_array['alg']
      result = verify_hmac(header_array['alg'], header + '.' + payload, secret, signature)
    elsif /^RS/ =~ header_array['alg']
      result = verify_rsa(header_array['alg'], header + '.' + payload, secret, signature)
    else
      fail "'#{alg}' is unsupported algorithm."
    end
    fail 'invalid signature.' if result == false

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

  def sign_hmac(alg, data, secret)
    digest = convert_algorithm_hmac(alg)
    urlsafe_encode(OpenSSL::HMAC.hexdigest(digest, secret, data))
  end

  def sign_rsa(alg, data, key)
    digest = convert_algorithm_rsa(alg)
    pkey = OpenSSL::PKey::RSA.new(key)
    urlsafe_encode(pkey.sign(digest, data))
  end

  def verify_hmac(alg, data, secret, signature)
    sig = sign_hmac(alg, data, secret)
    if signature == sig
      true
    else
      false
    end
  end

  def verify_rsa(alg, data, key, signature)
    digest = convert_algorithm_rsa(alg)
    pkey = OpenSSL::PKey::RSA.new(key)
    pub_key = pkey.public_key
    pub_key.verify(digest, signature, data)
  end

  def convert_algorithm_hmac(alg)
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

  def convert_algorithm_rsa(alg)
    if alg == 'RS256'
      OpenSSL::Digest::SHA256.new
    elsif alg == 'RS384'
      OpenSSL::Digest::SHA384.new
    elsif alg == 'RS512'
      OpenSSL::Digest::SHA512.new
    else
      fail "'#{alg}' is unsupported algorithm."
    end
  end
end
