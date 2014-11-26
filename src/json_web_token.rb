require 'base64'
require 'json'
require 'openssl'

#
# JSON Web Token Class
#
class JsonWebToken
  def encode(header, payload, secret)
    h = Base64.urlsafe_encode64(JSON.generate(header)).gsub('=', '')
    p = Base64.urlsafe_encode64(JSON.generate(payload)).gsub('=', '')
    if header[:alg] == 'HS256'
      ssl = OpenSSL::Digest::SHA256.new
    elsif header[:alg] == 'HS384'
      ssl = OpenSSL::Digest::SHA384.new
    elsif header[:alg] == 'HS512'
      ssl = OpenSSL::Digest::SHA512.new
    else
      fail
    end
    sig = OpenSSL::HMAC.hexdigest(ssl, secret, h + p)
    [h, p, sig].join('.')
  end
end
