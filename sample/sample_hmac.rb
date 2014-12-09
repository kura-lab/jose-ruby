#! ruby -Ku
# -*- encoding: utf-8 -*-

# JSON Web Token Sample

require 'date'
require '../src/json_web_token'

header = {
  alg: 'HS256',
  typ: 'JWT'
}
time_stamp = Time.now.to_i
payload = {
  iss:   'https://example.com',
  aud:   'client123',
  exp:   time_stamp + 24 * 60 * 60,
  iat:   time_stamp,
  nonce: 'aaabbbccc'
}
secret = 'xxxyyyzzz'

jwt = JsonWebToken.new
enc = jwt.encode(header, payload, secret)
puts "JWT: #{enc}"
