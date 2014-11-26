require 'spec_helper'
require './src/json_web_token'

describe JsonWebToken do
  it 'is encoded jwt' do
    header = {
      alg: 'HS256',
      typ: 'JWT'
    }
    time_stamp = 1417021392
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
    expect(enc).to eq 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiY2xpZW50MTIzIiwiZXhwIjoxNDE3MTA3NzkyLCJpYXQiOjE0MTcwMjEzOTIsIm5vbmNlIjoiYWFhYmJiY2NjIn0.2dad1d996991292badcfbaa80097b89efc17c7ba7a2fff6c8819b0f33a00e55f'
  end
end
