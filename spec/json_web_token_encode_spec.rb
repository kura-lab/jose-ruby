require 'spec_helper'
require './src/json_web_token'

describe JsonWebToken do
  before do
    @jwt = JsonWebToken.new
    @issued_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiY2xpZW50MTIzIiwic3ViIjoidXNlcjEyMyIsImV4cCI6MTQxNzEwNzc5MiwiaWF0IjoxNDE3MDIxMzkyLCJub25jZSI6ImFhYWJiYmNjYyJ9.YTNiZTFmMzczM2E2OTBhOWZiNzM1MTliYmIzMzU4MzI0YmM1ZDIzNWNhYmE4NjViZTM1NmIxNDE1ODQwM2FkNg'
    @secret = 'xxxyyyzzz'
    @time_stamp = 1417021392
  end

  it 'is encoded jwt' do
    header = {
      alg: 'HS256',
      typ: 'JWT'
    }
    payload = {
      iss:   'https://example.com',
      aud:   'client123',
      sub:   'user123',
      exp:   @time_stamp + 24 * 60 * 60,
      iat:   @time_stamp,
      nonce: 'aaabbbccc'
    }
    enc = @jwt.encode(header, payload, @secret)
    expect(enc).to eq @issued_jwt
  end
end
