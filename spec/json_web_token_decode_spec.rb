require 'spec_helper'
require './src/json_web_token'

describe JsonWebToken do
  before do
    @jwt = JsonWebToken.new
    @issued_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiY2xpZW50MTIzIiwic3ViIjoidXNlcjEyMyIsImV4cCI6MTQxNzEwNzc5MiwiaWF0IjoxNDE3MDIxMzkyLCJub25jZSI6ImFhYWJiYmNjYyJ9.YTNiZTFmMzczM2E2OTBhOWZiNzM1MTliYmIzMzU4MzI0YmM1ZDIzNWNhYmE4NjViZTM1NmIxNDE1ODQwM2FkNg'
    @secret = 'xxxyyyzzz'
    @time_stamp = 1417021392
  end

  describe 'decode' do
    context 'normal' do
      it 'is decoded jwt' do
        header, payload = @jwt.decode(@issued_jwt, @secret)
        expect(header['alg']).to eq 'HS256'
        expect(header['typ']).to eq 'JWT'
        expect(payload['iss']).to eq 'https://example.com'
        expect(payload['aud']).to eq 'client123'
        expect(payload['sub']).to eq 'user123'
        expect(payload['exp']).to eq @time_stamp + 24 * 60 * 60
        expect(payload['iat']).to eq @time_stamp
        expect(payload['nonce']).to eq 'aaabbbccc'
      end
    end

    context 'error' do
      it 'should fail' do
        expect{
          @jwt.decode(['Array'], @secret)
        }.to raise_error(RuntimeError, 'require jwt of string type.')
      end

      it 'should fail' do
        [
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiY2xpZW50MTIzIiwic3ViIjoidXNlcjEyMyIsImV4cCI6MTQxNzEwNzc5MiwiaWF0IjoxNDE3MDIxMzkyLCJub25jZSI6ImFhYWJiYmNjYyJ9'
        ].each { |val|
          expect{
            @jwt.decode(val, @secret)
          }.to raise_error(RuntimeError, 'require jwt format.')
        }
      end

      it 'should fail' do
        expect{
          @jwt.decode(@issued_jwt, 'invalid_secret')
        }.to raise_error(RuntimeError, 'invalid signature.')
      end
    end
  end
end
