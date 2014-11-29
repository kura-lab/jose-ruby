require 'spec_helper'
require './src/json_web_token'

describe JsonWebToken do
  before do
    @jwt = JsonWebToken.new
  end

  describe 'convert_algorithm' do
    context 'normal' do
      it 'should return algorithm' do
        {
          'HS256' => OpenSSL::Digest::SHA256,
          'HS384' => OpenSSL::Digest::SHA384,
          'HS512' => OpenSSL::Digest::SHA512,
        }.each { |alg, type|
          ssl = @jwt.instance_eval {
            convert_algorithm(alg)
          }
          expect(ssl.is_a? type).to be_truthy
        }
      end
    end

    context 'error' do
      it 'should fail' do
        alg = 'HS1'
        expect{
          @jwt.instance_eval{convert_algorithm(alg)}
        }.to raise_error(RuntimeError, "'#{alg}' is unsupported algorithm.")
      end
    end
  end
end
