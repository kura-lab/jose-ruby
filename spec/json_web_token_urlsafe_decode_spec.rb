require 'spec_helper'
require './src/json_web_token'

describe JsonWebToken do
  before do
    @jwt = JsonWebToken.new
  end

  it 'is urlsafe_decode' do
    data = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5'
    dec = @jwt.instance_eval {
      urlsafe_decode(data)
    }
    expect(dec).to eq 'abcdefghijklmnopqrstuvwxyz0123456789'
  end
end
