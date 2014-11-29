require 'spec_helper'
require './src/json_web_token'

describe JsonWebToken do
  before do
    @jwt = JsonWebToken.new
  end

  it 'is urlsafe_encode' do
    data = 'abcdefghijklmnopqrstuvwxyz0123456789'
    enc = @jwt.instance_eval {
      urlsafe_encode(data)
    }
    expect(enc).to eq 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5'
  end
end
