require "spec_helper"
require "./src/json_web_token"

describe JsonWebToken do
  it "is encoded jwt" do
    jwt = JsonWebToken.new()
    expect(jwt.encode).to eq ''
  end
end
