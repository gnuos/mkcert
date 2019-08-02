require "./spec_helper"

describe Mkcert::CaCert do
  it "can generate rootCA" do
    key = OpenSSL::EC.new(256)
    ca = Mkcert::CaCert.new(key)

    puts ca.to_pem
  end
end
