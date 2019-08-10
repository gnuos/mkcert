module Mkcert
  class CaCert < OpenSSL::X509::Certificate
    def self.new(priv_key : OpenSSL::PKey, days : Int32 = 365 * 10)
      raise "failed to generate CA certificate" unless priv_key

      new.tap do |cert|
        name = OpenSSL::X509::Name.new
        name.add_entry "CN", "mkcert #{ENV["USER"]}@#{System.hostname}"
        name.add_entry "O", "mkcert development CA"
        name.add_entry "OU", ENV["USER"] + "@" + System.hostname

        cert.subject = name
        cert.issuer = name
        cert.public_key = priv_key.public_key
        cert.public_key = priv_key if priv_key.is_a?(OpenSSL::EC)

        cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
        cert.not_after = OpenSSL::ASN1::Time.days_from_now(days)

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert

        cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
        cert.add_extension(ef.create_extension("keyUsage", "digitalSignature, keyCertSign, cRLSign", true))
        cert.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth, clientAuth, emailProtection, codeSigning, timeStamping", true))
        cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
        cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always", false))

        cert.sign(priv_key, OpenSSL::Digest::SHA256.new)
      end
    end

    def self.get_caroot : String
      return ENV["CAROOT"] if ENV.has_key?("CAROOT") && !ENV["CAROOT"].empty?

      Path.home.join(".local", "share", "mkcert").to_s
    end
  end
end
