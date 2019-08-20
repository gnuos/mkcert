module Mkcert
  ROOT_CERT_NAME = "rootCA.pem"
  ROOT_KEY_NAME  = "rootCA-key.pem"

  enum KeyType : UInt8
    RSA
    ECC
  end

  class CertPair
    property cert_file : String
    property key_file : String
    property is_client : Bool
    property rootca_dir : String
    property root_cert : String
    property root_key : String
    property ca_cert : OpenSSL::X509::Certificate
    property ca_key : OpenSSL::PKey::PKey

    def initialize(@address : Array(String), @key_type : KeyType, @is_client : Bool,
                   @cert_file : String = "", @key_file : String = "")
      @rootca_dir = CaCert.get_caroot
      @root_cert = Path.new(@rootca_dir).join(ROOT_CERT_NAME).to_s
      @root_key = Path.new(@rootca_dir).join(ROOT_KEY_NAME).to_s

      @ip_addr = @email_addr = @dns_addr = [] of String

      @ca_cert = uninitialized OpenSSL::X509::Certificate
      @ca_key = uninitialized OpenSSL::PKey::PKey
    end

    def generate
      if @rootca_dir.empty?
        raise "Failed to find the default CA location, set one as the CAROOT env var"
        exit(1)
      end

      begin
        Dir.mkdir_p(@rootca_dir, 0o755)

        load_rootca
        parse_san_addr

        san_list = [] of String
        san_list = @ip_addr.map { |ip| "IP:#{ip}" } +
                   @dns_addr.map { |dns| "DNS:#{dns}" } +
                   @email_addr.map { |email| "email:#{email}" }

        ext_usage = ["serverAuth", "clientAuth"]
        unless @is_client
          ext_usage << "codeSigning"
          ext_usage << "emailProtection" if @email_addr.size > 0
        end

        @is_rootca = false
        priv_key = generate_key
        pub_key = priv_key.public_key
        pub_key = priv_key if @key_type == KeyType::ECC

        cert = generate_cert
        cert.public_key = pub_key

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = @ca_cert

        cert.add_extension(ef.create_extension("keyUsage", "digitalSignature, keyEncipherment", true))
        cert.add_extension(ef.create_extension("extendedKeyUsage", ext_usage.join(","), false))
        cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
        cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always, issuer", false))
        cert.add_extension(ef.create_extension("subjectAltName", san_list.join(","), true))

        cert.sign(@ca_key, OpenSSL::Digest::SHA256.new)

        filename = default_name
        @cert_file = "./#{filename}.pem" if @cert_file.empty?
        @key_file = "./#{filename}-key.pem" if @key_file.empty?

        File.write @cert_file, cert.to_pem
        File.write @key_file, priv_key.to_pem, perm = File::Permissions.new(0o600)

        puts "\nCreated a new certificate valid for the following names :"
        @address.each do |addr|
          puts " - #{addr}"
          puts "   Warning: many browsers don't support second-level wildcards like #{addr} !" if SECOND_LEVEL_WILDCARD_REGEXP =~ addr
        end

        @address.each do |addr|
          if addr.starts_with?("*.")
            puts "\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.#{addr[2..-1]} !"
            break
          end
        end

        puts "\nThe certificate is at \"#{@cert_file}\" and the key at \"#{@key_file}\" \n\n"
      rescue
        raise "Failed to create the certificate pair"
        exit(1)
      end
    end

    private def generate_key : OpenSSL::PKey::PKey
      if @key_type == KeyType::ECC
        return OpenSSL::PKey::EC.new(256)
      end
      if @is_rootca
        return OpenSSL::PKey::RSA.new(3072)
      end
      OpenSSL::PKey::RSA.new(2048)
    end

    private def generate_cert : OpenSSL::X509::Certificate
      name = OpenSSL::X509::Name.new
      name.add_entry "O", "mkcert development certificate"
      name.add_entry "OU", ENV["USER"] + "@" + System.hostname

      if @dns_addr.size > 0
        name.add_entry "CN", @dns_addr[0]
      elsif @ip_addr.size > 0
        name.add_entry "CN", @ip_addr[0]
      end

      cert = OpenSSL::X509::Certificate.new
      cert.subject = name
      cert.issuer = @ca_cert.as(typeof(cert)).subject
      cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      cert.not_after = OpenSSL::ASN1::Time.days_from_now(365)

      cert
    end

    private def parse_san_addr
      invalid_addr = [] of String
      ip_addr = [] of String
      email_addr = [] of String
      dns_addr = [] of String

      @address.each do |addr|
        begin
          punycode = URI::Punycode.to_ascii addr

          if IPAddress.valid?(addr)
            ip_addr << addr
            next
          elsif addr =~ EMAIL_ADDRESS_FORMAT
            email_addr << addr
            next
          elsif punycode =~ HOSTNAME_FORMAT
            dns_addr << addr
            next
          else
            invalid_addr << addr
            next
          end
        rescue ex
          if ip_addr.includes?(addr) || dns_addr.includes?(addr)
            next
          else
            invalid_addr << addr
            next
          end
        end
      end

      if invalid_addr.size > 0
        LOG.error "#{invalid_addr.join(", ")} is unavaliable address, cancel generate certificate"
        exit(1)
      end

      @ip_addr, @email_addr, @dns_addr = ip_addr, email_addr, dns_addr
    end

    private def new_rootca
      @is_rootca = true
      priv_key = generate_key
      cert = CaCert.new(priv_key)

      begin
        File.write @root_cert, cert.to_pem
        File.write @root_key, priv_key.to_pem, perm: File::Permissions.new(0o400)

        puts "Created a new local CA at \"#{@rootca_dir}\"\n"
      rescue
        raise "failed to save CA cert and key"
      end
    end

    private def load_rootca
      unless File.exists?(@root_cert) || File.exists?(@root_key)
        new_rootca
      end

      begin
        @ca_cert = OpenSSL::X509::Certificate.new(File.read(@root_cert))
        @ca_key = OpenSSL::PKey.read(File.read(@root_key))

        LOG.info("Using the local CA at \"#{@rootca_dir}\"")
      rescue ex
        raise ex
      end
    end

    private def default_name
      name = @address[0].gsub(":", "_")
      name = name.gsub("*", "_wildcard")
      name += "+#{@address.size - 1}" if @address.size > 1
      name += "-client" if @is_client

      name
    end
  end
end
