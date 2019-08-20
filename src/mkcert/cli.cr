require "commander"
require "ipaddress"
require "logger"

module Mkcert
  LOG = Logger.new(STDOUT, level: Logger::WARN)

  SECOND_LEVEL_WILDCARD_REGEXP = /(?i)^\*\.[0-9a-z_-]+$/
  HOSTNAME_FORMAT              = /(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$/
  EMAIL_ADDRESS_FORMAT         = /\A[a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`^{\|\}\~]+(\.[a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`^{\|\}\~]+)*@[a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`^{\|\}\~]+(\.[a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`^{\|\}\~]+)+\z/

  class Cli
    def self.run
      cli = Commander::Command.new do |cmd|
        cmd.use = "mkcert"
        cmd.long = "A simple tool for making locally-trusted development certificates."

        cmd.flags.add do |flag|
          flag.name = "rsa"
          flag.short = "-r"
          flag.long = "--rsa"
          flag.default = false
          flag.description = "Generate a certificate with an RSA key."
        end

        cmd.flags.add do |flag|
          flag.name = "ecc"
          flag.short = "-e"
          flag.long = "--ecc"
          flag.default = false
          flag.description = "Generate a certificate with an ECC key."
        end

        cmd.flags.add do |flag|
          flag.name = "client"
          flag.short = "-c"
          flag.long = "--client"
          flag.default = false
          flag.description = "Generate a certificate for client authentication."
        end

        cmd.flags.add do |flag|
          flag.name = "caroot"
          flag.short = ""
          flag.long = "--CAROOT"
          flag.default = false
          flag.description = "Print the CA certificate and key storage location."
        end

        cmd.flags.add do |flag|
          flag.name = "cert-file"
          flag.short = ""
          flag.long = "--cert-file"
          flag.default = ""
          flag.description = "Customize the output paths of certificate file."
        end

        cmd.flags.add do |flag|
          flag.name = "key-file"
          flag.short = ""
          flag.long = "--key-file"
          flag.default = ""
          flag.description = "Customize the output paths of key file."
        end

        cmd.run do |options, arguments|
          if ARGV.size == 0
            puts cmd.help
            exit
          end

          if options.bool["caroot"]
            puts CaCert.get_caroot
            exit
          end

          if !options.bool["rsa"] && !options.bool["ecc"]
            puts cmd.help
            exit 1
          end

          if options.bool["rsa"] && options.bool["ecc"]
            LOG.error "Can only specity one between rsa and ecc"
            exit(1)
          end

          if arguments.size == 0
            puts cmd.help
            exit
          end

          key_type = KeyType.new 0

          if options.bool["rsa"]
            key_type = KeyType::RSA
          elsif options.bool["ecc"]
            key_type = KeyType::ECC
          end

          cert_pair = CertPair.new(arguments, key_type, options.bool["client"],
            options.string["cert-file"], options.string["key-file"])
          cert_pair.generate
        end
      end
      Commander.run(cli, ARGV)
    end
  end
end
