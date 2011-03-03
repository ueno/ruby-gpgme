module GPGME

  # Only purpose is to clean the root GPGME module.
  module Aux

    # Verify that the engine implementing the protocol <i>proto</i> is
    # installed in the system.
    def engine_check_version(proto)
      err = GPGME::gpgme_engine_check_version(proto)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Return a list of info structures of enabled engines.
    def engine_info
      rinfo = Array.new
      GPGME::gpgme_get_engine_info(rinfo)
      rinfo
    end

    # Change the default configuration of the crypto engine implementing
    # protocol <i>proto</i>.
    #
    # <i>file_name</i> is the file name of the executable program
    # implementing the protocol.
    # <i>home_dir</i> is the directory name of the configuration directory.
    def set_engine_info(proto, file_name, home_dir)
      err = GPGME::gpgme_set_engine_info(proto, file_name, home_dir)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    def error_to_exception(err)   # :nodoc:
      case GPGME::gpgme_err_code(err)
      when GPG_ERR_EOF
        EOFError.new
      when GPG_ERR_NO_ERROR
        nil
      when GPG_ERR_GENERAL
        Error::General.new(err)
      when GPG_ERR_ENOMEM
        Errno::ENOMEM.new
      when GPG_ERR_INV_VALUE
        Error::InvalidValue.new(err)
      when GPG_ERR_UNUSABLE_PUBKEY
        Error::UnusablePublicKey.new(err)
      when GPG_ERR_UNUSABLE_SECKEY
        Error::UnusableSecretKey.new(err)
      when GPG_ERR_NO_DATA
        Error::NoData.new(err)
      when GPG_ERR_CONFLICT
        Error::Conflict.new(err)
      when GPG_ERR_NOT_IMPLEMENTED
        Error::NotImplemented.new(err)
      when GPG_ERR_DECRYPT_FAILED
        Error::DecryptFailed.new(err)
      when GPG_ERR_BAD_PASSPHRASE
        Error::BadPassphrase.new(err)
      when GPG_ERR_CANCELED
        Error::Canceled.new(err)
      when GPG_ERR_INV_ENGINE
        Error::InvalidEngine.new(err)
      when GPG_ERR_AMBIGUOUS_NAME
        Error::AmbiguousName.new(err)
      when GPG_ERR_WRONG_KEY_USAGE
        Error::WrongKeyUsage.new(err)
      when GPG_ERR_CERT_REVOKED
        Error::CertificateRevoked.new(err)
      when GPG_ERR_CERT_EXPIRED
        Error::CertificateExpired.new(err)
      when GPG_ERR_NO_CRL_KNOWN
        Error::NoCRLKnown.new(err)
      when GPG_ERR_NO_POLICY_MATCH
        Error::NoPolicyMatch.new(err)
      when GPG_ERR_NO_SECKEY
        Error::NoSecretKey.new(err)
      when GPG_ERR_MISSING_CERT
        Error::MissingCertificate.new(err)
      when GPG_ERR_BAD_CERT_CHAIN
        Error::BadCertificateChain.new(err)
      when GPG_ERR_UNSUPPORTED_ALGORITHM
        Error::UnsupportedAlgorithm.new(err)
      when GPG_ERR_BAD_SIGNATURE
        Error::BadSignature.new(err)
      when GPG_ERR_NO_PUBKEY
        Error::NoPublicKey.new(err)
      else
        Error.new(err)
      end
    end

    private

    def split_args(args_options)
      if args_options.length > 0 and args_options[-1].respond_to? :to_hash
        args = args_options[0 ... -1]
        options = args_options[-1].to_hash
      else
        args = args_options
        options = Hash.new
      end
      [args, options]
    end

    def check_version(options = nil)
      version = nil
      if options.kind_of?(String)
        version = options
      elsif options.include?(:version)
        version = options[:version]
      end
      unless GPGME::gpgme_check_version(version)
        raise Error::InvalidVersion.new
      end
    end

    def resolve_keys(keys_or_names, secret_only, purposes = Array.new)
      keys = Array.new
      keys_or_names.each do |key_or_name|
        if key_or_name.kind_of? Key
          keys << key_or_name
        elsif key_or_name.kind_of? String
          GPGME::Ctx.new do |ctx|
            key = ctx.keys(key_or_name, secret_only).find {|k|
              k.usable_for?(purposes)
            }
            keys << key if key
          end
        end
      end
      keys
    end

    def input_data(input)
      if input.kind_of? GPGME::Data
        input
      elsif input.respond_to? :to_str
        GPGME::Data.from_str(input.to_str)
      elsif input.respond_to? :read
        GPGME::Data.from_callbacks(IOCallbacks.new(input))
      else
        raise ArgumentError, input.inspect
      end
    end

    def output_data(output)
      if output.kind_of? GPGME::Data
        output
      elsif output.respond_to? :write
        GPGME::Data.from_callbacks(IOCallbacks.new(output))
      elsif !output
        GPGME::Data.empty
      else
        raise ArgumentError, output.inspect
      end
    end

  end # Aux
end # GPGME
