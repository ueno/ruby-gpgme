$:.push File.expand_path("../..", __FILE__) # C extension is in the root

require 'gpgme_n'

# TODO without this call one can't GPGME::Ctx.new, find out why
GPGME::gpgme_check_version(nil)

require 'gpgme/constants'
require 'gpgme/ctx'
require 'gpgme/data'
require 'gpgme/error'
require 'gpgme/io_callbacks'
require 'gpgme/key_common'
require 'gpgme/key'
require 'gpgme/sub_key'
require 'gpgme/key_sig'
require 'gpgme/misc'
require 'gpgme/signature'
require 'gpgme/user_id'
require 'gpgme/engine'
require 'gpgme/crypto'

module GPGME
  class << self

    # From the c extension
    alias pubkey_algo_name gpgme_pubkey_algo_name
    alias hash_algo_name gpgme_hash_algo_name

    ##
    # Auxiliary method used by all the library to generate exceptions
    # from error codes returned by the C extension.
    def error_to_exception(err)
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

    ##
    # TODO find out what it does, can't seem to find a proper parameter that
    # returns something other than nil.
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

  end
end
