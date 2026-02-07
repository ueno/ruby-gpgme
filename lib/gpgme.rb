require 'gpgme_n'
require 'monitor'

# This call initializes the GPGME library and must happen before
# any GPGME operations (e.g. Ctx.new) can succeed.
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

  # Mutex for serializing GPGME operations when thread safety is enabled.
  # While the underlying GPGME C library supports separate contexts in
  # separate threads, the communication with gpg-agent over Unix domain
  # sockets can produce "Bad file descriptor" errors under heavy concurrent
  # load. Enable thread-safe mode to serialize operations.
  #
  # A Monitor is used instead of a Mutex because GPGME operations are
  # reentrant — e.g. Crypto#sign calls Ctx.new, and within that block,
  # Key.find calls Ctx.new again.
  #
  # @example
  #   GPGME.thread_safe = true
  #
  @thread_safe_mutex = Monitor.new
  @thread_safe = false

  class << self

    # Enable or disable thread-safe mode. When enabled, all high-level
    # GPGME operations (encrypt, decrypt, sign, verify, key listing, etc.)
    # will be serialized through a global mutex to prevent concurrent
    # access to gpg-agent from causing "Bad file descriptor" errors.
    #
    # @param [Boolean] value true to enable thread-safe mode
    attr_writer :thread_safe

    # Returns true if thread-safe mode is enabled.
    def thread_safe?
      @thread_safe
    end

    # The mutex used for thread-safe serialization. Can be used directly
    # if you need finer-grained control over locking.
    #
    # @example manual locking
    #   GPGME.synchronize do
    #     # multiple GPGME operations atomically
    #   end
    attr_reader :thread_safe_mutex

    # Execute a block with the GPGME mutex held if thread-safe mode is
    # enabled. If thread-safe mode is disabled, the block is executed
    # directly without locking.
    def synchronize(&block)
      if @thread_safe
        @thread_safe_mutex.synchronize(&block)
      else
        yield
      end
    end

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
