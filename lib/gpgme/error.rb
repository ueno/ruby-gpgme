module GPGME
  class Error < StandardError
    def initialize(error)
      @error = error
    end
    attr_reader :error

    # Return the error code.
    #
    # The error code indicates the type of an error, or the reason why
    # an operation failed.
    def code
      GPGME::gpgme_err_code(@error)
    end

    # Return the error source.
    #
    # The error source has not a precisely defined meaning.  Sometimes
    # it is the place where the error happened, sometimes it is the
    # place where an error was encoded into an error value.  Usually
    # the error source will give an indication to where to look for
    # the problem.  This is not always true, but it is attempted to
    # achieve this goal.
    def source
      GPGME::gpgme_err_source(@error)
    end

    # Return a description of the error code.
    def message
      GPGME::gpgme_strerror(@error)
    end

    class General < self; end
    class InvalidValue < self; end
    class UnusablePublicKey < self
      attr_accessor :keys
    end
    class UnusableSecretKey < self
      attr_accessor :keys
    end
    class NoData < self; end
    class Conflict < self; end
    class NotImplemented < self; end
    class DecryptFailed < self; end
    class BadPassphrase < self; end
    class Canceled < self; end
    class InvalidEngine < self; end
    class AmbiguousName < self; end
    class WrongKeyUsage < self
      attr_accessor :key_usage
    end
    class CertificateRevoked < self; end
    class CertificateExpired < self; end
    class NoCRLKnown < self; end
    class NoPolicyMatch < self; end
    class NoSecretKey < self; end
    class MissingCertificate < self; end
    class BadCertificateChain < self; end
    class UnsupportedAlgorithm < self
      attr_accessor :algorithm
    end
    class BadSignature < self; end
    class NoPublicKey < self; end
    class InvalidVersion < self; end
  end
end
