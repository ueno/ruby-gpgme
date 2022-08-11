module GPGME

  ##
  # Different, independent methods providing the simplest possible API to
  # execute crypto operations via GPG. All methods accept as options the same
  # common options as {GPGME::Ctx.new}. Read the documentation for that class to
  # know how to customize things further (like output stuff in ASCII armored
  # format, for example).
  #
  # @example
  #   crypto = GPGME::Crypto.new :armor => true
  #   encrypted = crypto.encrypt 'Plain text'
  #
  class Crypto

    attr_reader :default_options

    def initialize(options = {})
      @default_options = options
    end

    ##
    # Encrypts an element
    #
    #  crypto.encrypt something, options
    #
    # Will return a {GPGME::Data} element which can then be read.
    #
    # Must have some key imported, look for {GPGME::Key.import} to know how
    # to import one, or the gpg documentation to know how to create one
    #
    # @param plain
    #  Must be something that can be converted into a {GPGME::Data} object, or
    #  a {GPGME::Data} object itself.
    #
    # @param [Hash] options
    #  The optional parameters are as follows:
    #   * +:recipients+ for which recipient do you want to encrypt this file. It
    #     will pick the first one available if none specified. Can be an array of
    #     identifiers or just one (a string).
    #   * +:symmetric+ if set to true, will ignore +:recipients+, and will perform
    #     a symmetric encryption. Must provide a password via the +:password+
    #     option.
    #   * +:always_trust+ if set to true specifies all the recipients to be
    #     trusted, thus not requiring confirmation.
    #   * +:sign+ if set to true, performs a combined sign and encrypt operation.
    #   * +:signers+ if +:sign+ specified to true, a list of additional possible
    #     signers. Must be an array of sign identifiers.
    #   * +:output+ if specified, it will write the output into it. It will be
    #     converted to a {GPGME::Data} object, so it could be a file for example.
    #   * Any other option accepted by {GPGME::Ctx.new}
    #
    # @return [GPGME::Data] a {GPGME::Data} object that can be read.
    #
    # @example returns a {GPGME::Data} that can be later encrypted
    #  encrypted = crypto.encrypt "Hello world!"
    #  encrypted.read # => Encrypted stuff
    #
    # @example to be decrypted by someone@example.com.
    #  crypto.encrypt "Hello", :recipients => "someone@example.com"
    #
    # @example If I didn't trust any of my keys by default
    #  crypto.encrypt "Hello" # => GPGME::Error::General
    #  crypto.encrypt "Hello", :always_trust => true # => Will work fine
    #
    # @example encrypted string that can be decrypted and/or *verified*
    #  crypto.encrypt "Hello", :sign => true
    #
    # @example multiple signers
    #  crypto.encrypt "Hello", :sign => true, :signers => "extra@example.com"
    #
    # @example writing to a file instead
    #  file = File.open("signed.sec","w+")
    #  crypto.encrypt "Hello", :output => file # output written to signed.sec
    #
    # @raise [GPGME::Error::General] when trying to encrypt with a key that is
    #   not trusted, and +:always_trust+ wasn't specified
    #
    def encrypt(plain, options = {})
      options = @default_options.merge options

      plain_data  = Data.new(plain)
      cipher_data = Data.new(options[:output])
      keys        = Key.find(:public, options[:recipients])
      keys        = nil if options[:symmetric]

      flags = 0
      flags |= GPGME::ENCRYPT_ALWAYS_TRUST if options[:always_trust]

      GPGME::Ctx.new(options) do |ctx|
        begin
          if options[:sign]
            if options[:signers]
              signers = Key.find(:public, options[:signers], :sign)
              ctx.add_signer(*signers)
            end
            ctx.encrypt_sign(keys, plain_data, cipher_data, flags)
          else
            ctx.encrypt(keys, plain_data, cipher_data, flags)
          end
        rescue GPGME::Error::UnusablePublicKey => exc
          exc.keys = ctx.encrypt_result.invalid_recipients
          raise exc
        rescue GPGME::Error::UnusableSecretKey => exc
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end
      end

      cipher_data.seek(0)
      cipher_data
    end

    ##
    # Decrypts a previously encrypted element
    #
    #   crypto.decrypt cipher, options, &block
    #
    # Must have the appropiate key to be able to decrypt, of course. Returns
    # a {GPGME::Data} object which can then be read.
    #
    # @param cipher
    #   Must be something that can be converted into a {GPGME::Data} object,
    #   or a {GPGME::Data} object itself. It is the element that will be
    #   decrypted.
    #
    # @param [Hash] options
    #   The optional parameters:
    #   * +:output+ if specified, it will write the output into it. It will
    #     me converted to a {GPGME::Data} object, so it can also be a file,
    #     for example.
    #   * If the file was encrypted with symmetric encryption, must provide
    #     a :password option.
    #   * Any other option accepted by {GPGME::Ctx.new}
    #
    # @param &block
    #   In the block all the signatures are yielded, so one could verify them.
    #   See examples.
    #
    # @return [GPGME::Data] a {GPGME::Data} that can be read.
    #
    # @example Simple decrypt
    #   crypto.decrypt encrypted_data
    #
    # @example symmetric encryption, or passwored key
    #   crypto.decrypt encrypted_data, :password => "gpgme"
    #
    # @example Output to file
    #   file = File.open("decrypted.txt", "w+")
    #   crypto.decrypt encrypted_data, :output => file
    #
    # @example Verifying signatures
    #   crypto.decrypt encrypted_data do |signature|
    #     raise "Signature could not be verified" unless signature.valid?
    #   end
    #
    # @raise [GPGME::Error::UnsupportedAlgorithm] when the cipher was encrypted
    #   using an algorithm that's not supported currently.
    #
    # @raise [GPGME::Error::WrongKeyUsage] TODO Don't know when
    #
    # @raise [GPGME::Error::DecryptFailed] when the cipher was encrypted
    #   for a key that's not available currently.
    def decrypt(cipher, options = {})
      options = @default_options.merge options

      plain_data   = Data.new(options[:output])
      cipher_data  = Data.new(cipher)

      GPGME::Ctx.new(options) do |ctx|
        begin
          ctx.decrypt_verify(cipher_data, plain_data)
        rescue GPGME::Error::UnsupportedAlgorithm => exc
          exc.algorithm = ctx.decrypt_result.unsupported_algorithm
          raise exc
        rescue GPGME::Error::WrongKeyUsage => exc
          exc.key_usage = ctx.decrypt_result.wrong_key_usage
          raise exc
        end

        verify_result = ctx.verify_result
        if verify_result && block_given?
          verify_result.signatures.each do |signature|
            yield signature
          end
        end

      end

      plain_data.seek(0)
      plain_data
    end

    ##
    # Creates a signature of a text
    #
    #   crypto.sign text, options
    #
    # Must have the appropiate key to be able to decrypt, of course. Returns
    # a {GPGME::Data} object which can then be read.
    #
    # @param text
    #   The object that will be signed. Must be something that can be converted
    #   to {GPGME::Data}.
    #
    # @param [Hash] options
    #  Optional parameters.
    #   * +:signer+ sign identifier to sign the text with. Will use the first
    #    key it finds if none specified.
    #   * +:output+ if specified, it will write the output into it. It will be
    #     converted to a {GPGME::Data} object, so it could be a file for example.
    #   * +:mode+ Desired type of signature. Options are:
    #    - +GPGME::SIG_MODE_NORMAL+ for a normal signature. The default one if
    #      not specified.
    #    - +GPGME::SIG_MODE_DETACH+ for a detached signature
    #    - +GPGME::SIG_MODE_CLEAR+ for a cleartext signature
    #   * Any other option accepted by {GPGME::Ctx.new}
    #
    # @return [GPGME::Data] a {GPGME::Data} that can be read.
    #
    # @example normal sign
    #   crypto.sign "Hi there"
    #
    # @example outputing to a file
    #   file = File.open("text.sign", "w+")
    #   crypto.sign "Hi there", :options => file
    #
    # @example doing a detached signature
    #   crypto.sign "Hi there", :mode => GPGME::SIG_MODE_DETACH
    #
    # @example specifying the signer
    #   crypto.sign "Hi there", :signer => "mrsimo@example.com"
    #
    # @raise [GPGME::Error::UnusableSecretKey] TODO don't know when
    def sign(text, options = {})
      options = @default_options.merge options

      plain  = Data.new(text)
      output = Data.new(options[:output])
      mode   = options[:mode] || GPGME::SIG_MODE_NORMAL

      GPGME::Ctx.new(options) do |ctx|
        if options[:signer]
          signers = Key.find(:secret, options[:signer], :sign)
          ctx.add_signer(*signers)
        end

        begin
          ctx.sign(plain, output, mode)
        rescue GPGME::Error::UnusableSecretKey => exc
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end
      end

      output.seek(0)
      output
    end

    # Verifies a previously signed element
    #
    #   crypto.verify sig, options, &block
    #
    # Must have the proper keys available.
    #
    # @param sig
    #   The signature itself. Must be possible to convert into a {GPGME::Data}
    #   object, so can be a file.
    #
    # @param [Hash] options
    #   * +:signed_text+ if the sign is detached, then must be the plain text
    #     for which the signature was created.
    #   * +:output+ where to store the result of the signature. Will be
    #     converted to a {GPGME::Data} object.
    #   * Any other option accepted by {GPGME::Ctx.new}
    #
    # @param &block
    #   In the block all the signatures are yielded, so one could verify them.
    #   See examples.
    #
    # @return [GPGME::Data] unless the sign is detached, the {GPGME::Data}
    #   object with the plain text. If the sign is detached, will return nil.
    #
    # @example simple verification
    #   sign = crypto.sign("Hi there")
    #   data = crypto.verify(sign) { |signature| signature.valid? }
    #   data.read # => "Hi there"
    #
    # @example saving output to file
    #   sign = crypto.sign("Hi there")
    #   out  = File.open("test.asc", "w+")
    #   crypto.verify(sign, :output => out) {|signature| signature.valid?}
    #   out.read # => "Hi there"
    #
    # @example verifying a detached signature
    #   sign = crypto.detach_sign("Hi there")
    #   # Will fail
    #   crypto.verify(sign) { |signature| signature.valid? }
    #   # Will succeed
    #   crypto.verify(sign, :signed_text => "hi there") do |signature|
    #     signature.valid?
    #   end
    #
    def verify(sig, options = {})
      options = @default_options.merge options

      sig         = Data.new(sig)
      signed_text = Data.new(options[:signed_text])
      output      = Data.new(options[:output]) unless options[:signed_text]

      GPGME::Ctx.new(options) do |ctx|
        ctx.verify(sig, signed_text, output)
        ctx.verify_result.signatures.each do |signature|
          yield signature
        end
      end

      if output
        output.seek(0)
        output
      end
    end

    # Clearsigns an element
    #
    #   crypto.clearsign text, options
    #
    # Same functionality of {.sign} only doing clearsigns by default.
    #
    def clearsign(text, options = {})
      sign text, options.merge(:mode => GPGME::SIG_MODE_CLEAR)
    end

    # Creates a detached signature of an element
    #
    #   crypto.detach_sign text, options
    #
    # Same functionality of {.sign} only doing detached signs by default.
    #
    def detach_sign(text, options = {})
      sign text, options.merge(:mode => GPGME::SIG_MODE_DETACH)
    end

    ##
    # Allows calling of methods directly in the module without the need to
    # create a new instance.
    def self.method_missing(method, *args, &block)
      if GPGME::Crypto.instance_methods(false).include?(method)
        crypto = GPGME::Crypto.new
        crypto.send method, *args, &block
      else
        super
      end
    end

  end # module Crypto
end # module GPGME
