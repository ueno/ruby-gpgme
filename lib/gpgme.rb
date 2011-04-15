$:.push File.expand_path("../..", __FILE__) # C extension is in the root

require 'gpgme_n'
require 'gpgme/constants'
require 'gpgme/aux'
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

module GPGME

  extend Aux

  PROTOCOL_NAMES = {
    PROTOCOL_OpenPGP => :OpenPGP,
    PROTOCOL_CMS => :CMS
  }

  KEYLIST_MODE_NAMES = {
    KEYLIST_MODE_LOCAL => :local,
    KEYLIST_MODE_EXTERN => :extern,
    KEYLIST_MODE_SIGS => :sigs,
    KEYLIST_MODE_VALIDATE => :validate
  }

  VALIDITY_NAMES = {
    VALIDITY_UNKNOWN => :unknown,
    VALIDITY_UNDEFINED => :undefined,
    VALIDITY_NEVER => :never,
    VALIDITY_MARGINAL => :marginal,
    VALIDITY_FULL => :full,
    VALIDITY_ULTIMATE => :ultimate
  }

  class << self

    # From the c extension
    alias pubkey_algo_name gpgme_pubkey_algo_name
    alias hash_algo_name gpgme_hash_algo_name

  end

  class << self

    ##
    # Encrypts an element
    #
    #  GPGME.encrypt something, options
    #
    # Will return a {GPGME::Data} element which can then be read.
    #
    # Must have some key imported, look for {GPGME.import} to know how
    # to import one, or the gpg documentation to know how to create one
    #
    # @param plain
    #  Must be something that can be converted into a {GPGME::Data} object, or
    #  a {GPGME::Data} object itself.
    #
    # @param [Hash] options
    #  The optional parameters are as follows:
    #  * +:recipients+ for which recipient do you want to encrypt this file. It
    #    will pick the first one available if none specified. Can be an array of
    #    identifiers or just one (a string).
    #  * +:always_trust+ if set to true specifies all the recipients to be
    #    trusted, thus not requiring confirmation.
    #  * +:sign+ if set to true, performs a combined sign and encrypt operation.
    #  * +:signers+ if +:sign+ specified to true, a list of additional possible
    #    signers. Must be an array of sign identifiers.
    #  * +:output+ if specified, it will write the output into it. It will be
    #    converted to a {GPGME::Data} object, so it could be a file for example.
    #
    # @return [GPGME::Data] a {GPGME::Data} object that can be read.
    #
    # @example returns a {GPGME::Data} that can be later encrypted
    #  encrypted = GPGME.encrypt "Hello world!"
    #  encrypted.read # => Encrypted stuff
    #
    # @example to be decrypted by someone@example.com.
    #  GPGME.encrypt "Hello", :recipients => "someone@example.com"
    #
    # @example If I didn't trust any of my keys by default
    #  GPGME.encrypt "Hello" # => GPGME::Error::General
    #  GPGME.encrypt "Hello", :always_trust => true # => Will work fine
    #
    # @example encrypted string that can be decrypted and/or *verified*
    #  GPGME.encrypt "Hello", :sign => true
    #
    # @example multiple signers
    #  GPGME.encrypt "Hello", :sign => true, :signers => "extra@example.com"
    #
    # @example writing to a file instead
    #  file = File.new("signed.sec","wa")
    #  GPGME.encrypt "Hello", :output => file # output written to signed.sec
    #
    # @raise [GPGME::Error::General] when trying to encrypt with a key that is
    #   not trusted, and +:always_trust+ wasn't specified
    #
    def encrypt(plain, options = {})
      check_version(options) # TODO what does it do?

      plain_data  = Data.new(plain)
      cipher_data = Data.new(options[:output])
      keys        = Key.find(:public, options[:recipients])

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
    #   GPGME.decrypt cipher, options, &block
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
    #
    # @param &block
    #   In the block all the signatures are yielded, so one could verify them.
    #   See examples.
    #
    # @return [GPGME::Data] a {GPGME::Data} that can be read.
    #
    # @example Simple decrypt
    #   GPGME.decrypt encrypted_data
    #
    # @example Output to file
    #   file = File.new("decrypted.txt")
    #   GPGME.decrypt encrypted_data, :output => file
    #
    # @example Verifying signatures
    #   GPGME.decrypt encrypted_data do |signature|
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
      check_version(options)

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
    #   GPGME.sign text, options
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
    #  * +:signer+ sign identifier to sign the text with. Will use the first
    #   key it finds if none specified.
    #  * +:output+ if specified, it will write the output into it. It will be
    #    converted to a {GPGME::Data} object, so it could be a file for example.
    #  * +:mode+ Desired type of signature. Options are:
    #   - +GPGME::SIG_MODE_NORMAL+ for a normal signature. The default one if
    #     not specified.
    #   - +GPGME::SIG_MODE_DETACH+ for a detached signature
    #   - +GPGME::SIG_MODE_CLEAR+ for a cleartext signature
    #
    # @return [GPGME::Data] a {GPGME::Data} that can be read.
    #
    # @example normal sign
    #  GPGME.sign "Hi there"
    #
    # @example outputing to a file
    #  file = File.new("text.sign")
    #  GPGME.sign "Hi there", :options => file
    #
    # @example doing a detached signature
    #  GPGME.sign "Hi there", :mode => GPGME::SIG_MODE_DETACH
    #
    # @example specifying the signer
    #  GPGME.sign "Hi there", :signer => "mrsimo@example.com"
    #
    # @raise [GPGME::Error::UnusableSecretKey] TODO don't know
    def sign(text, options = {})
      check_version(options) # TODO no idea what it does

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
    #   GPGME.verify sig, options, &block
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
    # @param &block
    #   In the block all the signatures are yielded, so one could verify them.
    #   See examples.
    #
    # @return [GPGME::Data] unless the sign is detached, the {GPGME::Data}
    #   object with the plain text. If the sign is detached, will return nil.
    #
    # @example simple verification
    #   sign = GPGME.sign("Hi there")
    #   data = GPGME.verify(sign) { |signature| signature.valid? }
    #   data.read # => "Hi there"
    #
    # @example saving output to file
    #   sign = GPGME.sign("Hi there")
    #   out  = File.open("test.asc", "w+")
    #   GPGME.verify(sign, :output => out) {|signature| signature.valid?}
    #   out.read # => "Hi there"
    #
    # @example verifying a detached signature
    #   sign = GPGME.detach_sign("Hi there")
    #   # Will fail
    #   GPGME.verify(sign) { |signature| signature.valid? }
    #   # Will succeed
    #   GPGME.verify(sign, :signed_text => "hi there") do |signature|
    #     signature.valid?
    #   end
    #
    def verify(sig, options = {}) # :yields: signature
      check_version(options) # TODO no idea what it does

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
      keys
    end

    # Clearsigns an element
    #
    #   GPGME.clearsign text, options
    #
    # Same functionality of {GPGME.sign} only doing clearsigns by default.
    #
    def clearsign(text, options = {})
      GPGME.sign text, options.merge(:mode => GPGME::SIG_MODE_CLEAR)
    end

    # Creates a detached signature of an element
    #
    #   GPGME.detach_sign text, options
    #
    # Same functionality of {GPGME.sign} only doing detached signs by default.
    #
    def detach_sign(text, options = {})
      GPGME.sign text, options.merge(:mode => GPGME::SIG_MODE_DETACH)
    end

    # Lists all the keys available
    #
    #   GPGME.list_keys(pattern=nil, secret_only=false, options=Hash.new){|key| ...}
    #
    # <code>GPGME.list_keys</code> iterates over the key ring.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.list_keys(<i>pattern</i>, <i>secret_only</i>, <i>options</i>)
    #
    # All arguments are optional.  If the last argument is a Hash, options
    # will be read from it.
    #
    # <i>pattern</i> is a string or <tt>nil</tt>.  If <i>pattern</i> is
    # <tt>nil</tt>, all available keys are returned.  If
    # <i>secret_only</i> is <tt>true</tt>, the only secret keys are
    # returned.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def list_keys(*args_options) # :yields: key
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
      args, options = split_args(args_options)
      pattern, secret_only = args
      check_version(options)
      GPGME::Ctx.new do |ctx|
        if block_given?
          ctx.each_key(pattern, secret_only || false) do |key|
            yield key
          end
        else
          ctx.keys(pattern, secret_only || false)
        end
      end
    end

    # Exports a key
    #
    #   GPGME.export(pattern)
    #
    # <code>GPGME.export</code> extracts public keys from the key ring.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.export(<i>pattern</i>, <i>options</i>) -> <i>keydata</i>
    # - GPGME.export(<i>pattern</i>, <i>keydata</i>, <i>options</i>)
    #
    # All arguments are optional.  If the last argument is a Hash, options
    # will be read from it.
    #
    # <i>pattern</i> is a string or <tt>nil</tt>.  If <i>pattern</i> is
    # <tt>nil</tt>, all available public keys are returned.
    # <i>keydata</i> is output.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def export(*args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      pattern, key = args[0]
      key_data = Data.new(key)
      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.export_keys(pattern, key_data)

        unless key
          key_data.seek(0, IO::SEEK_SET)
          key_data.read
        end
      end
    end

    # Imports a key
    #
    #   GPGME.import(keydata)
    #
    # <code>GPGME.import</code> adds the keys to the key ring.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.import(<i>keydata</i>, <i>options</i>)
    #
    # All arguments are optional.  If the last argument is a Hash, options
    # will be read from it.
    #
    # <i>keydata</i> is input.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def import(*args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      key = args[0]
      key_data = Data.new(key)
      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.import_keys(key_data)
        ctx.import_result
      end
    end
  end
end
