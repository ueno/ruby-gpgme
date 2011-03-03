$:.push File.expand_path("../..", __FILE__) # C extension is in the root

require 'gpgme_n'
require 'gpgme/constants'
require 'gpgme/aux'
require 'gpgme/ctx'
require 'gpgme/data'
require 'gpgme/error'
require 'gpgme/io_callbacks'
require 'gpgme/key'
require 'gpgme/key_sig'
require 'gpgme/misc'
require 'gpgme/signature'
require 'gpgme/sub_key'
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
    # Decrypts a previously encrypted element
    #
    #   GPGME.decrypt(cipher, plain=nil, options=Hash.new){|signature| ...}
    #
    # <code>GPGME.decrypt</code> performs decryption.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.decrypt(<i>cipher</i>, <i>plain</i>, <i>options</i>)
    # - GPGME.decrypt(<i>cipher</i>, <i>options</i>) -> <i>plain</i>
    #
    # All arguments except <i>cipher</i> are optional.  <i>cipher</i> is
    # input, and <i>plain</i> is output.  If the last argument is a
    # Hash, options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def decrypt(cipher, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      plain = args[0]

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        cipher_data = input_data(cipher)
        plain_data = output_data(plain)
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

        unless plain
          plain_data.seek(0, IO::SEEK_SET)
          plain_data.read
        end
      end
    end

    # Verifies a previously signed element
    #
    #   GPGME.verify(sig, signed_text=nil, plain=nil, options=Hash.new){|signature| ...}
    #
    # <code>GPGME.verify</code> verifies a signature.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.verify(<i>sig</i>, <i>signed_text</i>, <i>plain</i>, <i>options</i>)
    # - GPGME.verify(<i>sig</i>, <i>signed_text</i>, <i>options</i>) -> <i>plain</i>
    #
    # All arguments except <i>sig</i> are optional.  <i>sig</i> and
    # <i>signed_text</i> are input.  <i>plain</i> is output.  If the last
    # argument is a Hash, options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # If <i>sig</i> is a detached signature, then the signed text should
    # be provided in <i>signed_text</i> and <i>plain</i> should be
    # <tt>nil</tt>.  Otherwise, if <i>sig</i> is a normal (or cleartext)
    # signature, <i>signed_text</i> should be <tt>nil</tt>.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def verify(sig, *args_options) # :yields: signature
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
      args, options = split_args(args_options)
      signed_text, plain = args

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        sig_data = input_data(sig)
        if signed_text
          signed_text_data = input_data(signed_text)
          plain_data = nil
        else
          signed_text_data = nil
          plain_data = output_data(plain)
        end
        ctx.verify(sig_data, signed_text_data, plain_data)
        ctx.verify_result.signatures.each do |signature|
          yield signature
        end
        if !signed_text && !plain
          plain_data.seek(0, IO::SEEK_SET)
          plain_data.read
        end
      end
    end

    # Signs an element
    #
    #   GPGME.sign(plain, sig=nil, options=Hash.new)
    #
    # <code>GPGME.sign</code> creates a signature of the plaintext.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.sign(<i>plain</i>, <i>sig</i>, <i>options</i>)
    # - GPGME.sign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
    #
    # All arguments except <i>plain</i> are optional.  <i>plain</i> is
    # input and <i>sig</i> is output.  If the last argument is a Hash,
    # options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    # - <tt>:mode</tt> Desired type of a signature.  Either
    #   <tt>GPGME::SIG_MODE_NORMAL</tt> for a normal signature,
    #   <tt>GPGME::SIG_MODE_DETACH</tt> for a detached signature, or
    #   <tt>GPGME::SIG_MODE_CLEAR</tt> for a cleartext signature.
    #
    def sign(plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      sig = args[0]

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.add_signer(*resolve_keys(options[:signers], true, [:sign])) if options[:signers]
        mode = options[:mode] || GPGME::SIG_MODE_NORMAL
        plain_data = input_data(plain)
        sig_data = output_data(sig)
        begin
          ctx.sign(plain_data, sig_data, mode)
        rescue GPGME::Error::UnusableSecretKey => exc
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end

        unless sig
          sig_data.seek(0, IO::SEEK_SET)
          sig_data.read
        end
      end
      keys
    end

    # Clearsigns an element
    #
    #   GPGME.clearsign(plain, sig=nil, options=Hash.new)
    #
    # <code>GPGME.clearsign</code> creates a cleartext signature of the plaintext.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.clearsign(<i>plain</i>, <i>sig</i>, <i>options</i>)
    # - GPGME.clearsign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
    #
    # All arguments except <i>plain</i> are optional.  <i>plain</i> is
    # input and <i>sig</i> is output.  If the last argument is a Hash,
    # options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    #
    def clearsign(plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      args.push(options.merge({:mode => GPGME::SIG_MODE_CLEAR}))
      GPGME.sign(plain, *args)
    end

    # Creates a detached signature of an element
    #
    #   GPGME.detach_sign(plain, sig=nil, options=Hash.new)
    #
    # <code>GPGME.detach_sign</code> creates a detached signature of the plaintext.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.detach_sign(<i>plain</i>, <i>sig</i>, <i>options</i>)
    # - GPGME.detach_sign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
    #
    # All arguments except <i>plain</i> are optional.  <i>plain</i> is
    # input and <i>sig</i> is output.  If the last argument is a Hash,
    # options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    #
    def detach_sign(plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      args.push(options.merge({:mode => GPGME::SIG_MODE_DETACH}))
      GPGME.sign(plain, *args)
    end

    ##
    # Encrypts an element
    #
    #  GPGME.encrypt something
    #
    # Will return a string with the encrypted result unless specified otherwise.
    #
    # Must have some key imported, look for {GPGME.import} to know how
    # to import one, or the gpg documentation to know how to create one
    #
    # @param plain
    #  Must be something that can be converted into a {GPGME::Data} object, or
    #  a GPGME::Data object itself.
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
    #    converted to a GPGME::Data object, so it could be a file for example.
    #
    # @example returns string that can be later encrypted
    #  GPGME.encrypt "Hello world!"
    #
    # @example string that can be encrypted by someone@example.com.
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
    #
    def encrypt(recipients, plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
      args, options = split_args(args_options)
      cipher = args[0]
      recipient_keys = recipients ? resolve_keys(recipients, false, [:encrypt]) : nil

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        plain_data = input_data(plain)
        cipher_data = output_data(cipher)
        begin
          flags = 0
          if options[:always_trust]
            flags |= GPGME::ENCRYPT_ALWAYS_TRUST
          end
          if options[:sign]
            if options[:signers]
              ctx.add_signer(*resolve_keys(options[:signers], true, [:sign]))
            end
            ctx.encrypt_sign(recipient_keys, plain_data, cipher_data, flags)
          else
            ctx.encrypt(recipient_keys, plain_data, cipher_data, flags)
          end
        rescue GPGME::Error::UnusablePublicKey => exc
          exc.keys = ctx.encrypt_result.invalid_recipients
          raise exc
        rescue GPGME::Error::UnusableSecretKey => exc
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end

        unless cipher
          cipher_data.seek(0, IO::SEEK_SET)
          cipher_data.read
        end
      end
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
      key_data = output_data(key)
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
      key_data = input_data(key)
      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.import_keys(key_data)
        ctx.import_result
      end
    end
  end
end
