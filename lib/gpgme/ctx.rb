module GPGME

  ##
  # A context within which all cryptographic operations are performed.
  #
  # More operations can be done which are not available in the higher level
  # API. Note how to create a new instance of this class in {GPGME::Ctx.new}.
  #
  class Ctx

    ##
    # Create a new instance from the given +options+. Must be released either
    # executing the operations inside a block, or executing {GPGME::Ctx#release}
    # afterwards.
    #
    # @param [Hash] options
    #  The optional parameters are as follows:
    #  * +:protocol+ Either +PROTOCOL_OpenPGP+ or +PROTOCOL_CMS+.
    #  * +:armor+ will return ASCII armored outputs if specified true.
    #  * +:textmode+ if +true+, inform the recipient that the input is text.
    #  * +:keylist_mode+ One of: +KEYLIST_MODE_LOCAL+, +KEYLIST_MODE_EXTERN+,
    #    +KEYLIST_MODE_SIGS+ or +KEYLIST_MODE_VALIDATE+.
    #  * +:pinentry_mode+ One of: +PINENTRY_MODE_DEFAULT+,
    #    +PINENTRY_MODE_ASK+, +PINENTRY_MODE_CANCEL+,
    #    +PINENTRY_MODE_ERROR+, or +PINENTRY_MODE_LOOPBACK+.
    #  * +:offline+ if set to true, dirmngr will not contact external services
    #  * +:password+ password of the passphrased password being used.
    #  * +:passphrase_callback+ A callback function. See {#set_passphrase_callback}.
    #  * +:passphrase_callback_value+ An object passed to passphrase_callback.
    #  * +:progress_callback+  A callback function. See {#set_progress_callback}.
    #  * +:progress_callback_value+ An object passed to progress_callback.
    #  * +:status_callback+ A callback function. See {#set_status_callback}.
    #  * +:status_callback_value+ An object passed to status_callback.
    #
    # @example
    #   ctx = GPGME::Ctx.new
    #   # operate on ctx
    #   ctx.release
    #
    # @example
    #   GPGME::Ctx.new do |ctx|
    #     # operate on ctx
    #   end
    #
    def self.new(options = {})
      rctx = []
      err = GPGME::gpgme_new(rctx)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      ctx = rctx[0]

      ctx.protocol      = options[:protocol]      if options[:protocol]
      ctx.armor         = options[:armor]         if options[:armor]
      ctx.textmode      = options[:textmode]      if options[:textmode]
      ctx.keylist_mode  = options[:keylist_mode]  if options[:keylist_mode]
      ctx.pinentry_mode = options[:pinentry_mode] if options[:pinentry_mode]
      ctx.offline       = options[:offline]       if options[:offline]

      if options[:password]
        ctx.set_passphrase_callback GPGME::Ctx.method(:pass_function),
          options[:password]
      else
        if options[:passphrase_callback]
          ctx.set_passphrase_callback options[:passphrase_callback],
            options[:passphrase_callback_value]
        end
      end
      if options[:progress_callback]
        ctx.set_progress_callback options[:progress_callback],
          options[:progress_callback_value]
      end
      if options[:status_callback]
        ctx.set_status_callback options[:status_callback],
          options[:status_callback_value]
      end

      if block_given?
        begin
          yield ctx
        ensure
          GPGME::gpgme_release(ctx)
        end
      else
        ctx
      end
    end


    ##
    # Releases the Ctx instance. Must be called if it was initialized without
    # a block.
    #
    # @example
    #   ctx = GPGME::Ctx.new
    #   # operate on ctx
    #   ctx.release
    #
    def release
      GPGME::gpgme_release(self)
    end

    ##
    # Getters and setters
    ##

    # Set the +protocol+ used within this context. See {GPGME::Ctx.new} for
    # possible values.
    def protocol=(proto)
      err = GPGME::gpgme_set_protocol(self, proto)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      proto
    end

    # Return the +protocol+ used within this context.
    def protocol
      GPGME::gpgme_get_protocol(self)
    end

    # Tell whether the output should be ASCII armored.
    def armor=(yes)
      GPGME::gpgme_set_armor(self, yes ? 1 : 0)
      yes
    end

    # Return true if the output is ASCII armored.
    def armor
      GPGME::gpgme_get_armor(self) == 1 ? true : false
    end

    # Tell whether canonical text mode should be used.
    def textmode=(yes)
      GPGME::gpgme_set_textmode(self, yes ? 1 : 0)
      yes
    end

    # Return true if canonical text mode is enabled.
    def textmode
      GPGME::gpgme_get_textmode(self) == 1 ? true : false
    end

    # Change the default behaviour of the key listing functions.
    def keylist_mode=(mode)
      GPGME::gpgme_set_keylist_mode(self, mode)
      mode
    end

    # Return the current key listing mode.
    def keylist_mode
      GPGME::gpgme_get_keylist_mode(self)
    end

    # Change the default behaviour of the pinentry invocation.
    def pinentry_mode=(mode)
      GPGME::gpgme_set_pinentry_mode(self, mode)
      mode
    end

    # Return the current pinentry mode.
    def pinentry_mode
      GPGME::gpgme_get_pinentry_mode(self)
    end

    # Change the default behaviour of the dirmngr that might require
    # connections to external services.
    def offline=(mode)
      GPGME::gpgme_set_offline(self, mode)
      mode
    end

    # Return the current offline mode.
    def offline
      GPGME::gpgme_get_offline(self)
    end

    ##
    # Passphrase and progress callbacks
    ##

    # Set the passphrase callback with given hook value.
    # +passfunc+ should respond to +call+ with 5 arguments.
    #
    # * +obj+ the parameter +:passphrase_callback_value+ passed when creating
    #   the {GPGME::Ctx} object.
    # * +uid_hint+ hint as to what key are we asking the password for. Ex:
    #
    #   +CFB3294A50C2CFD7 Albert Llop <mrsimo@example.com>+
    #
    # * +passphrase_info+
    # * +prev_was_bad+ 0 if it's the first time the password is being asked,
    #   1 otherwise.
    # * +fd+ file descriptor where the password must be written too.
    #
    # Expects a Method object which can be obtained by the +method+ method
    # (really..).
    #
    #  ctx.set_passphrase_callback(MyModule.method(:passfunc))
    #
    # @example this method will simply return +maria+ as password.
    #  def pass_function(obj, uid_hint, passphrase_info, prev_was_bad, fd)
    #    io = IO.for_fd(fd, 'w')
    #    io.puts "maria"
    #    io.flush
    #  end
    #
    # @example this will interactively ask for the password
    #  def passfunc(obj, uid_hint, passphrase_info, prev_was_bad, fd)
    #    $stderr.write("Passphrase for #{uid_hint}: ")
    #    $stderr.flush
    #    begin
    #      system('stty -echo')
    #      io = IO.for_fd(fd, 'w')
    #      io.puts(gets)
    #      io.flush
    #    ensure
    #      (0 ... $_.length).each do |i| $_[i] = ?0 end if $_
    #      system('stty echo')
    #    end
    #    $stderr.puts
    #  end
    #
    # Note that this function doesn't work with GnuPG 2.0.  You can
    # use either GnuPG 1.x, which can be installed in parallel with
    # GnuPG 2.0, or GnuPG 2.1, which has loopback pinentry feature (see
    # {#pinentry_mode}).
    def set_passphrase_callback(passfunc, hook_value = nil)
      GPGME::gpgme_set_passphrase_cb(self, passfunc, hook_value)
    end
    alias set_passphrase_cb set_passphrase_callback

    # Set the progress callback with given hook value.
    # <i>progfunc</i> should respond to <code>call</code> with 5 arguments.
    #
    #  def progfunc(hook, what, type, current, total)
    #    $stderr.write("#{what}: #{current}/#{total}\r")
    #    $stderr.flush
    #  end
    #
    #  ctx.set_progress_callback(method(:progfunc))
    #
    def set_progress_callback(progfunc, hook_value = nil)
      GPGME::gpgme_set_progress_cb(self, progfunc, hook_value)
    end
    alias set_progress_cb set_progress_callback

    # Set the status callback with given hook value.
    # +statusfunc+ should respond to +call+ with 3 arguments.
    #
    # * +obj+ the parameter +:status_callback_value+ passed when creating
    #   the {GPGME::Ctx} object.
    # * +keyword+ the name of the status message
    # * +args+ any arguments for the status message
    #
    #  def status_function(obj, keyword, args)
    #    $stderr.puts("#{keyword} #{args}")
    #    return 0
    #  end
    def set_status_callback(statusfunc, hook_value = nil)
      GPGME::gpgme_set_status_cb(self, statusfunc, hook_value)
    end
    alias set_status_cb set_status_callback

    ##
    # Searching and iterating through keys. Used by {GPGME::Key.find}
    ##

    # Initiate a key listing operation for given pattern. If +pattern+ is
    # +nil+, all available keys are returned. If +secret_only<+ is +true+,
    # only secret keys are returned.
    #
    # Used by {GPGME::Ctx#each_key}
    def keylist_start(pattern = nil, secret_only = false)
      err = GPGME::gpgme_op_keylist_start(self, pattern, secret_only ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Advance to the next key in the key listing operation.
    #
    # Used by {GPGME::Ctx#each_key}
    def keylist_next
      rkey = []
      err = GPGME::gpgme_op_keylist_next(self, rkey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    # End a pending key list operation.
    #
    # Used by {GPGME::Ctx#each_key}
    def keylist_end
      err = GPGME::gpgme_op_keylist_end(self)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Convenient method to iterate over keys.
    #
    # If +pattern+ is +nil+, all available keys are returned. If +secret_only+
    # is +true+, only secret keys are returned.
    #
    # See {GPGME::Key.find} for an example of how to use, or for an easier way
    # to use.
    def each_key(pattern = nil, secret_only = false, &block)
      keylist_start(pattern, secret_only)
      begin
        loop { yield keylist_next }
      rescue EOFError
        # The last key in the list has already been returned.
      ensure
        keylist_end
      end
    end
    alias each_keys each_key

    # Returns the keys that match the +pattern+, or all if +pattern+ is nil.
    # Returns only secret keys if +secret_only+ is true.
    def keys(pattern = nil, secret_only = nil)
      keys = []
      each_key(pattern, secret_only) do |key|
        keys << key
      end
      keys
    end

    # Get the key with the +fingerprint+.
    # If +secret+ is +true+, secret key is returned.
    def get_key(fingerprint, secret = false)
      rkey = []
      err = GPGME::gpgme_get_key(self, fingerprint, rkey, secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    ##
    # Import/export and generation/deletion of keys
    ##

    # Generate a new key pair.
    # +parms+ is a string which looks like
    #
    #  <GnupgKeyParms format="internal">
    #  Key-Type: DSA
    #  Key-Length: 1024
    #  Subkey-Type: ELG-E
    #  Subkey-Length: 1024
    #  Name-Real: Joe Tester
    #  Name-Comment: with stupid passphrase
    #  Name-Email: joe@foo.bar
    #  Expire-Date: 0
    #  Passphrase: abc
    #  </GnupgKeyParms>
    #
    # If +pubkey+ and +seckey+ are both set to +nil+, it stores the generated
    # key pair into your key ring.
    def generate_key(parms, pubkey = nil, seckey = nil)
      err = GPGME::gpgme_op_genkey(self, parms, pubkey, seckey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias genkey generate_key

    # Extract the public keys that match the +recipients+. Returns a
    # {GPGME::Data} object which is not rewinded (should do +seek(0)+
    # before reading).
    #
    # Private keys cannot be exported due to GPGME restrictions.
    #
    # If passed, the key will be exported to +keydata+, which must be
    # a {GPGME::Data} object.
    def export_keys(recipients, keydata = Data.new, mode=0)
      err = GPGME::gpgme_op_export(self, recipients, mode, keydata)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      keydata
    end
    alias export export_keys

    # Add the keys in the data buffer to the key ring.
    def import_keys(keydata)
      err = GPGME::gpgme_op_import(self, keydata)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias import import_keys

    def import_result
      GPGME::gpgme_op_import_result(self)
    end

    # Delete the key from the key ring.
    # If allow_secret is false, only public keys are deleted,
    # otherwise secret keys are deleted as well.
    def delete_key(key, allow_secret = false)
      err = GPGME::gpgme_op_delete(self, key, allow_secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias delete delete_key

    # Edit attributes of the key in the local key ring.
    def edit_key(key, editfunc, hook_value = nil, out = Data.new)
      err = GPGME::gpgme_op_edit(self, key, editfunc, hook_value, out)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias edit edit_key

    # Edit attributes of the key on the card.
    def edit_card_key(key, editfunc, hook_value = nil, out = Data.new)
      err = GPGME::gpgme_op_card_edit(self, key, editfunc, hook_value, out)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias edit_card edit_card_key
    alias card_edit edit_card_key

    ##
    # Crypto operations
    ##

    # Decrypt the ciphertext and return the plaintext.
    def decrypt(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt(self, cipher, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    def decrypt_verify(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt_verify(self, cipher, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    def decrypt_result
      GPGME::gpgme_op_decrypt_result(self)
    end

    # Verify that the signature in the data object is a valid signature.
    def verify(sig, signed_text = nil, plain = Data.new)
      err = GPGME::gpgme_op_verify(self, sig, signed_text, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
    end

    def verify_result
      GPGME::gpgme_op_verify_result(self)
    end

    # Remove the list of signers from this object.
    def clear_signers
      GPGME::gpgme_signers_clear(self)
    end

    # Add _keys_ to the list of signers.
    def add_signer(*keys)
      keys.each do |key|
        err = GPGME::gpgme_signers_add(self, key)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
      end
    end

    # Create a signature for the text.
    # +plain+ is a data object which contains the text.
    # +sig+ is a data object where the generated signature is stored.
    def sign(plain, sig = Data.new, mode = GPGME::SIG_MODE_NORMAL)
      err = GPGME::gpgme_op_sign(self, plain, sig, mode)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      sig
    end

    def sign_result
      GPGME::gpgme_op_sign_result(self)
    end

    # Encrypt the plaintext in the data object for the recipients and
    # return the ciphertext.
    def encrypt(recp, plain, cipher = Data.new, flags = 0)
      err = GPGME::gpgme_op_encrypt(self, recp, flags, plain, cipher)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      cipher
    end

    def encrypt_result
      GPGME::gpgme_op_encrypt_result(self)
    end

    def encrypt_sign(recp, plain, cipher = Data.new, flags = 0)
      err = GPGME::gpgme_op_encrypt_sign(self, recp, flags, plain, cipher)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      cipher
    end

    def spawn(file, argv, datain, dataout, dataerr, flags = 0)
      err = GPGME::gpgme_op_spawn(self, file, argv, datain, dataout, dataerr,
                                  flags)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    def inspect
      "#<#{self.class} protocol=#{PROTOCOL_NAMES[protocol] || protocol}, \
armor=#{armor}, textmode=#{textmode}, \
keylist_mode=#{KEYLIST_MODE_NAMES[keylist_mode]}>"
    end

    private

    def self.pass_function(pass, uid_hint, passphrase_info, prev_was_bad, fd)
      io = IO.for_fd(fd, 'w')
      io.autoclose = false
      io.puts pass
      io.flush
    end

  end
end
