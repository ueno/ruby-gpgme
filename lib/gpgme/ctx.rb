module GPGME
  # A context within which all cryptographic operations are performed.
  class Ctx
    # Create a new instance from the given <i>options</i>.
    # <i>options</i> is a Hash whose keys are
    #
    # * <tt>:protocol</tt>  Either <tt>PROTOCOL_OpenPGP</tt> or
    #   <tt>PROTOCOL_CMS</tt>.
    #
    # * <tt>:armor</tt>  If <tt>true</tt>, the output should be ASCII armored.
    #
    # * <tt>:textmode</tt>  If <tt>true</tt>, inform the recipient that the
    #   input is text.
    #
    # * <tt>:keylist_mode</tt>  Either
    #   <tt>KEYLIST_MODE_LOCAL</tt>,
    #   <tt>KEYLIST_MODE_EXTERN</tt>,
    #   <tt>KEYLIST_MODE_SIGS</tt>, or
    #   <tt>KEYLIST_MODE_VALIDATE</tt>.
    # * <tt>:passphrase_callback</tt>  A callback function.
    # * <tt>:passphrase_callback_value</tt> An object passed to
    #   passphrase_callback.
    # * <tt>:progress_callback</tt>  A callback function.
    # * <tt>:progress_callback_value</tt> An object passed to
    #   progress_callback.
    #
    def self.new(options = Hash.new)
      rctx = Array.new
      err = GPGME::gpgme_new(rctx)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      ctx = rctx[0]
      options.each_pair do |key, value|
        case key
        when :protocol
          ctx.protocol = value
        when :armor
          ctx.armor = value
        when :textmode
          ctx.textmode = value
        when :keylist_mode
          ctx.keylist_mode = value
        when :passphrase_callback
          ctx.set_passphrase_callback(value,
                                      options[:passphrase_callback_value])
        when :progress_callback
          ctx.set_progress_callback(value,
                                      options[:progress_callback_value])
        end
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

    # Set the <i>protocol</i> used within this context.
    def protocol=(proto)
      err = GPGME::gpgme_set_protocol(self, proto)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      proto
    end

    # Return the protocol used within this context.
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

    def inspect
      "#<#{self.class} protocol=#{PROTOCOL_NAMES[protocol] || protocol}, \
armor=#{armor}, textmode=#{textmode}, \
keylist_mode=#{KEYLIST_MODE_NAMES[keylist_mode]}>"
    end

    # Set the passphrase callback with given hook value.
    # <i>passfunc</i> should respond to <code>call</code> with 5 arguments.
    #
    #  def passfunc(hook, uid_hint, passphrase_info, prev_was_bad, fd)
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
    #  ctx.set_passphrase_callback(method(:passfunc))
    #
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

    # Initiate a key listing operation for given pattern.
    # If <i>pattern</i> is <tt>nil</tt>, all available keys are
    # returned.  If <i>secret_only</i> is <tt>true</tt>, the only
    # secret keys are returned.
    def keylist_start(pattern = nil, secret_only = false)
      err = GPGME::gpgme_op_keylist_start(self, pattern, secret_only ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Advance to the next key in the key listing operation.
    def keylist_next
      rkey = Array.new
      err = GPGME::gpgme_op_keylist_next(self, rkey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    # End a pending key list operation.
    def keylist_end
      err = GPGME::gpgme_op_keylist_end(self)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end

    # Convenient method to iterate over keys.
    # If <i>pattern</i> is <tt>nil</tt>, all available keys are
    # returned.  If <i>secret_only</i> is <tt>true</tt>, the only
    # secret keys are returned.
    def each_key(pattern = nil, secret_only = false, &block) # :yields: key
      keylist_start(pattern, secret_only)
      begin
	loop do
	  yield keylist_next
	end
        keys
      rescue EOFError
	# The last key in the list has already been returned.
      ensure
	keylist_end
      end
    end
    alias each_keys each_key

    def keys(pattern = nil, secret_only = nil)
      keys = Array.new
      each_key(pattern, secret_only) do |key|
        keys << key
      end
      keys
    end

    # Get the key with the <i>fingerprint</i>.
    # If <i>secret</i> is <tt>true</tt>, secret key is returned.
    def get_key(fingerprint, secret = false)
      rkey = Array.new
      err = GPGME::gpgme_get_key(self, fingerprint, rkey, secret ? 1 : 0)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rkey[0]
    end

    # Generate a new key pair.
    # <i>parms</i> is a string which looks like
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
    # If <i>pubkey</i> and <i>seckey</i> are both set to <tt>nil</tt>,
    # it stores the generated key pair into your key ring.
    def generate_key(parms, pubkey = Data.new, seckey = Data.new)
      err = GPGME::gpgme_op_genkey(self, parms, pubkey, seckey)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
    end
    alias genkey generate_key

    # Extract the public keys of the recipients.
    def export_keys(recipients, keydata = Data.new)
      err = GPGME::gpgme_op_export(self, recipients, 0, keydata)
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

    # Decrypt the ciphertext and return the plaintext.
    def decrypt_verify(cipher, plain = Data.new)
      err = GPGME::gpgme_op_decrypt_verify(self, cipher, plain)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      plain
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
    # <i>plain</i> is a data object which contains the text.
    # <i>sig</i> is a data object where the generated signature is stored.
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
  end
end
