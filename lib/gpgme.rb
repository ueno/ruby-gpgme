# gpgme.rb -- OO interface to GPGME
# Copyright (C) 2003,2006 Daiki Ueno

# This file is a part of Ruby-GPGME.

# This program is free software; you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation; either version 2, or (at your option)  
# any later version.                                                   

# This program is distributed in the hope that it will be useful,      
# but WITHOUT ANY WARRANTY; without even the implied warranty of       
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the        
# GNU General Public License for more details.                         

# You should have received a copy of the GNU General Public License    
# along with GNU Emacs; see the file COPYING.  If not, write to the    
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.
 
require 'gpgme_n'

module GPGME
  class GpgmeError < StandardError
    def initialize(error)
      @error = error
    end
    attr_reader :error

    def code
      GPGME::gpgme_err_code(@error)
    end

    def source
      GPGME::gpgme_err_source(@error)
    end

    def message
      GPGME::gpgme_strerror(@error)
    end

    class General < self; end
    class InvalidValue < self; end
    class UnusablePublicKey < self; end
    class UnusableSecretKey < self; end
    class NoData < self; end
    class Conflict < self; end
    class NotImplemented < self; end
    class DecryptFailed < self; end
    class BadPassphrase < self; end
    class Canceled < self; end
    class InvalidEngine < self; end
    class AmbiguousName < self; end
    class WrongKeyUsage < self; end
    class CertificateRevoked < self; end
    class CertificateExpired < self; end
    class NoCRLKnown < self; end
    class NoPolicyMatch < self; end
    class NoSecretKey < self; end
    class MissingCertificate < self; end
    class BadCertificateChain < self; end
    class UnsupportedAlgorithm < self; end
    class BadSignature < self; end
    class NoPublicKey < self; end
  end
  Error = GpgmeError

  private
  def check_error(err)
    case GPGME::gpgme_err_code(err)
    when GPG_ERR_EOF
      raise EOFError
    when GPG_ERR_NO_ERROR
    when GPG_ERR_GENERAL
      raise GpgmeError::General.new(err)
    when GPG_ERR_ENOMEM
      raise Errno::ENOMEM
    when GPG_ERR_INV_VALUE
      raise GpgmeError::InvalidValue.new(err)
    when GPG_ERR_UNUSABLE_PUBKEY
      raise GpgmeError::UnusablePublicKey.new(err)
    when GPG_ERR_UNUSABLE_SECKEY
      raise GpgmeError::UnusableSecretKey.new(err)
    when GPG_ERR_NO_DATA
      raise GpgmeError::NoData.new(err)
    when GPG_ERR_CONFLICT
      raise GpgmeError::Conflict.new(err)
    when GPG_ERR_NOT_IMPLEMENTED
      raise GpgmeError::NotImplemented.new(err)
    when GPG_ERR_DECRYPT_FAILED
      raise GpgmeError::DecryptFailed.new(err)
    when GPG_ERR_BAD_PASSPHRASE
      raise GpgmeError::BadPassphrase.new(err)
    when GPG_ERR_CANCELED
      raise GpgmeError::Canceled.new(err)
    when GPG_ERR_INV_ENGINE
      raise GpgmeError::InvalidEngine.new(err)
    when GPG_ERR_AMBIGUOUS_NAME
      raise GpgmeError::AmbiguousName.new(err)
    when GPG_ERR_WRONG_KEY_USAGE
      raise GpgmeError::WrongKeyUsage.new(err)
    when GPG_ERR_CERT_REVOKED
      raise GpgmeError::CertificateRevoked.new(err)
    when GPG_ERR_CERT_EXPIRED
      raise GpgmeError::CertificateExpired.new(err)
    when GPG_ERR_NO_CRL_KNOWN
      raise GpgmeError::NoCRLKnown.new(err)
    when GPG_ERR_NO_POLICY_MATCH
      raise GpgmeError::NoPolicyMatch.new(err)
    when GPG_ERR_NO_SECKEY
      raise GpgmeError::NoSecretKey.new(err)
    when GPG_ERR_MISSING_CERT
      raise GpgmeError::MissingCertificate.new(err)
    when GPG_ERR_BAD_CERT_CHAIN
      raise GpgmeError::BadCertificateChain.new(err)
    when GPG_ERR_UNSUPPORTED_ALGORITHM
      raise GpgmeError::UnsupportedAlgorithm.new(err)
    when GPG_ERR_BAD_SIGNATURE
      raise GpgmeError::BadSignature.new(err)
    when GPG_ERR_NO_PUBKEY
      raise GpgmeError::NoPublicKey.new(err)
    else
      raise GpgmeError.new(err)
    end
  end
  module_function :check_error

  public
  def engine_info
    rinfo = Array.new
    GPGME::gpgme_get_engine_info(rinfo)
    rinfo
  end
  module_function :engine_info

  # A class for managing data buffers.
  class GpgmeData
    BLOCK_SIZE = 4096

    # Create a new GpgmeData instance.
    def self.new
      rdh = Array.new
      err = GPGME::gpgme_data_new(rdh)
      GPGME::check_error(err)
      rdh[0]
    end

    # Create a new GpgmeData instance with internal buffer.
    def self.new_from_mem(buf, copy = false)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_mem(rdh, buf, buf.length, copy ? 1 : 0)
      GPGME::check_error(err)
      rdh[0]
    end

    def self.new_from_file(filename, copy = false)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_file(rdh, filename, copy ? 1 : 0)
      GPGME::check_error(err)
      rdh[0]
    end

    def self.new_from_fd(fd)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_fd(rdh, fd)
      GPGME::check_error(err)
      rdh[0]
    end

    def self.new_from_cbs(cbs, hook_value = nil)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_cbs(rdh, cbs, hook_value)
      GPGME::check_error(err)
      rdh[0]
    end

    def _read(len)
      buf = "\x0" * len
      nread = GPGME::gpgme_data_read(self, buf, len)
      if nread > 0
        buf[0 .. nread - 1]
      elsif nread == 0
        raise EOFError
      else
        raise 'error reading data'
      end
    end
    private :_read

    # Read bytes from this object.  If len is supplied, it causes
    # this method to read up to the number of bytes.
    def read(len = nil)
      if len
	_read(len)
      else
	buf = ''
	begin
	  loop do
	    buf << _read(BLOCK_SIZE)
	  end
	rescue EOFError
	  buf
	end
      end
    end

    # Reset the data pointer.
    def rewind
      GPGME::gpgme_data_rewind(self)
    end

    # Seek the data pointer.
    def seek(offset, whence = IO::SEEK_SET)
      GPGME::gpgme_data_seek(self, offset, IO::SEEK_SET)
    end

    # Write bytes into this object.  If len is supplied, it causes
    # this method to write up to the number of bytes.
    def write(buf, len = buf.length)
      GPGME::gpgme_data_write(self, buf, len)
    end

    # Return the type of the underlying data.
    def data_type
      GPGME::gpgme_data_type(self)
    end

    # Return the encoding of the underlying data.
    def encoding
      GPGME::gpgme_data_get_encoding(self)
    end

    # Set the encoding of the underlying data.
    def encoding=(enc)
      err = gpgme_data_set_encoding(self, enc)
      GPGME::check_error(err)
      enc
    end
  end
  Data = GpgmeData

  class GpgmeEngineInfo
    private_class_method :new
    
    attr_reader :protocol, :file_name, :version, :req_version
  end
  EngineInfo = GpgmeEngineInfo

  # A context within which all cryptographic operations are performed.
  class GpgmeCtx
    # Create a new GpgmeCtx object.
    def self.new(attrs = Hash.new)
      rctx = Array.new
      err = GPGME::gpgme_new(rctx)
      GPGME::check_error(err)
      ctx = rctx[0]
      attrs.each_pair do |key, value|
        case key
        when :protocol
          ctx.protocol = value
        when :armor
          ctx.armor = value
        when :textmode
          ctx.textmode = value
        when :keylist_mode
          ctx.keylist_mode = value
        end
      end
      ctx
    end

    # Set the protocol used within this context.
    def protocol=(proto)
      err = GPGME::gpgme_set_protocol(self, proto)
      GPGME::check_error(err)
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
      GPGME::gpgme_get_armor(self)
    end

    # Tell whether canonical text mode should be used.
    def textmode=(yes)
      GPGME::gpgme_set_textmode(self, yes ? 1 : 0)
      yes
    end

    # Return true if canonical text mode is enabled.
    def textmode
      GPGME::gpgme_get_textmode(self)
    end

    # Change the default behaviour of the key listing functions.
    def keylist_mode=(mode)
      GPGME::gpgme_set_keylist_mode(self, mode)
      mode
    end

    # Returns the current key listing mode.
    def keylist_mode
      GPGME::gpgme_get_keylist_mode(self)
    end

    # Set the passphrase callback with given hook value.
    def set_passphrase_cb(passfunc, hook_value = nil)
      GPGME::gpgme_set_passphrase_cb(self, passfunc, hook_value)
    end
    # An array which contains a Proc and an Object.
    # The former is the passphrase callback and the latter is hook value
    # passed to it.
    attr_reader :passphrase_cb

    # Set the progress callback with given hook value.
    def set_progress_cb(progfunc, hook_value = nil)
      GPGME::gpgme_set_progress_cb(self, progfunc, hook_value)
    end
    # An array which contains a Proc and an Object.
    # The former is the progress callback used when progress
    # information is available and the latter is hook value
    # passed to it.
    attr_reader :progress_cb

    # Initiates a key listing operation for given pattern.
    # If pattern is nil, all available keys are returned.
    # If secret_only is true, the list is restricted to secret keys only.
    def keylist_start(pattern = nil, secret_only = false)
      err = GPGME::gpgme_op_keylist_start(self, pattern, secret_only ? 1 : 0)
      GPGME::check_error(err)
    end

    # Returns the next key in the list created by a previous
    # keylist_start operation.
    def keylist_next
      rkey = Array.new
      err = GPGME::gpgme_op_keylist_next(self, rkey)
      GPGME::check_error(err)
      rkey[0]
    end

    # End a pending key list operation.
    def keylist_end
      err = GPGME::gpgme_op_keylist_end(self)
      GPGME::check_error(err)
    end

    # Convenient method to iterate over keylist.
    def each_keys(pattern = nil, secret_only = false, &block)
      keylist_start(pattern, secret_only)
      begin
	loop do
	  yield keylist_next
	end
      rescue EOFError
	# The last key in the list has already been returned.
      rescue
	keylist_end
      end
    end

    # Get the key with the fingerprint.
    def get_key(fpr, secret = false)
      rkey = Array.new
      err = GPGME::gpgme_get_key(self, fpr, rkey, secret ? 1 : 0)
      GPGME::check_error(err)
      rkey[0]
    end

    # Generates a new key pair.
    # If store is true, this method puts the key pair into the
    # standard key ring.
    def genkey(parms, store = false)
      if store
	pubkey, seckey = nil, nil
      else
	pubkey, seckey = GpgmeData.new, GpgmeData.new
      end
      err = GPGME::gpgme_op_genkey(self, parms, pubkey, seckey)
      GPGME::check_error(err)
      [pubkey, seckey]
    end

    # Extracts the public keys of the recipients.
    def export(recipients)
      keydata = GpgmeData.new
      err = GPGME::gpgme_op_export(self, recipients, keydata)
      GPGME::check_error(err)
      keydata
    end

    # Add the keys in the data buffer to the key ring.
    def import(keydata)
      err = GPGME::gpgme_op_import(self, keydata)
      GPGME::check_error(err)
    end

    # Delete the key from the key ring.
    # If allow_secret is false, only public keys are deleted,
    # otherwise secret keys are deleted as well.
    def delete(key, allow_secret = false)
      err = GPGME::gpgme_op_delete(self, key, allow_secret ? 1 : 0)
      GPGME::check_error(err)
    end

    # Decrypt the ciphertext and return the plaintext.
    def decrypt(cipher)
      plain = GpgmeData.new
      err = GPGME::gpgme_op_decrypt(self, cipher, plain)
      GPGME::check_error(err)
      plain
    end

    # Verify that the signature in the data object is a valid signature.
    def verify(sig, signed_text = nil, plain = nil)
      plain = GpgmeData.new
      err = GPGME::gpgme_op_verify(self, sig, signed_text, plain)
      GPGME::check_error(err)
      plain
    end

    def verify_result
      GPGME::gpgme_op_verify_result(self)
    end

    # Removes the list of signers from this object.
    def clear_signers
      GPGME::gpgme_signers_clear(self)
    end

    # Add the key to the list of signers.
    def add_signer(key)
      err = GPGME::gpgme_signers_add(self, key)
      GPGME::check_error(err)
    end

    # Create a signature for the text in the data object.
    def sign(plain, mode = GPGME::GPGME_SIG_MODE_NORMAL)
      sig = GpgmeData.new
      err = GPGME::gpgme_op_sign(self, plain, sig, mode)
      GPGME::check_error(err)
      sig
    end

    # Encrypt the plaintext in the data object for the recipients and
    # return the ciphertext.
    def encrypt(recp, plain, flags = 0)
      cipher = GpgmeData.new
      err = GPGME::gpgme_op_encrypt(self, recp, flags, plain, cipher)
      GPGME::check_error(err)
      cipher
    end
  end
  Ctx = GpgmeCtx

  # A public or secret key.
  class GpgmeKey
    private_class_method :new

    attr_reader :keylist_mode, :protocol, :owner_trust
    attr_reader :issuer_serial, :issuer_name, :chain_id
    attr_reader :subkeys, :uids

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def disabled?
      @disabled == 1
    end

    def invalid?
      @invalid == 1
    end

    def can_encrypt?
      @can_encrypt == 1
    end

    def can_sign?
      @can_sign == 1
    end

    def can_certify?
      @can_certify == 1
    end

    def can_authenticate?
      @can_authenticate == 1
    end

    def secret?
      @secret == 1
    end

    # Return the value of the attribute of the key.
    def [](what, idx = 0)
      GPGME::gpgme_key_get_string_attr(self, what, idx)
    end
  end
  Key = GpgmeKey

  class GpgmeSubKey
    private_class_method :new

    attr_reader :pubkey_algo, :length, :keyid, :fpr

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def disabled?
      @disabled == 1
    end

    def invalid?
      @invalid == 1
    end

    def can_encrypt?
      @can_encrypt == 1
    end

    def can_sign?
      @can_sign == 1
    end

    def can_certify?
      @can_certify == 1
    end

    def can_authenticate?
      @can_authenticate == 1
    end

    def secret?
      @secret == 1
    end

    def timestamp
      Time.new(@timestamp)
    end

    def expires
      Time.new(@expires)
    end
  end
  SubKey = GpgmeSubKey

  class GpgmeUserId
    private_class_method :new

    attr_reader :validity, :uid, :name, :comment, :email, :signatures

    def revoked?
      @revoked == 1
    end

    def invalid?
      @invalid == 1
    end
  end
  UserId = GpgmeUserId

  class GpgmeKeySig
    private_class_method :new

    attr_reader :pubkey_algo, :keyid

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def invalid?
      @invalid == 1
    end

    def exportable?
      @exportable == 1
    end

    def timestamp
      Time.at(@timestamp)
    end

    def expires
      Time.at(@expires)
    end
  end
  KeySig = GpgmeKeySig

  class GpgmeVerifyResult
    private_class_method :new

    attr_reader :signatures
  end
  VerifyResult = GpgmeVerifyResult

  class GpgmeSignature
    private_class_method :new

    attr_reader :summary, :fpr, :status, :notations

    def timestamp
      Time.at(@timestamp)
    end

    def exp_timestamp
      Time.at(@exp_timestamp)
    end
  end
  Signature = GpgmeSignature

  class GpgmeImportStatus
    private_class_method :new

    attr_reader :fpr, :result, :status
  end
  ImportStatus = GpgmeImportStatus

  class GpgmeImportResult
    private_class_method :new

    attr_reader :considered, :no_user_id, :imported, :imported_rsa, :unchanged
    attr_reader :new_user_ids, :new_sub_keys, :new_signatures, :new_revocations
    attr_reader :secret_read, :secret_imported, :secret_unchanged
    attr_reader :not_imported, :imports
  end
  ImportResult = ImportStatus

  # Deprecated functions.
  alias gpgme_trust_item_release gpgme_trust_item_unref

  def gpgme_data_rewind(dh)
    begin
      GPGME::gpgme_data_seek(dh, 0, IO::SEEK_SET)
    rescue SystemCallError => e
      return e.errno
    end
  end
  module_function :gpgme_data_rewind

  def gpgme_op_import_ext(ctx, keydata, nr)
    err = GPGME::gpgme_op_import(ctx, keydata)
    if GPGME::gpgme_err_code(err) == GPGME::GPG_ERR_NO_ERROR
      result = GPGME::gpgme_op_import_result(ctx)
      nr.push(result.considered)
    end
  end
  module_function :gpgme_op_import_ext
end
