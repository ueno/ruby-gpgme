require 'gpgme'

# TODO: Find why is this needed. I guess the name compat means it's just
# backwards compatibility. Consider removing?

module GPGME
  GpgmeError = Error
  GpgmeData = Data
  GpgmeEngineInfo = EngineInfo
  GpgmeCtx = Ctx
  GpgmeKey = Key
  GpgmeSubKey = SubKey
  GpgmeUserID = UserID
  GpgmeKeySig = KeySig
  GpgmeVerifyResult = VerifyResult
  GpgmeSignature = Signature
  GpgmeDecryptResult = DecryptResult
  GpgmeSignResult = SignResult
  GpgmeEncryptResult = EncryptResult
  GpgmeInvalidKey = InvalidKey
  GpgmeNewSignature = NewSignature
  GpgmeImportStatus = ImportStatus
  GpgmeImportResult = ImportResult

  class Ctx
    # Set the data pointer to the beginning.
    def rewind
      seek(0)
    end
  end

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
