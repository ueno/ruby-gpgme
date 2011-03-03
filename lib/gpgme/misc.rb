module GPGME
  class EngineInfo
    private_class_method :new

    attr_reader :protocol, :file_name, :version, :req_version, :home_dir
    alias required_version req_version
  end

  class VerifyResult
    private_class_method :new

    attr_reader :signatures
  end

  class DecryptResult
    private_class_method :new

    attr_reader :unsupported_algorithm, :wrong_key_usage
  end

  class SignResult
    private_class_method :new

    attr_reader :invalid_signers, :signatures
  end

  class EncryptResult
    private_class_method :new

    attr_reader :invalid_recipients
  end

  class InvalidKey
    private_class_method :new

    attr_reader :fpr, :reason
    alias fingerprint fpr
  end

  class NewSignature
    private_class_method :new

    attr_reader :type, :pubkey_algo, :hash_algo, :sig_class, :fpr
    alias fingerprint fpr

    def timestamp
      Time.at(@timestamp)
    end
  end

  class ImportStatus
    private_class_method :new

    attr_reader :fpr, :result, :status
    alias fingerprint fpr
  end

  class ImportResult
    private_class_method :new

    attr_reader :considered, :no_user_id, :imported, :imported_rsa, :unchanged
    attr_reader :new_user_ids, :new_sub_keys, :new_signatures, :new_revocations
    attr_reader :secret_read, :secret_imported, :secret_unchanged
    attr_reader :not_imported, :imports
  end
end
