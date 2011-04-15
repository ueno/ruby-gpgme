module GPGME
  class Signature
    private_class_method :new

    attr_reader :summary, :fpr, :status, :notations, :wrong_key_usage
    attr_reader :validity, :validity_reason
    attr_reader :pka_trust, :pka_address
    alias fingerprint fpr

    ##
    # Returns true if the signature is correct
    def valid?
      status_code == GPGME::GPG_ERR_NO_ERROR
    end

    def status_code
      GPGME::gpgme_err_code(status)
    end

    def from
      @from ||= begin
        ctx = Ctx.new
        if from_key = ctx.get_key(fingerprint)
          "#{from_key.subkeys[0].keyid} #{from_key.uids[0].uid}"
        else
          fingerprint
        end
      end
    end

    def timestamp
      Time.at(@timestamp)
    end

    def exp_timestamp
      Time.at(@exp_timestamp)
    end

    def to_s
      case status_code
      when GPGME::GPG_ERR_NO_ERROR
        "Good signature from #{from}"
      when GPGME::GPG_ERR_SIG_EXPIRED
        "Expired signature from #{from}"
      when GPGME::GPG_ERR_KEY_EXPIRED
        "Signature made from expired key #{from}"
      when GPGME::GPG_ERR_CERT_REVOKED
        "Signature made from revoked key #{from}"
      when GPGME::GPG_ERR_BAD_SIGNATURE
        "Bad signature from #{from}"
      when GPGME::GPG_ERR_NO_ERROR
        "No public key for #{from}"
      end
    end
  end
end
