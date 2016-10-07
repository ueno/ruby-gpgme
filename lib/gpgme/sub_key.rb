module GPGME
  class SubKey
    private_class_method :new

    attr_reader :pubkey_algo, :length, :keyid, :fpr
    alias fingerprint fpr

    include KeyCommon

    def timestamp
      case @timestamp
      when -1, 0
        # FIXME: add a special value for invalid timestamp, or throw an error
        return nil
      else
        return Time.at(@timestamp)
      end
    end

    def expires?
      @expires != 0
    end

    def expires
      expires? ? Time.at(@expires) : nil
    end

    def expired
      expires? && @expires < Time.now.to_i
    end

    def sha
      (@fpr || @keyid)[-8 .. -1]
    end

    PUBKEY_ALGO_LETTERS = {
      PK_RSA    => "R",
      PK_ELG_E  => "g",
      PK_ELG    => "G",
      PK_DSA    => "D"
    }

    def pubkey_algo_letter
      PUBKEY_ALGO_LETTERS[@pubkey_algo] || "?"
    end

    def inspect
      sprintf("#<#{self.class} %s %4d%s/%s %s trust=%s, capability=%s>",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fpr || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'),
              trust.inspect,
              capability.inspect)
    end

    def to_s
      sprintf("%s   %4d%s/%s %s\n",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fpr || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'))
    end
  end
end
