module GPGME
  class SubKey
    private_class_method :new

    attr_reader :pubkey_algo, :length, :keyid, :fpr
    alias fingerprint fpr

    include KeyCommon

    def timestamp
      Time.at(@timestamp)
    end

    def expires
      Time.at(@expires)
    end

    def expired
      return false if @expires == 0
      @expires < Time.now.to_i
    end

    def sha
      (@fingerprint || @keyid)[-8 .. -1]
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
              (@fingerprint || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'),
              trust.inspect,
              capability.inspect)
    end

    def to_s
      sprintf("%s   %4d%s/%s %s\n",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fingerprint || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'))
    end
  end
end
