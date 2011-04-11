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
      sprintf("#<#{self.class} %s %4d%c/%s %s trust=%s, capability=%s>",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fingerprint || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'),
              trust.inspect,
              capability.inspect)
    end

    def to_s
      sprintf("%s   %4d%c/%s %s\n",
              secret? ? 'ssc' : 'sub',
              length,
              pubkey_algo_letter,
              (@fingerprint || @keyid)[-8 .. -1],
              timestamp.strftime('%Y-%m-%d'))
    end
  end
end
