module GPGME
  class SubKey
    private_class_method :new

    attr_reader :pubkey_algo, :length, :keyid, :fpr
    alias fingerprint fpr

    def trust
      return :revoked if @revoked == 1
      return :expired if @expired == 1
      return :disabled if @disabled == 1
      return :invalid if @invalid == 1
    end

    def capability
      caps = Array.new
      caps << :encrypt if @can_encrypt
      caps << :sign if @can_sign
      caps << :certify if @can_certify
      caps << :authenticate if @can_authenticate
      caps
    end

    def usable_for?(purposes)
      unless purposes.kind_of? Array
        purposes = [purposes]
      end
      return false if [:revoked, :expired, :disabled, :invalid].include? trust
      return (purposes - capability).empty?
    end

    def secret?
      @secret == 1
    end

    def timestamp
      Time.at(@timestamp)
    end

    def expires
      Time.at(@expires)
    end

    PUBKEY_ALGO_LETTERS = {
      PK_RSA => ?R,
      PK_ELG_E => ?g,
      PK_ELG => ?G,
      PK_DSA => ?D
    }

    def pubkey_algo_letter
      PUBKEY_ALGO_LETTERS[@pubkey_algo] || ??
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
