module GPGME
  # A public or secret key.
  class Key
    private_class_method :new

    attr_reader :keylist_mode, :protocol, :owner_trust
    attr_reader :issuer_serial, :issuer_name, :chain_id
    attr_reader :subkeys, :uids

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

    def inspect
      primary_subkey = subkeys[0]
      sprintf("#<#{self.class} %s %4d%c/%s %s trust=%s, owner_trust=%s, \
capability=%s, subkeys=%s, uids=%s>",
              primary_subkey.secret? ? 'sec' : 'pub',
              primary_subkey.length,
              primary_subkey.pubkey_algo_letter,
              primary_subkey.fingerprint[-8 .. -1],
              primary_subkey.timestamp.strftime('%Y-%m-%d'),
              trust.inspect,
              VALIDITY_NAMES[@owner_trust].inspect,
              capability.inspect,
              subkeys.inspect,
              uids.inspect)
    end

    def to_s
      primary_subkey = subkeys[0]
      s = sprintf("%s   %4d%c/%s %s\n",
                  primary_subkey.secret? ? 'sec' : 'pub',
                  primary_subkey.length,
                  primary_subkey.pubkey_algo_letter,
                  primary_subkey.fingerprint[-8 .. -1],
                  primary_subkey.timestamp.strftime('%Y-%m-%d'))
      uids.each do |user_id|
        s << "uid\t\t#{user_id.name} <#{user_id.email}>\n"
      end
      subkeys.each do |subkey|
        s << subkey.to_s
      end
      s
    end
  end
end
