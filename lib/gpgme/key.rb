module GPGME

  ##
  # A ruby representation of a public or a secret key.
  class Key
    private_class_method :new

    attr_reader :keylist_mode, :protocol, :owner_trust
    attr_reader :issuer_serial, :issuer_name, :chain_id
    attr_reader :subkeys, :uids

    include KeyCommon

    ##
    # Returns an array of {GPGME::Key} objects that match the parameters.
    # * +secret+ set to +:secret+ to get only secret keys, or to +:public+ to
    #   get only public keys.
    # * +keys_or_names+ an array or an item that can be either {GPGME::Key}
    #   elements, or string identifiers like the email or the sha. Leave
    #   blank to get all.
    # * +purposes+ get only keys that are usable for any of these purposes.
    #   See {GPGME::Key} for a list of possible key capabilities.
    #
    # @example
    #   GPGME::Key.find :secret # => first secret key found
    #
    # @example
    #   GPGME::Key.find(:public, "mrsimo@example.com")
    #   # => return only public keys that match mrsimo@example.com
    #
    # @example
    #   GPGME::Key.find(:public, "mrsimo@example.com", :sign)
    #   # => return the public keys that match mrsimo@exampl.com and are
    #   #    capable of signing
    def self.find(secret, keys_or_names = nil, purposes = [])
      secret = (secret == :secret)
      keys_or_names = [""] if keys_or_names.nil? || keys_or_names.empty?
      keys_or_names = [keys_or_names].flatten
      purposes      = [purposes].flatten.compact.uniq

      keys = []
      keys_or_names.each do |key_or_name|
        case key_or_name
        when Key then keys << key_or_name
        when String
          GPGME::Ctx.new do |ctx|
            keys += ctx.keys(key_or_name, secret).select do |k|
              k.usable_for?(purposes)
            end
          end
        end
      end
      keys
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
