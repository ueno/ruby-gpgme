module GPGME
  module KeyCommon

    ##
    # Returns nil if the trust is valid.
    # Returns one of +:revoked+, +:expired+, +:disabled+, +:invalid+
    def trust
      return :revoked if @revoked == 1
      return :expired if @expired == 1
      return :disabled if @disabled == 1
      return :invalid if @invalid == 1
    end

    ##
    # Array of capabilities for this key. It can contain any combination of
    # +:encrypt+, +:sign+, +:certify+ or +:authenticate+
    def capability
      caps = []
      caps << :encrypt if @can_encrypt
      caps << :sign if @can_sign
      caps << :certify if @can_certify
      caps << :authenticate if @can_authenticate
      caps
    end

    ##
    # Checks if the key is capable of all of these actions. If empty array
    # is passed then will return true.
    #
    # Returns false if the keys trust has been invalidated.
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
  end
end
