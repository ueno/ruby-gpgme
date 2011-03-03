module GPGME
  class KeySig
    private_class_method :new

    attr_reader :pubkey_algo, :keyid

    def revoked?
      @revoked == 1
    end

    def expired?
      @expired == 1
    end

    def invalid?
      @invalid == 1
    end

    def exportable?
      @exportable == 1
    end

    def timestamp
      Time.at(@timestamp)
    end

    def expires
      Time.at(@expires)
    end

    def inspect
      "#<#{self.class} #{keyid} timestamp=#{timestamp}, expires=#{expires}>"
    end
  end
end
