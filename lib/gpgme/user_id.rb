module GPGME
  class UserID
    private_class_method :new

    attr_reader :validity, :uid, :name, :comment, :email, :signatures

    def revoked?
      @revoked == 1
    end

    def invalid?
      @invalid == 1
    end

    def inspect
      "#<#{self.class} #{name} <#{email}> \
validity=#{VALIDITY_NAMES[validity]}, signatures=#{signatures.inspect}>"
    end
  end
end
