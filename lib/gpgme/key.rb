module GPGME

  ##
  # A ruby representation of a public or a secret key.
  #
  # Every key has two instances of {GPGME::SubKey}, accessible through
  # {.subkeys}, and with a {.primary_subkey} where most attributes are
  # derived from, like the +fingerprint+.
  #
  # Also, every key has at least a {GPGME::UserID}, accessible through
  # {.uids}, with a {.primary_uid}, where other attributes are derived from,
  # like +email+ or +name+
  class Key
    private_class_method :new

    attr_reader :keylist_mode, :protocol, :owner_trust
    attr_reader :issuer_serial, :issuer_name, :chain_id
    attr_reader :subkeys, :uids

    include KeyCommon

    class << self

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
      #   # => return the public keys that match mrsimo@example.com and are
      #   #    capable of signing
      def find(secret, keys_or_names = nil, purposes = [])
        secret = (secret == :secret)
        keys_or_names = [""] if keys_or_names.nil? || (keys_or_names.is_a?(Array) && keys_or_names.empty?)
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

      def get(fingerprint)
        Ctx.new do |ctx|
          ctx.get_key(fingerprint)
        end
      end

      # Exports public keys
      #
      #   GPGME::Key.export pattern, options
      #
      # Private keys cannot be exported due to GPGME restrictions.
      #
      # @param pattern
      #   Identifier of the key to export.
      #
      # @param [Hash] options
      #   * +:output+ specify where to write the key to. It will be converted to
      #     a {GPGME::Data}, so it could be a file, for example.
      #   * +:minimal+ set to true to let the export mode be 'minimal'.
      #   * Any other option accepted by {GPGME::Ctx.new}
      #
      # @return [GPGME::Data] the exported key.
      #
      # @example
      #   key = GPGME::Key.export "mrsimo@example.com"
      #
      # @example writing to a file
      #   out = File.open("my.key", "w+")
      #   GPGME::Key.export "mrsimo@example.com", :output => out
      #
      def export(pattern, options = {})
        output = Data.new(options[:output])
        if options.delete(:minimal) == true
          export_mode = 4
        else
          export_mode = 0
        end

        GPGME::Ctx.new(options) do |ctx|
          ctx.export_keys(pattern, output, export_mode)
        end

        output.seek(0)
        output
      end

      # Imports a key
      #
      #   GPGME::Key.import keydata, options
      #
      # @param keydata
      #   The key to import. It will be converted to a {GPGME::Data} object,
      #   so could be a file, for example.
      # @param options
      #   Any other option accepted by {GPGME::Ctx.new}
      #
      # @example
      #   GPGME::Key.import(File.open("my.key"))
      #
      def import(keydata, options = {})
        GPGME::Ctx.new(options) do |ctx|
          ctx.import_keys(Data.new(keydata))
          ctx.import_result
        end
      end

      # Checks if a key is valid
      def valid?(key)
        GPGME::Key.import(key).considered == 1
      end

    end

    ##
    # Exports this key. Accepts the same options as {GPGME::Ctx.new}, and
    # +options[:output]+, where you can specify something that can become a
    # {GPGME::Data}, where the output will go.
    #
    # @example
    #   key.export(:armor => true)
    #   # => GPGME::Data you can read with ASCII armored format
    #
    # @example
    #   file = File.open("key.asc", "w+")
    #   key.export(:output => file)
    #   # => the key will be written to the file.
    #
    def export(options = {})
      Key.export self.sha, options
    end

    ##
    # Delete this key. If it's public, and has a secret one it will fail unless
    # +allow_secret+ is specified as true.
    def delete!(allow_secret = false)
      GPGME::Ctx.new do |ctx|
        ctx.delete_key self, allow_secret
      end
    end

    ##
    # Returns true if the key has an expiry date else false
    def expires?
      primary_subkey.expires?
    end

    ##
    # Returns the expiry date for this key
    def expires
      primary_subkey.expires
    end

    ##
    # Returns true if the key is expired
    def expired
      subkeys.any?(&:expired)
    end

    def primary_subkey
      @primary_subkey ||= subkeys.first
    end

    ##
    # Short descriptive value. Can be used to identify the key.
    def sha
      primary_subkey.sha
    end

    ##
    # Longer descriptive value. Can be used to identify the key.
    def fingerprint
      primary_subkey.fingerprint
    end

    ##
    # Returns the main {GPGME::UserID} for this key.
    def primary_uid
      uids.first
    end

    ##
    # Returns the email for this key.
    def email
      primary_uid.email
    end

    ##
    # Returns the issuer name for this key.
    def name
      primary_uid.name
    end

    ##
    # Returns the issuer comment for this key.
    def comment
      primary_uid.comment
    end

    def ==(another_key)
      self.class === another_key and fingerprint == another_key.fingerprint
    end

    def inspect
      sprintf("#<#{self.class} %s %4d%s/%s %s trust=%s, owner_trust=%s, \
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
      s = sprintf("%s   %4d%s/%s %s\n",
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
