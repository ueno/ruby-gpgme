module GPGME

  ##
  # Convenience methods to check different aspects of the gpg system
  # installation.
  module Engine
    class << self

      ##
      # Verify that the engine implementing the protocol +proto+ is installed in
      # the system. Can be one of +PROTOCOL_OpenPGP+ or +PROTOCOL_CMS+.
      #
      # @return [Boolean] true if the engine is installed.
      #
      # @example
      #   GPGME::Engine.check_version(GPGME::PROTOCOL_OpenPGP) # => true
      #
      def check_version(proto)
        err = GPGME::gpgme_engine_check_version(proto)
        exc = GPGME::error_to_exception(err)
        !exc
      end

      ##
      # Return an array of {GPGME::EngineInfo} structures of enabled engines.
      #
      # @example
      #   GPGME::Engine.info.first
      #   # => #<GPGME::EngineInfo:0x00000100d4fbd8
      #          @file_name="/usr/local/bin/gpg",
      #          @protocol=0,
      #          @req_version="1.3.0",
      #          @version="1.4.11">
      #
      def info
        rinfo = []
        GPGME::gpgme_get_engine_info(rinfo)
        rinfo
      end

      ##
      # Change the default configuration of the crypto engine implementing
      # protocol +proto+.
      #
      # @param proto
      #   Can be one of +PROTOCOL_OpenPGP+ or +PROTOCOL_CMS+.
      #
      # @param file_name
      #   The file name of the executable program implementing the protocol.
      #
      # @param home_dir
      #   The directory name of the configuration directory.
      #
      # @example
      #   GPGME::Engine.set_info(GPGME::PROTOCOL_OpenPGP, '/usr/local/bin/gpg', home_dir)
      #
      def set_info(proto, file_name, home_dir)
        err = GPGME::gpgme_set_engine_info(proto, file_name, home_dir)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
      end

      ##
      # Sets the home dir for the configuration options. This way one could,
      # for example, load the keys from a customized keychain.
      #
      # @example
      #   GPGME::Engine.home_dir = '/tmp'
      #
      def home_dir=(home_dir)
        current = info.first
        set_info current.protocol, current.file_name, home_dir
      end

      ##
      # Return the default configuration.
      #
      # @example
      #   GPGME::Engine.dirinfo('homedir')
      #   # => '/home/user/.gnupg"
      #
      def dirinfo(what)
        GPGME::gpgme_get_dirinfo(what)
      end
    end # class << self
  end # class Engine
end # module GPGME
