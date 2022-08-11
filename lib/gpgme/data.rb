module GPGME

  ##
  # A class whose purpose is to unify the way we work with the data (both input
  # and output). Most of the calls expect instances of this class, or will try
  # to create one from your parameters.
  #
  # Read the {#read}, {#write} and {#seek} methods for the most commonly used
  # methods.
  class Data

    BLOCK_SIZE = 4096

    class << self

      ##
      # We implement +self.new+ instead of initialize because objects are actually
      # instantiated through the C API with stuff like +gpgme_data_new+.
      #
      # We try to create a {GPGME::Data} smartly depending on the object passed, and if
      # another {GPGME::Data} object is passed, it just returns it, so when in
      # doubt, you can always pass a {GPGME::Data} object.
      #
      # @example empty
      #   data = GPGME::Data.new
      #   data.write("stuff")
      #
      # @example from a string
      #   data = GPGME::Data.new("From a string")
      #
      # @example from a file
      #   data = GPGME::Data.new(File.open("secure.pass"))
      #
      # @example from a file descriptor
      #   data = GPGME::Data.new(0) # Standard input
      #   data = GPGME::Data.new(1) # Standard output
      #
      #   file = File.open("secure.pass")
      #   data = GPGME::Data.new(file.fileno) # file descriptor
      #
      def new(object = nil)
        if object.nil?
          empty!
        elsif object.is_a?(Data)
          object
        elsif object.is_a?(Integer)
          from_fd(object)
        elsif object.respond_to? :to_str
          from_str(object.to_str)
        elsif object.respond_to? :to_io
          from_io(object.to_io)
        elsif object.respond_to? :open
          from_io(object.open)
        elsif defined?(StringIO) and object.is_a?(StringIO)
          from_io(object)
        end
      end

      # Create a new instance with an empty buffer.
      def empty!
        rdh = []
        err = GPGME::gpgme_data_new(rdh)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
        rdh.first
      end

      # Create a new instance with internal buffer.
      def from_str(string)
        rdh = []
        err = GPGME::gpgme_data_new_from_mem(rdh, string, string.bytesize)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
        rdh.first
      end

      # Create a new instance associated with a given IO.
      def from_io(io)
        from_callbacks(IOCallbacks.new(io))
      end

      # Create a new instance from the specified file descriptor.
      def from_fd(fd)
        rdh = []
        err = GPGME::gpgme_data_new_from_fd(rdh, fd)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
        rdh.first
      end

      # Create a new instance from the specified callbacks.
      def from_callbacks(callbacks, hook_value = nil)
        rdh = []
        err = GPGME::gpgme_data_new_from_cbs(rdh, callbacks, hook_value)
        exc = GPGME::error_to_exception(err)
        raise exc if exc
        rdh.first
      end
    end # class << self

    # Read at most +length+ bytes from the data object, or to the end
    # of file if +length+ is omitted or is +nil+.
    #
    # @example
    #   data = GPGME::Data.new("From a string")
    #   data.read # => "From a string"
    #
    # @example
    #   data = GPGME::Data.new("From a string")
    #   data.read(4) # => "From"
    #
    def read(length = nil)
      if length
        GPGME::gpgme_data_read(self, length)
      else
        buf = String.new
        loop do
          s = GPGME::gpgme_data_read(self, BLOCK_SIZE)
          break unless s
          buf << s
        end
        buf
      end
    end

    ##
    # Seek to a given +offset+ in the data object according to the
    # value of +whence+.
    #
    # @example going to the beginning of the buffer after writing something
    #  data = GPGME::Data.new("Some data")
    #  data.read # => "Some data"
    #  data.read # => ""
    #  data.seek 0
    #  data.read # => "Some data"
    #
    def seek(offset, whence = IO::SEEK_SET)
      GPGME::gpgme_data_seek(self, offset, IO::SEEK_SET)
    end

    ##
    # Writes +length+ bytes from +buffer+ into the data object.
    # Writes the full buffer if no length passed.
    #
    # @example
    #   data = GPGME::Data.new
    #   data.write "hola"
    #   data.seek 0
    #   data.read # => "hola"
    #
    # @example
    #   data = GPGME::Data.new
    #   data.write "hola", 2
    #   data.seek 0
    #   data.read # => "ho"
    #
    def write(buffer, length = buffer.length)
      GPGME::gpgme_data_write(self, buffer, length)
    end

    ##
    # Return the encoding of the underlying data.
    def encoding
      GPGME::gpgme_data_get_encoding(self)
    end

    ##
    # Sets the encoding for this buffer. Accepts only integer values 0 to 7:
    #
    # 0 = GPGME_DATA_ENCODING_NONE   (Not specified)
    # 1 = GPGME_DATA_ENCODING_BINARY
    # 2 = GPGME_DATA_ENCODING_BASE64
    # 3 = GPGME_DATA_ENCODING_ARMOR  (Either PEM or OpenPGP Armor)
    # 4 = GPGME_DATA_ENCODING_URL    (LF delimited URL list)
    # 5 = GPGME_DATA_ENCODING_URLESC (Ditto, but percent escaped)
    # 6 = GPGME_DATA_ENCODING_URL0   (Nul delimited URL list)
    # 7 = GPGME_DATA_ENCODING_MIME   (Data is a MIME part)
    #
    # @raise [GPGME::Error::InvalidValue] if the value isn't accepted.
    def encoding=(encoding)
      err = GPGME::gpgme_data_set_encoding(self, encoding)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      encoding
    end

    ##
    # Return the file name of the underlying data.
    def file_name
      GPGME::gpgme_data_get_file_name(self)
    end

    ##
    # Sets the file name for this buffer.
    #
    # @raise [GPGME::Error::InvalidValue] if the value isn't accepted.
    def file_name=(file_name)
      err = GPGME::gpgme_data_set_file_name(self, file_name)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      file_name
    end

    ##
    # Return the entire content of the data object as string.
    def to_s
      pos = seek(0, IO::SEEK_CUR)
      begin
        seek(0)
        read
      ensure
        seek(pos)
      end
    end
  end
end
