module GPGME
  class Data

    BLOCK_SIZE = 4096

    # Create a new instance.
    #
    # The created data types depend on <i>arg</i>.  If <i>arg</i> is
    # <tt>nil</tt>, it creates an instance with an empty buffer.
    # Otherwise, <i>arg</i> is either a string, an IO, or a Pathname.
    def self.new(arg = nil, copy = false)
      if arg.nil?
        return empty
      elsif arg.respond_to? :to_str
        return from_str(arg.to_str, copy)
      elsif arg.respond_to? :to_io
        return from_io(arg.to_io)
      elsif arg.respond_to? :open
        return from_io(arg.open)
      end
    end

    # Create a new instance with an empty buffer.
    def self.empty
      rdh = Array.new
      err = GPGME::gpgme_data_new(rdh)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance with internal buffer.
    def self.from_str(buf, copy = true)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_mem(rdh, buf, buf.length)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance associated with a given IO.
    def self.from_io(io)
      from_callbacks(IOCallbacks.new(io))
    end

    # Create a new instance from the specified file descriptor.
    def self.from_fd(fd)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_fd(rdh, fd)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Create a new instance from the specified callbacks.
    def self.from_callbacks(callbacks, hook_value = nil)
      rdh = Array.new
      err = GPGME::gpgme_data_new_from_cbs(rdh, callbacks, hook_value)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      rdh[0]
    end

    # Read at most <i>length</i> bytes from the data object, or to the end
    # of file if <i>length</i> is omitted or is <tt>nil</tt>.
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

    # Seek to a given <i>offset</i> in the data object according to the
    # value of <i>whence</i>.
    def seek(offset, whence = IO::SEEK_SET)
      GPGME::gpgme_data_seek(self, offset, IO::SEEK_SET)
    end

    # Write <i>length</i> bytes from <i>buffer</i> into the data object.
    def write(buffer, length = buffer.length)
      GPGME::gpgme_data_write(self, buffer, length)
    end

    # Return the encoding of the underlying data.
    def encoding
      GPGME::gpgme_data_get_encoding(self)
    end

    # Set the encoding to a given <i>encoding</i> of the underlying
    # data object.
    def encoding=(encoding)
      err = GPGME::gpgme_data_set_encoding(self, encoding)
      exc = GPGME::error_to_exception(err)
      raise exc if exc
      encoding
    end
  end
end
