# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Data do
  describe :new do
    it "smartly creates an empty buffer if nothing passed" do
      data = GPGME::Data.new
      assert_instance_of GPGME::Data, data
      assert_respond_to data, :read
      assert_respond_to data, :write
    end

    it "doesn't create a new object if the object passed is a Data already" do
      data = GPGME::Data.new
      new_data = GPGME::Data.new(data)

      assert_equal data, new_data
    end

    it "creates a data from strings" do
      data = GPGME::Data.new("wadus")
      assert_equal "wadus", data.read
    end

    it "creates a data from a file" do
      # magic fromfile
      data = GPGME::Data.new(File.open(__FILE__))
      assert_match /magic fromfile/, data.read
    end

    it "creates a data from file descriptor" do
      # magic filedescriptor
      File.open(__FILE__) do |f|
        data = GPGME::Data.new(f.fileno)
        assert_match /magic filedescriptor/, data.read
      end
    end
  end

  describe :read do
    it "allows to read only a length of the object" do
      data = GPGME::Data.new("wadus")
      assert_equal "wad", data.read(3)
    end

    it "returns nil if reading 0 length" do
      data = GPGME::Data.new("wadus")
      assert_nil data.read(0)
    end

    it "returns the full thing if reading without parameter" do
      data = GPGME::Data.new("wadus")
      assert_equal "wadus", data.read
    end
  end

  ##
  # We consider seek tested by these ones, since we have to seek(0) before
  # reading.
  describe :write do
    it "writes data to it" do
      data = GPGME::Data.new
      data.write("wadus")
      data.seek(0)
      assert_equal "wadus", data.read
    end

    it "writes data to it, specifying the length of the things to write" do
      data = GPGME::Data.new
      data.write("wadus", 5)
      data.seek(0)
      assert_equal "wadus", data.read
    end

    it "writes only a limited part if specified a small number" do
      data = GPGME::Data.new
      data.write("wadus", 3)
      data.seek(0)
      assert_equal "wad", data.read
    end

    # TODO: test doesn't pass, I believe there might be a security issue here,
    # random crap is written to the buffer if a longer size is passed.
    #
    # it "writes only the full data passed even if the length is bigger" do
    #   data = GPGME::Data.new
    #   data.write("wadus", 100)
    #   data.seek(0)
    #   assert_equal "wadus", data.read
    # end
  end

  describe :encoding do
    it "has encoding 0 by default (DATA_ENCODING_NONE)" do
      data = GPGME::Data.new("wadus")
      assert_equal GPGME::DATA_ENCODING_NONE, data.encoding
    end

    it "can set encodings" do
      data = GPGME::Data.new("wadus")
      [ GPGME::DATA_ENCODING_ARMOR, GPGME::DATA_ENCODING_BASE64,
        GPGME::DATA_ENCODING_BINARY,GPGME::DATA_ENCODING_NONE ].each do |encoding|
        data.encoding = encoding
        assert_equal encoding, data.encoding
      end
    end

    it "breaks if not set a proper encoding value" do
      data = GPGME::Data.new("wadus")
      assert_raises GPGME::Error::InvalidValue do
        data.encoding = 64
      end
    end
  end
end

