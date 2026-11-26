# -*- encoding: utf-8 -*-
require 'test_helper'
require 'stringio'

# Regression tests for memory-safety bugs in ext/gpgme/gpgme_n.c.
describe "GPGME native extension" do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  describe "read callback" do
    it "fails instead of overflowing when the callback returns too much" do
      callbacks = Object.new
      def callbacks.read(hook, length)
        "x" * (length * 4)
      end

      data = GPGME::Data.from_callbacks(callbacks)
      assert_raises(Errno::EINVAL) { data.read(16) }
    end
  end
end
