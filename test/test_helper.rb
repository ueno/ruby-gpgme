# -*- encoding: utf-8 -*-
require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/pride'
require 'mocha'
require 'ruby-debug'
require 'gpgme'

require File.dirname(__FILE__) + "/support/resources"

def import_keys
  KEYS.each do |key|
    import_key(key)
  end
end

def import_key(key)
  GPGME::Key.import key[:public]
  GPGME::Key.import key[:private]
end

def remove_keys
  KEYS.each do |key|
    delete_key(key)
  end
end

def delete_key(key)
  GPGME::Key.find(:public, key[:sha]).each do |k|
    k.delete!(true)
  end
end

##
# Execute the code inside the block with only the +size+ first keys available.
#
# @example
#   test "something that requires no keys" do
#     with_keys 0 do
#       # none of the test keys are available
#     end
#   end
def with_keys(size, &block)
  KEYS.last(KEYS.size - size).each do |key|
    delete_key(key)
  end

  begin
    yield
  ensure
    KEYS.last(KEYS.size - size).each do |key|
      import_key(key)
    end
  end
end

import_keys

# Remove the tests key at the end of test execution
MiniTest::Unit.after_tests do
  remove_keys
end
