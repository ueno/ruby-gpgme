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
    remove_key(key)
  end
end

def remove_key(key)
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
    remove_key key
  end

  begin
    yield
  ensure
    KEYS.last(KEYS.size - size).each do |key|
      import_key key
    end
  end
end

def with_password_key(&block)
  import_key PASSWORD_KEY

  begin
    yield
  ensure
    remove_key PASSWORD_KEY
  end
end

# We use a different home directory for the keys to not disturb current
# installation
require 'tmpdir'
GPGME::Engine.home_dir = Dir.tmpdir
import_keys
