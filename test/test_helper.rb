# -*- encoding: utf-8 -*-

# include compiled gpgme_n.bundle
tmp_dir = File.join(File.dirname(__FILE__), '..', 'tmp')
$:.unshift(tmp_dir) if File.directory?(tmp_dir)

require 'rubygems'
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

def import_key(key, only = :all)
  GPGME::Key.import(key[:public]) unless only == :secret
  GPGME::Key.import(key[:secret]) unless only == :public
end

def remove_keys
  KEYS.each do |key|
    remove_key(key)
  end
end

def remove_all_keys
  GPGME::Key.find(:public).each do |k|
    k.delete!(true)
  end
  GPGME::Key.find(:secret).each do |k|
    k.delete!(true)
  end
end

def remove_key(key)
  GPGME::Key.find(:public, key[:sha]).each do |k|
    k.delete!(true)
  end
  GPGME::Key.find(:secret, key[:sha]).each do |k|
    k.delete!(true)
  end
end

def with_key(key, only = :all, &block)
  import_key key, only

  begin
    yield
  ensure
    remove_key key
  end
end

def without_key(key, &block)
  remove_key key

  begin
    yield
  ensure
    import_key key
  end
end

# We use a different home directory for the keys to not disturb current
# installation

require 'tmpdir'
GPGME::Engine.home_dir = Dir.tmpdir
remove_all_keys
import_keys
