= GPGME

This README is better viewed through the YARD formatted documentation:
http://rdoc.info/github/ueno/ruby-gpgme/frames for latest github
version, or http://rdoc.info/gems/gpgme for latest gem release.

{<img src="https://github.com/ueno/ruby-gpgme/actions/workflows/test.yml/badge.svg" alt="Build Status" />}[https://github.com/ueno/ruby-gpgme/actions/workflows/test.yml]
{<img src="https://coveralls.io/repos/ueno/ruby-gpgme/badge.png" alt="Coverage Status" />}[https://coveralls.io/r/ueno/ruby-gpgme]

== Requirements

* Ruby 1.8 or later
* GPGME 1.1.2 or later
* gpg-agent (optional, but recommended)

== Installation

 $ gem install gpgme

== API

GPGME provides three levels of API. The highest level API is as simple as it
gets, the mid level API provides more functionality but might be less
user-friendly, and the lowest level API is close to the C interface of GPGME.

=== The highest level API

For example, to create a cleartext signature of the plaintext from
stdin and write the result to stdout can be written as follows.

 crypto = GPGME::Crypto.new
 crypto.clearsign $stdin, :output => $stdout

=== The mid level API

The same example can be rewritten in the mid level API as follows.

 plain = GPGME::Data.new($stdin)
 sig   = GPGME::Data.new($stdout)
 GPGME::Ctx.new do |ctx|
   ctx.sign(plain, sig, GPGME::SIG_MODE_CLEAR)
 end

=== The lowest level API

The same example can be rewritten in the lowest level API as follows.

 ret = []
 GPGME::gpgme_new(ret)
 ctx = ret.shift
 GPGME::gpgme_data_new_from_fd(ret, 0)
 plain = ret.shift
 GPGME::gpgme_data_new_from_fd(ret, 1)
 sig = ret.shift
 GPGME::gpgme_op_sign(ctx, plain, sig, GPGME::SIG_MODE_CLEAR)

As you see, it's much harder to write a program in this API than the
highest level API. However, if you are already familiar with the C
interface of GPGME and want to control detailed behavior of GPGME, it
might be useful.

== Usage

All the high level methods attack the mid level <tt>GPGME::Ctx</tt> API. It is
recommended to read through the <tt>GPGME::Ctx.new</tt> methods for common options.

Also, most of the input/output is done via <tt>GPGME::Data</tt> objects that create a
common interface for reading/writing to normal strings, or other common
objects like files. Read the <tt>GPGME::Data</tt> documentation to understand
how it works. Every time the lib needs a <tt>GPGME::Data</tt> object, it will be
automatically converted to it.

=== Crypto

The <tt>GPGME::Crypto</tt> class has the high level convenience methods to encrypt,
decrypt, sign and verify signatures. Here are some examples, but it is
recommended to read through the <tt>GPGME::Crypto</tt> class to see all the options.

* Document encryption via <tt>GPGME::Crypto#encrypt</tt>:
 crypto = GPGME::Crypto.new
 crypto.encrypt "Hello world!", :recipients => "someone@example.com"

* Symmetric encryption:
 crypto = GPGME::Crypto.new :password => "gpgme"
 crypto.encrypt "Hello world!", :symmetric => true


* Document decryption via <tt>GPGME::Crypto#decrypt</tt> (including signature verification):
 crypto.decrypt File.open("text.gpg")

* Document signing via <tt>GPGME::Crypto#sign</tt>. Also the clearsigning and detached signing.
 crypto.sign "I hereby proclaim Github the beneficiary of all my money when I die"

* Sign verification via <tt>GPGME::Crypto#verify</tt>
 sign = crypto.sign "Some text"
 data = crypto.verify(sign) { |signature| signature.valid? }

=== Key

The <tt>GPGME::Key</tt> object represents a key, and has the high level related
methods to work with them and find them, export, import, deletetion and
creation.

* Key listing
 GPGME::Key.find(:secret, "someone@example.com")
 # => Returns an array with all the secret keys available in the keychain.
 #    that match "someone@example.com"

* Key exporting
 GPGME::Key.export("someone@example.com")
 # => Returns a GPGME::Data object with the exported key.

 key = GPGME::Key.find(:secret, "someone@example.com").first
 key.export
 # => Returns a GPGME::Data object with the exported key.

* Key importing
 GPGME::Key.import(File.open("my.key"))

* Key validation
 GPGME::Key.valid?(public_key)
 # => Returns wheter this key is valid or not


* TODO: Key generation

=== Engine

Provides three convenience methods to obtain information about the gpg engine
one is currently using. For example:

* Getting current information
 GPGME::Engine.info.first
      # => #<GPGME::EngineInfo:0x00000100d4fbd8
             @file_name="/usr/local/bin/gpg",
             @protocol=0,
             @req_version="1.3.0",
             @version="1.4.11">

* Changing home directory to work with different settings:
 GPGME::Engine.home_dir = '/tmp'

=== Round trip example using keychain keys

Rather than importing the keys it's possible to specify the recipient
when performing crypto functions. Here's a roundtrip example,
and note that as this is for a console, the <tt>conf.echo = false</tt>
line is to stop IRB complaining when echoing binary data

  # Stop IRB echoing everything, which errors with binary data.
  # Not required for production code
  conf.echo = false

  class PassphraseCallback
    def initialize(passphrase)
      @passphrase = passphrase
    end

    def call(*args)
      fd = args.last
      io = IO.for_fd(fd, 'w')
      io.puts(@passphrase)
      io.flush
    end
  end

  # recipients can be found using $ gpg --list-keys --homedir ./keychain_location
  # pub   2048R/A1B2C3D4 2014-01-17
  # Use that line to substitute your own. 2048R is the key length and type (RSA in this case)

  # If you want to substitute a non-default keychain into the engine do this:
  # home_dir = Rails.root.join('keychain_location').to_s
  # GPGME::Engine.set_info(GPGME::PROTOCOL_OpenPGP, '/usr/local/bin/gpg', home_dir)
  # Note GPG executable location will change across platforms


  crypto = GPGME::Crypto.new
  options = {:recipients => 'A1B2C3D4'}

  plaintext = GPGME::Data.new(File.open(Rails.root.join('Gemfile')))

  data = crypto.encrypt plaintext, options

  f = File.open(Rails.root.join('Gemfile.gpg'), 'wb')
  bytes_written = f.write(data)
  f.close

  puts bytes_written


  crypto = GPGME::Crypto.new
  options = {:recipients => 'A1B2C3D4', :passphrase_callback => PassphraseCallback.new('my_passphrase')}

  cipthertext = GPGME::Data.new(File.open(Rails.root.join('Gemfile.gpg')))

  data = crypto.decrypt cipthertext, options
  puts data


== Contributing

To run the local test suite you need bundler and gpg:

 bundle
 rake compile   # simple rake task to compile the extension
 rake           # runs the test suite

== License

The library itself is licensed under LGPLv2.1+.  See the file
COPYING.LESSER and each file for copyright and warranty information.
