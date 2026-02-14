# GPGME Ruby Bindings

[![Build Status](https://github.com/ueno/ruby-gpgme/actions/workflows/test.yml/badge.svg)](https://github.com/ueno/ruby-gpgme/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/ueno/ruby-gpgme/badge.png)](https://coveralls.io/r/ueno/ruby-gpgme)


> **Documentation:**
> - [API docs (GitHub, latest)](https://www.rubydoc.info/github/ueno/ruby-gpgme)
> - [API docs (Gem release)](https://www.rubydoc.info/gems/gpgme)

> **Badges:**
> - Build: [![Build Status](https://github.com/ueno/ruby-gpgme/actions/workflows/test.yml/badge.svg)](https://github.com/ueno/ruby-gpgme/actions/workflows/test.yml)
> - Coverage: [![Coverage Status](https://coveralls.io/repos/ueno/ruby-gpgme/badge.png)](https://coveralls.io/r/ueno/ruby-gpgme)
>   (If badges do not render, check the respective service for status.)


## Requirements

- Ruby 2.5 or later (Ruby 2.0–2.4 are no longer supported)
- GPGME 2.0.0 or later (older versions are deprecated)
- `gpg-agent` (optional, but recommended)

> **Tested with:**
> - Ruby 2.5, 2.6, 2.7, 3.0, 3.1, 3.2
> - GPGME 2.0.0, 1.21.0

## Installation

```sh
$ gem install gpgme
```


## API Overview

GPGME provides three levels of API:
- **High-level API:** Easiest to use for common operations.
- **Mid-level API:** More control, less user-friendly.
- **Low-level API:** Closest to the C interface, for advanced use.

## Recent Features

- Support for GPGME 2.0.0 and later
- Deletion of secret keys without confirmation
- Improved thread safety and encryption flags
- `ignore_mdc_error` flag setter/getter
- Minimal key exports (`GPGME::Key.valid?`)
- Support for Ruby 3.2 and later
- More efficient key sign lookups
- Updated dependency versions (libgpg-error, libassuan)

See [NEWS](NEWS) for full changelog.

### High-level API Example

```ruby
crypto = GPGME::Crypto.new
crypto.clearsign $stdin, output: $stdout
```

### Mid-level API Example

```ruby
plain = GPGME::Data.new($stdin)
sig   = GPGME::Data.new($stdout)
GPGME::Ctx.new do |ctx|
  ctx.sign(plain, sig, GPGME::SIG_MODE_CLEAR)
end
```

### Low-level API Example

```ruby
ret = []
GPGME::gpgme_new(ret)
ctx = ret.shift
GPGME::gpgme_data_new_from_fd(ret, 0)
plain = ret.shift
GPGME::gpgme_data_new_from_fd(ret, 1)
sig = ret.shift
GPGME::gpgme_op_sign(ctx, plain, sig, GPGME::SIG_MODE_CLEAR)
```

The high-level API is recommended for most users. The low-level API is only needed for advanced use cases or when porting C code.

## Usage

Most high-level methods use the mid-level `GPGME::Ctx` API. Input/output is handled via `GPGME::Data` objects, which can wrap strings, files, or other IO objects. See the documentation for `GPGME::Ctx` and `GPGME::Data` for details.

### Crypto Operations

The `GPGME::Crypto` class provides methods for encryption, decryption, signing, and verification. Examples:

- **Encrypt for a recipient:**
  ```ruby
  crypto = GPGME::Crypto.new
  crypto.encrypt "Hello world!", recipients: "someone@example.com"
  ```
- **Symmetric encryption:**
  ```ruby
  crypto = GPGME::Crypto.new(password: "gpgme")
  crypto.encrypt "Hello world!", symmetric: true
  ```
- **Decrypt (with signature verification):**
  ```ruby
  crypto.decrypt File.open("text.gpg")
  ```
- **Sign data:**
  ```ruby
  crypto.sign "I hereby proclaim Github the beneficiary of all my money when I die"
  ```
- **Verify signature:**
  ```ruby
  sign = crypto.sign "Some text"
  data = crypto.verify(sign) { |signature| signature.valid? }
  ```


### Key Management

The `GPGME::Key` object represents a key and provides methods to find, export, import, delete, and create keys.

- **List keys:**
  ```ruby
  GPGME::Key.find(:secret, "someone@example.com")
  # => Array of secret keys matching the email
  ```
- **Export a key:**
  ```ruby
  GPGME::Key.export("someone@example.com")
  # => GPGME::Data object with the exported key
  key = GPGME::Key.find(:secret, "someone@example.com").first
  key.export
  # => GPGME::Data object
  ```
- **Import a key:**
  ```ruby
  GPGME::Key.import(File.open("my.key"))
  ```
- **Validate a key:**
  ```ruby
  GPGME::Key.valid?(public_key)
  # => true/false
  ```
- **Key generation:** _(See API docs; new flags available in GPGME 2.0.0+)_

### Engine Information

GPGME provides methods to obtain information about the GPG engine in use:

- **Get engine info:**
  ```ruby
  GPGME::Engine.info.first
  # => #<GPGME::EngineInfo ...>
  ```
- **Change home directory:**
  ```ruby
  GPGME::Engine.home_dir = '/tmp'
  ```

### Round Trip Example Using Keychain Keys

Rather than importing keys, you can specify the recipient directly. Example (for IRB/console):

```ruby
# Stop IRB echoing everything, which errors with binary data (not needed in production)
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

# Find recipients using: $ gpg --list-keys --homedir ./keychain_location
# pub   2048R/A1B2C3D4 2014-01-17
# Use the key ID (e.g., 'A1B2C3D4')

# To use a non-default keychain:
# home_dir = Rails.root.join('keychain_location').to_s
# GPGME::Engine.set_info(GPGME::PROTOCOL_OpenPGP, '/usr/local/bin/gpg', home_dir)

crypto = GPGME::Crypto.new
options = { recipients: 'A1B2C3D4' }
plaintext = GPGME::Data.new(File.open(Rails.root.join('Gemfile')))
data = crypto.encrypt plaintext, options

File.open(Rails.root.join('Gemfile.gpg'), 'wb') { |f| f.write(data) }

# Decrypt
crypto = GPGME::Crypto.new
options = { recipients: 'A1B2C3D4', passphrase_callback: PassphraseCallback.new('my_passphrase') }
ciphertext = GPGME::Data.new(File.open(Rails.root.join('Gemfile.gpg')))
data = crypto.decrypt ciphertext, options
puts data
```

## Contributing

To run the local test suite you need Bundler and GPG:

```sh
bundle
rake compile   # Compile the extension
rake           # Run the test suite
```

## License

This library is licensed under LGPLv2.1+. See the file `COPYING.LESSER` and each source file for copyright and warranty information.
