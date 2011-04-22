$:.push File.expand_path("../..", __FILE__) # C extension is in the root

require 'gpgme_n'

# TODO without this call one can't GPGME::Ctx.new :\
GPGME::gpgme_check_version(nil)

require 'gpgme/constants'
require 'gpgme/aux'
require 'gpgme/ctx'
require 'gpgme/data'
require 'gpgme/error'
require 'gpgme/io_callbacks'
require 'gpgme/key_common'
require 'gpgme/key'
require 'gpgme/sub_key'
require 'gpgme/key_sig'
require 'gpgme/misc'
require 'gpgme/signature'
require 'gpgme/user_id'
require 'gpgme/high_level'

module GPGME
  extend Aux
  extend HighLevel

  class << self

    # From the c extension
    alias pubkey_algo_name gpgme_pubkey_algo_name
    alias hash_algo_name gpgme_hash_algo_name

  end
end
