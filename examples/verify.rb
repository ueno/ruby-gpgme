#!/usr/bin/env ruby
require 'gpgme'

include GPGME

ctx = GPGME::Ctx.new
sig = GPGME::Data.new_from_mem(ARGF.read)
ctx.verify(sig)
signatures = ctx.verify_result.signatures
signatures.each do |signature|
  from_key = ctx.get_key(signature.fpr)
  from = from_key ? "#{from_key.subkeys[0].keyid} #{from_key.uids[0].uid}" :
    signature.fpr
  case GPGME::gpgme_err_code(signature.status)
  when GPGME::GPG_ERR_NO_ERROR
    puts("Good signature from #{from}")
  when GPGME::GPG_ERR_SIG_EXPIRED
    puts("Expired signature from #{from}")
  when GPGME::GPG_ERR_KEY_EXPIRED
    puts("Signature made from expired key #{from}")
  when GPGME::GPG_ERR_CERT_REVOKED
    puts("Signature made from revoked key #{from}")
  when GPGME::GPG_ERR_BAD_SIGNATURE
    puts("Bad signature from #{from}")
  when GPGME::GPG_ERR_NO_ERROR
    puts("No public key for #{from}")
  end
end
