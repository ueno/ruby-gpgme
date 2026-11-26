# -*- encoding: utf-8 -*-
require 'test_helper'

# Calls each low-level GPGME::gpgme_* function that the high-level API
# does not use, so that memory checkers (ASAN, Guard Malloc) see them.
describe "GPGME low-level functions" do
  before do
    skip unless ensure_keys GPGME::PROTOCOL_OpenPGP
  end

  def finish(ctx)
    status = []
    assert_same ctx, GPGME::gpgme_wait(ctx, status, 1)
    status.first
  end

  def check(err)
    exc = GPGME::error_to_exception(err)
    raise exc if exc
  end

  def key(sha = KEYS.first[:sha], secret = false)
    GPGME::Key.find(secret ? :secret : :public, sha).first
  end

  def read_all(data)
    data.seek(0)
    data.read
  end

  def armored_ctx
    ctx = GPGME::Ctx.new(armor: true)
    GPGME::gpgme_set_offline(ctx, 1) if GPGME.respond_to?(:gpgme_set_offline)
    ctx
  end

  it "gets back the callbacks it set" do
    ctx = GPGME::Ctx.new
    cb = proc {}
    GPGME::gpgme_set_passphrase_cb(ctx, cb, :pass)
    GPGME::gpgme_set_progress_cb(ctx, cb, :progress)
    GPGME::gpgme_set_status_cb(ctx, cb, :status) if GPGME.respond_to?(:gpgme_set_status_cb)
    %w[passphrase progress status].each do |name|
      getter = "gpgme_get_#{name}_cb"
      next unless GPGME.respond_to?(getter)
      func, hook = [], []
      GPGME.send(getter, ctx, func, hook)
      assert_same cb, func.first
      assert_equal name[0, 4], hook.first.to_s[0, 4]
    end
    ctx.release
  end

  it "sets and gets context settings" do
    ctx = GPGME::Ctx.new
    GPGME::gpgme_set_include_certs(ctx, 2)
    assert_equal 2, GPGME::gpgme_get_include_certs(ctx)
    GPGME::gpgme_set_locale(ctx, 0, "C")

    info = []
    GPGME::gpgme_ctx_get_engine_info(ctx, info)
    openpgp = info.find { |i| i.protocol == GPGME::PROTOCOL_OpenPGP }
    check GPGME::gpgme_ctx_set_engine_info(ctx, GPGME::PROTOCOL_OpenPGP,
                                           openpgp.file_name, openpgp.home_dir)

    GPGME::gpgme_signers_add(ctx, key(KEYS.first[:sha], true))
    assert_equal 1, GPGME::gpgme_signers_count(ctx) if GPGME.respond_to?(:gpgme_signers_count)
    assert_instance_of GPGME::Key, GPGME::gpgme_signers_enum(ctx, 0)
    assert_nil GPGME::gpgme_signers_enum(ctx, 1)
    ctx.release
  end

  it "runs every asynchronous crypto operation" do
    ctx = armored_ctx
    signer = key(KEYS.first[:sha], true)
    GPGME::gpgme_signers_add(ctx, signer)
    recipients = [key]
    flags = GPGME::ENCRYPT_ALWAYS_TRUST

    cipher = GPGME::Data.new
    check GPGME::gpgme_op_encrypt_start(ctx, recipients, flags,
                                        GPGME::Data.new("plain"), cipher)
    check finish(ctx)

    plain = GPGME::Data.new
    check GPGME::gpgme_op_decrypt_start(ctx, GPGME::Data.new(read_all(cipher)), plain)
    check finish(ctx)
    assert_equal "plain", read_all(plain)

    signed_cipher = GPGME::Data.new
    check GPGME::gpgme_op_encrypt_sign_start(ctx, recipients, flags,
                                             GPGME::Data.new("both"), signed_cipher)
    check finish(ctx)

    plain = GPGME::Data.new
    check GPGME::gpgme_op_decrypt_verify_start(ctx, GPGME::Data.new(read_all(signed_cipher)), plain)
    check finish(ctx)
    assert_equal "both", read_all(plain)

    sig = GPGME::Data.new
    check GPGME::gpgme_op_sign_start(ctx, GPGME::Data.new("signed"), sig,
                                     GPGME::SIG_MODE_NORMAL)
    check finish(ctx)

    plain = GPGME::Data.new
    check GPGME::gpgme_op_verify_start(ctx, GPGME::Data.new(read_all(sig)), nil, plain)
    check finish(ctx)
    assert_equal "signed", read_all(plain)
    ctx.release
  end

  it "runs every asynchronous key operation" do
    ctx = armored_ctx
    shas = KEYS.first(2).map { |k| k[:sha] }

    exported = GPGME::Data.new
    check GPGME::gpgme_op_export_ext_start(ctx, shas, 0, exported)
    check finish(ctx)

    exported_keys = GPGME::Data.new
    check GPGME::gpgme_op_export_keys_start(ctx, shas.map { |s| key(s) }, 0, exported_keys)
    check finish(ctx)
    assert_equal read_all(exported).bytesize, read_all(exported_keys).bytesize

    check GPGME::gpgme_op_import_start(ctx, GPGME::Data.new(read_all(exported)))
    check finish(ctx)
    assert_equal 2, GPGME::gpgme_op_import_result(ctx).considered

    # Importing local keys by Key object needs a keyserver, so any error
    # is fine.  Only the memory handling matters here.
    GPGME::gpgme_op_import_keys(ctx, [key])
    if GPGME::gpgme_op_import_keys_start(ctx, [key]) == 0
      finish(ctx)
    end

    check GPGME::gpgme_op_keylist_ext_start(ctx, shas, 0)
    found = []
    loop do
      rkey = []
      err = GPGME::gpgme_op_keylist_next(ctx, rkey)
      break if GPGME::gpgme_err_code(err) == GPGME::GPG_ERR_EOF
      check err
      found << rkey.first
    end
    check GPGME::gpgme_op_keylist_end(ctx)
    assert_equal 2, found.size
    ctx.release
  end

  it "generates, edits and deletes a key asynchronously" do
    ctx = armored_ctx
    parms = <<~PARMS
      <GnupgKeyParms format="internal">
      Key-Type: EDDSA
      Key-Curve: ed25519
      Name-Email: lowlevel@example.com
      Expire-Date: 0
      %no-protection
      </GnupgKeyParms>
    PARMS
    check GPGME::gpgme_op_genkey_start(ctx, parms, nil, nil)
    check finish(ctx)
    generated = key("lowlevel@example.com", true)
    fpr = generated.fingerprint

    editfunc = proc do |_hook, status, args, fd|
      next unless fd >= 0
      reply = status == GPGME::GPGME_STATUS_GET_BOOL ? "y\n" : "quit\n"
      next unless [GPGME::GPGME_STATUS_GET_LINE, GPGME::GPGME_STATUS_GET_BOOL].include?(status)
      io = IO.for_fd(fd, autoclose: false)
      io.write(reply)
      io.flush
    end
    check GPGME::gpgme_op_edit_start(ctx, generated, editfunc, nil, GPGME::Data.new)
    check finish(ctx)

    if GPGME.respond_to?(:gpgme_op_delete_ext)
      flags = GPGME::DELETE_ALLOW_SECRET | GPGME::DELETE_FORCE
      check GPGME::gpgme_op_delete_ext(ctx, generated, flags)
    else
      check GPGME::gpgme_op_delete_start(ctx, generated, 1)
      check finish(ctx)
    end
    assert_nil GPGME::Key.find(:public, fpr).first
    ctx.release
  end

  it "runs delete_start" do
    ctx = GPGME::Ctx.new
    # Deleting a key with a secret part fails without allow_secret.
    # The error is expected; this only exercises the call.
    if GPGME::gpgme_op_delete_start(ctx, key(KEYS.first[:sha]), 0) == 0
      finish(ctx)
    end
    refute_nil GPGME::Key.find(:public, KEYS.first[:sha]).first
    ctx.release
  end

  it "spawns a process" do
    skip unless GPGME.respond_to?(:gpgme_op_spawn_start)
    ctx = GPGME::Ctx.new
    # GPGME_PROTOCOL_SPAWN is an enum, so the extension's #ifdef never
    # defines the Ruby constant.
    check GPGME::gpgme_set_protocol(ctx, 6)
    out = GPGME::Data.new
    check GPGME::gpgme_op_spawn_start(ctx, "/bin/echo", ["echo", "spawned"],
                                      GPGME::Data.new, out, GPGME::Data.new, 0)
    check finish(ctx)
    assert_equal "spawned\n", read_all(out)
    ctx.release
  end
end
