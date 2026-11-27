/* gpgme_n.c -- low level interface to GPGME
   Copyright (C) 2003,2006,2007,2008,2009 Daiki Ueno

   This file is a part of Ruby-GPGME.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA */

/* While this file was written by hand, it is (semi) automatically
   generated.  High-level functions are written in Ruby instead of C
   (See "lib/gpgme.rb").  If you are about to edit this file, you may
   want to check out the translation rules:

1. Each symbol defined in this file is either a class, a module
   function, or a constant.  _No instance methods are defined here_.

2. Each symbol defined in this file follows the same naming convention
   as the GPGME API.  That is, symbol names are followed by `gpgme_'
   for functions, and `GPGME_' or `GPG_' for constants.

3. Output arguments are wrapped in arrays.  For example, the first
   argument of `gpgme_data_new' has the type `gpgme_data_t *', and to
   be used to hold a newly created gpgme_data_t object.  The
   corresponding Ruby interface expects an array (empty for typical
   cases) for that.  */

#include "ruby.h"
#ifdef HAVE_RUBY_ENCODING_H
#include "ruby/encoding.h"
#endif
#include "ruby/thread.h"
#include "gpgme.h"
#include <errno.h>
#include <string.h>

/* Blocking libgpgme calls run without the GVL, so other Ruby threads
   can run while gpg works.  Callbacks find the running call through a
   thread-local variable, so this needs thread-local storage, which
   extconf.rb checks for.  Without it, every call keeps the GVL as
   before.  */
#ifdef RUBY_GPGME_THREAD_LOCAL
#define RUBY_GPGME_RELEASE_GVL 1
#endif

/* Define this if you use GPGME 1.1.2 and earlier.
   https://bugs.g10code.com/gnupg/issue715 */
#ifdef RUBY_GPGME_NEED_WORKAROUND_KEYLIST_NEXT
#define CHECK_KEYLIST_IN_PROGRESS(vctx)                                   \
  if (rb_iv_get (vctx, "ruby_gpgme_keylist_in_progress") != Qtrue)        \
    return LONG2NUM(gpgme_error (GPG_ERR_INV_STATE))
#define CHECK_KEYLIST_NOT_IN_PROGRESS(vctx)                               \
  if (rb_iv_get (vctx, "ruby_gpgme_keylist_in_progress") == Qtrue)        \
    return LONG2NUM(gpgme_error (GPG_ERR_INV_STATE))
#define SET_KEYLIST_IN_PROGRESS(vctx)                                \
  rb_iv_set (vctx, "ruby_gpgme_keylist_in_progress", Qtrue)
#define RESET_KEYLIST_IN_PROGRESS(vctx)                              \
  rb_iv_set (vctx, "ruby_gpgme_keylist_in_progress", Qfalse)
#else
#define CHECK_KEYLIST_IN_PROGRESS(vctx)
#define CHECK_KEYLIST_NOT_IN_PROGRESS(vctx)
#define SET_KEYLIST_IN_PROGRESS(vctx)
#define RESET_KEYLIST_IN_PROGRESS(vctx)
#endif

/* StringValuePtr is not available in 1.6. */
#ifndef StringValuePtr
#define StringValuePtr(str) RSTRING(str)->ptr
#endif

/* STR2CSTR is obsoleted in 1.8. */
#ifndef StringValueCStr
#define StringValueCStr STR2CSTR
#endif

/* RARRAY_LEN is not available in 1.8. */
#ifndef RARRAY_LEN
#define RARRAY_LEN(a) RARRAY(a)->len
#endif

/* RARRAY_PTR is not available in 1.8. */
#ifndef RARRAY_PTR
#define RARRAY_PTR(a) RARRAY(a)->ptr
#endif

/* RSTRING_LEN is not available in 1.8.5. */
#ifndef RSTRING_LEN
#define RSTRING_LEN(a) RSTRING(a)->len
#endif

/* Ruby objects whose VALUE is handed to libgpgme as a raw pointer
   (callback hook values) or that libgpgme uses after a call returns
   (the arguments of an asynchronous operation).  They are kept in an
   array per owning gpgme_ctx_t or gpgme_data_t, and the owner's mark
   function marks them with rb_gc_mark.  That keeps them alive as long
   as the owner and pins them, so GC.compact never moves an object
   libgpgme still points to.

   An asynchronous operation replaces its references only after
   libgpgme has accepted it, because until then the previous operation
   may still be running.  gpgme_wait clears them once the operation is
   done.  */
static st_table *owner_refs;

enum {
  CTX_REF_PASSPHRASE_CB,
  CTX_REF_STATUS_CB,
  CTX_REF_PROGRESS_CB,
  CTX_REF_EDIT_CB,
  CTX_REF_OP_ARGS
};

enum {
  DATA_REF_CBS
};

static void
owner_ref_set (void *owner, long slot, VALUE obj)
{
  st_data_t refs;

  if (!st_lookup (owner_refs, (st_data_t)owner, &refs))
    {
      refs = (st_data_t)rb_ary_new ();
      st_insert (owner_refs, (st_data_t)owner, refs);
    }
  rb_ary_store ((VALUE)refs, slot, obj);
}

static void
owner_refs_mark (void *owner)
{
  st_data_t refs;
  long i;

  if (owner && st_lookup (owner_refs, (st_data_t)owner, &refs))
    {
      rb_gc_mark ((VALUE)refs);
      for (i = 0; i < RARRAY_LEN((VALUE)refs); i++)
        rb_gc_mark (RARRAY_AREF((VALUE)refs, i));
    }
}

static void
owner_refs_delete (void *owner)
{
  st_data_t key = (st_data_t)owner;

  st_delete (owner_refs, &key, NULL);
}

/* Maps each libgpgme context to the GPGME::Ctx object that owns it, so
   that gpgme_wait can return the existing object instead of wrapping
   the context a second time.  The entries are weak: they are removed
   when the object is freed and updated when GC.compact moves it.  */
static st_table *ctx_objects;

/* What ctx_objects stores for each libgpgme context.  It is allocated
   separately, so GC.compact can update OBJECT without changing the
   table.  Changing the table would allocate, which is not allowed
   during GC.  */
struct ctx_entry
{
  VALUE object;                 /* The GPGME::Ctx object.  */
};

static void
owner_ref_clear (void *owner, long slot)
{
  st_data_t refs;

  if (st_lookup (owner_refs, (st_data_t)owner, &refs))
    rb_ary_store ((VALUE)refs, slot, Qnil);
}

/* TypedData type definitions for Ruby 3.x compatibility */
static void
gpgme_data_free(void *ptr)
{
  if (ptr)
    {
      owner_refs_delete (ptr);
      gpgme_data_release((gpgme_data_t)ptr);
    }
}

static const rb_data_type_t gpgme_data_type = {
  .wrap_struct_name = "GPGME::Data",
  .function = {
    .dmark = owner_refs_mark,
    .dfree = gpgme_data_free,
    .dsize = NULL,
  },
  .data = NULL,
  .flags = 0,
};

static void
gpgme_ctx_free(void *ptr)
{
  if (ptr)
    {
      st_data_t key = (st_data_t)ptr, value;

      if (st_delete (ctx_objects, &key, &value))
        xfree ((struct ctx_entry *)value);
      owner_refs_delete (ptr);
      gpgme_release((gpgme_ctx_t)ptr);
    }
}

static void
gpgme_ctx_compact(void *ptr)
{
  st_data_t value;

  if (ptr && st_lookup (ctx_objects, (st_data_t)ptr, &value))
    {
      struct ctx_entry *entry = (struct ctx_entry *)value;

      entry->object = rb_gc_location (entry->object);
    }
}

static const rb_data_type_t gpgme_ctx_type = {
  .wrap_struct_name = "GPGME::Ctx",
  .function = {
    .dmark = owner_refs_mark,
    .dfree = gpgme_ctx_free,
    .dsize = NULL,
    .dcompact = gpgme_ctx_compact,
  },
  .data = NULL,
  .flags = 0,
};

static void
gpgme_key_free(void *ptr)
{
  if (ptr)
    gpgme_key_unref((gpgme_key_t)ptr);
}

static const rb_data_type_t gpgme_key_type = {
  .wrap_struct_name = "GPGME::Key",
  .function = {
    .dmark = NULL,
    .dfree = gpgme_key_free,
    .dsize = NULL,
  },
  .data = NULL,
  .flags = 0,
};

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
static void
gpgme_trust_item_free(void *ptr)
{
  if (ptr)
    gpgme_trust_item_unref((gpgme_trust_item_t)ptr);
}

static const rb_data_type_t gpgme_trust_item_type = {
  .wrap_struct_name = "GPGME::TrustItem",
  .function = {
    .dmark = NULL,
    .dfree = gpgme_trust_item_free,
    .dsize = NULL,
  },
  .data = NULL,
  .flags = 0,
};
#endif

/* Contexts and data objects in use by a running libgpgme call, mapped
   to the fiber that runs it.  libgpgme does not allow two threads to
   use one context or data object at the same time, and the call runs
   without the GVL, so any other fiber that touches the object raises
   instead.  The table is only read and written with the GVL held.  */
static st_table *busy_objects;

static void
check_not_busy (const void *ptr, const char *what)
{
  st_data_t owner;

  if (ptr && st_lookup (busy_objects, (st_data_t)ptr, &owner)
      && (VALUE)owner != rb_fiber_current ())
    rb_raise (rb_eThreadError, "%s is in use by another thread", what);
}

#define WRAP_GPGME_DATA(dh)                                        \
  TypedData_Wrap_Struct(cData, &gpgme_data_type, dh)
/* `gpgme_data_t' is typedef'ed as `struct gpgme_data *'. */
#define UNWRAP_GPGME_DATA(vdh, dh)                                \
  do {                                                            \
    TypedData_Get_Struct(vdh, struct gpgme_data, &gpgme_data_type, dh); \
    check_not_busy (dh, "GPGME::Data");                           \
  } while (0)

#define WRAP_GPGME_CTX(ctx)                                        \
  TypedData_Wrap_Struct(cCtx, &gpgme_ctx_type, ctx)
/* `gpgme_ctx_t' is typedef'ed as `struct gpgme_context *'. */
#define UNWRAP_GPGME_CTX(vctx, ctx)                                \
  do {                                                            \
    TypedData_Get_Struct(vctx, struct gpgme_context, &gpgme_ctx_type, ctx); \
    check_not_busy (ctx, "GPGME::Ctx");                           \
  } while (0)

#define WRAP_GPGME_KEY(key)                                        \
  TypedData_Wrap_Struct(cKey, &gpgme_key_type, key)
/* `gpgme_key_t' is typedef'ed as `struct _gpgme_key *'. */
#define UNWRAP_GPGME_KEY(vkey, key)                                \
  TypedData_Get_Struct(vkey, struct _gpgme_key, &gpgme_key_type, key)

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
#define WRAP_GPGME_TRUST_ITEM(item)                                          \
  TypedData_Wrap_Struct(cTrustItem, &gpgme_trust_item_type, item)
/* `gpgme_trust_item_t' is typedef'ed as `struct _gpgme_trust_item *'. */
#define UNWRAP_GPGME_TRUST_ITEM(vitem, item)                        \
  TypedData_Get_Struct(vitem, struct _gpgme_trust_item, &gpgme_trust_item_type, item)
#endif

static VALUE cEngineInfo,
  cCtx,
  cData,
  cKey,
  cSubKey,
  cUserID,
  cKeySig,
  cInvalidKey,
  cNewSignature,
  cSignature,
  cSigNotation,
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
  cTrustItem,
#endif
  cRecipient,
  cDecryptResult,
  cVerifyResult,
  cSignResult,
  cEncryptResult,
  cImportStatus,
  cImportResult;

/* A blocking libgpgme call, made without the GVL.

   The caller converts every Ruby argument into this struct first,
   because nothing may touch a Ruby object without the GVL.  Strings
   and key arrays are copied or referenced, since another thread could
   change or free the originals while the call runs.  FN then makes
   the libgpgme call from the struct.

   Callbacks take the GVL back to run Ruby code.  If one raises, the
   exception is stored here, libgpgme gets an error, and the exception
   is raised again once the call returns.

   There is no unblocking function.  Interrupting libgpgme would cancel
   the operation on every signal, including the SIGCHLD from gpg
   itself, so Thread#raise and Thread#kill wait for the call to end.  */
typedef struct gpgme_call gpgme_call_t;
struct gpgme_call
{
  void (*fn) (gpgme_call_t *c);
  gpgme_ctx_t ctx;
  void *p[4];                   /* Pointer arguments, mostly data.  */
  size_t u[2];                  /* Integer arguments.  size_t holds both
                                   the int flags and the size_t sizes.  */
  gpgme_key_t key_in;           /* Key argument, referenced.  */
  gpgme_key_t *keys;            /* Key array argument, referenced.  */
  char *str;                    /* String argument, copied.  */
  const char **strv;            /* String array argument, copied.  */

  gpgme_error_t err;            /* Results.  */
  gpgme_key_t key;              /* Referenced until the caller wraps it.  */
  size_t size;
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
  gpgme_trust_item_t item;
#endif

  /* For an asynchronous operation, the objects to keep alive until it
     completes.  They are saved only if libgpgme accepted it.  */
  VALUE op_args;
  VALUE edit_cb;

  void *busy[6];
  int nbusy;
  int marked;
  int ran;                      /* libgpgme made the call.  */
  int done;                     /* The caller gets the results.  */

  /* Callback state.  */
  int state;                    /* Tag of the jump out of a callback.  */
  VALUE errinfo;
};

#ifdef RUBY_GPGME_RELEASE_GVL
/* The call that is running without the GVL on this thread, or NULL.
   It is set only while no Ruby code runs: callbacks clear it before
   they run Ruby code and set it again after.  So Ruby code always sees
   NULL, and a call started from a callback, or from another fiber that
   a callback switched to, never sees the outer call.  */
static RUBY_GPGME_THREAD_LOCAL gpgme_call_t *current_call;
#endif

static void
gpgme_call_init (gpgme_call_t *c, void (*fn) (gpgme_call_t *),
                 gpgme_ctx_t ctx)
{
  memset (c, 0, sizeof *c);
  c->fn = fn;
  c->ctx = ctx;
  c->op_args = Qnil;
  c->edit_cb = Qnil;
  c->errinfo = Qnil;
  if (ctx)
    c->busy[c->nbusy++] = ctx;
}

/* Mark the data object DH busy during the call.  */
static void
gpgme_call_use (gpgme_call_t *c, gpgme_data_t dh)
{
  if (dh && c->nbusy < (int)(sizeof c->busy / sizeof c->busy[0]))
    c->busy[c->nbusy++] = dh;
}

/* Copy the string VSTR for the call.  */
static void
gpgme_call_str (gpgme_call_t *c, VALUE vstr)
{
  const char *str = StringValueCStr(vstr);
  size_t len = strlen (str);

  c->str = xmalloc (len + 1);
  memcpy (c->str, str, len + 1);
}

/* Copy the strings in VSTRS, which string_array_new returned, into one
   block that holds a NULL-terminated array and the bytes.  */
static void
gpgme_call_strv (gpgme_call_t *c, VALUE vstrs)
{
  long i, len = RARRAY_LEN(vstrs);
  size_t size = (len + 1) * sizeof (char *);
  char **strv, *p;

  for (i = 0; i < len; i++)
    size += RSTRING_LEN(RARRAY_AREF(vstrs, i)) + 1;
  strv = xmalloc (size);
  p = (char *)(strv + len + 1);
  for (i = 0; i < len; i++)
    {
      VALUE vstr = RARRAY_AREF(vstrs, i);
      long n = RSTRING_LEN(vstr);

      memcpy (p, RSTRING_PTR(vstr), n);
      p[n] = '\0';
      strv[i] = p;
      p += n + 1;
    }
  strv[len] = NULL;
  c->strv = (const char **)strv;
}

/* Reference the key in VKEY for the call.  */
static void
gpgme_call_key (gpgme_call_t *c, VALUE vkey)
{
  gpgme_key_t key;

  TypedData_Get_Struct(vkey, struct _gpgme_key, &gpgme_key_type, key);
  gpgme_key_ref (key);
  c->key_in = key;
}

/* Reference the keys in the array VKEYS for the call.  Every element
   is checked first, so a bad element raises before anything is
   allocated.  */
static void
gpgme_call_keys (gpgme_call_t *c, VALUE vkeys)
{
  long i, len;

  Check_Type (vkeys, T_ARRAY);
  len = RARRAY_LEN(vkeys);
  for (i = 0; i < len; i++)
    rb_check_typeddata (RARRAY_AREF(vkeys, i), &gpgme_key_type);
  c->keys = ALLOC_N(gpgme_key_t, len + 1);
  for (i = 0; i < len; i++)
    {
      TypedData_Get_Struct(RARRAY_AREF(vkeys, i), struct _gpgme_key,
                           &gpgme_key_type, c->keys[i]);
      gpgme_key_ref (c->keys[i]);
    }
  c->keys[len] = NULL;
}

static void
gpgme_call_free (gpgme_call_t *c)
{
  gpgme_key_t *key;

  if (c->key_in)
    gpgme_key_unref (c->key_in);
  if (c->keys)
    {
      for (key = c->keys; *key; key++)
        gpgme_key_unref (*key);
      xfree (c->keys);
    }
  if (c->str)
    xfree (c->str);
  if (c->strv)
    xfree ((void *)c->strv);
}

/* Release the results of a call that won't reach its caller, because
   an exception ended it.  */
static void
gpgme_call_drop_results (gpgme_call_t *c)
{
  if (c->key)
    gpgme_key_unref (c->key);
  c->key = NULL;
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
  if (c->item)
    gpgme_trust_item_unref (c->item);
  c->item = NULL;
#endif
}

static VALUE
gpgme_call_ensure (VALUE arg)
{
  gpgme_call_t *c = (gpgme_call_t *)arg;
  int i;

  if (c->marked)
    for (i = 0; i < c->nbusy; i++)
      {
        st_data_t key = (st_data_t)c->busy[i];

        st_delete (busy_objects, &key, NULL);
      }
  gpgme_call_free (c);
  /* Thread#raise or Thread#kill can be handled right after the call,
     before the caller wraps its results.  */
  if (!c->done)
    gpgme_call_drop_results (c);
  /* libgpgme uses these until the asynchronous operation completes.  */
  if (c->ran && !c->err)
    {
      if (!NIL_P(c->op_args))
        owner_ref_set (c->ctx, CTX_REF_OP_ARGS, c->op_args);
      if (!NIL_P(c->edit_cb))
        owner_ref_set (c->ctx, CTX_REF_EDIT_CB, c->edit_cb);
    }
  return Qnil;
}

#ifdef RUBY_GPGME_RELEASE_GVL
static void *
gpgme_call_nogvl (void *arg)
{
  gpgme_call_t *c = arg;

  current_call = c;
  c->fn (c);
  current_call = NULL;
  c->ran = 1;
  return NULL;
}
#endif

static VALUE
gpgme_call_body (VALUE arg)
{
  gpgme_call_t *c = (gpgme_call_t *)arg;

#ifdef RUBY_GPGME_RELEASE_GVL
  /* This handles pending interrupts before and after the call, and
     either can raise.  */
  rb_thread_call_without_gvl (gpgme_call_nogvl, c, NULL, NULL);
#else
  c->fn (c);
  c->ran = 1;
#endif
  c->done = 1;
  return Qnil;
}

static int
is_exception (VALUE obj)
{
  return !SPECIAL_CONST_P(obj) && BUILTIN_TYPE(obj) == T_OBJECT
    && rb_obj_is_kind_of (obj, rb_eException);
}

/* Make the call C and return its error code.  This raises if an object
   the call uses is busy, or if a callback raised.  */
static gpgme_error_t
gpgme_call_run (gpgme_call_t *c)
{
  int i;

  for (i = 0; i < c->nbusy; i++)
    if (st_lookup (busy_objects, (st_data_t)c->busy[i], NULL))
      {
        gpgme_call_free (c);
        rb_raise (rb_eThreadError, "%s is in use by another thread",
                  c->busy[i] == c->ctx ? "GPGME::Ctx" : "GPGME::Data");
      }
  for (i = 0; i < c->nbusy; i++)
    st_insert (busy_objects, (st_data_t)c->busy[i],
               (st_data_t)rb_fiber_current ());
  c->marked = 1;

  rb_ensure (gpgme_call_body, (VALUE)c, gpgme_call_ensure, (VALUE)c);

  if (c->state)
    {
      gpgme_call_drop_results (c);
      if (is_exception (c->errinfo))
        rb_exc_raise (c->errinfo);
      rb_jump_tag (c->state);
    }
  return c->err;
}

struct callback
{
  VALUE (*fn) (VALUE);
  void *arg;
  gpgme_call_t *call;
};

#ifdef RUBY_GPGME_RELEASE_GVL
static void *
callback_with_gvl (void *arg)
{
  struct callback *cb = arg;
  gpgme_call_t *c = cb->call;
  int state = 0;

  /* After one callback fails, run no more Ruby code.  libgpgme gets
     an error from every callback until the operation ends.  */
  if (c->state)
    return NULL;
  rb_protect (cb->fn, (VALUE)cb->arg, &state);
  if (state)
    {
      c->state = state;
      c->errinfo = rb_errinfo ();
      /* A throw or a thread kill leaves no exception.  Their state
         stays in errinfo until rb_jump_tag resumes them.  */
      if (is_exception (c->errinfo))
        rb_set_errinfo (Qnil);
    }
  return NULL;
}
#endif

/* Run FN(ARG), the Ruby side of a callback from libgpgme.  Return 0 on
   success, or -1 if it raised and libgpgme must get an error.  */
static int
callback_run (VALUE (*fn) (VALUE), void *arg)
{
#ifdef RUBY_GPGME_RELEASE_GVL
  gpgme_call_t *c = current_call;
  struct callback cb;

  if (c)
    {
      cb.fn = fn;
      cb.arg = arg;
      cb.call = c;
      current_call = NULL;
      rb_thread_call_with_gvl (callback_with_gvl, &cb);
      current_call = c;
      return c->state ? -1 : 0;
    }
#endif
  /* The GVL is held, because the call came straight from Ruby, such as
     Data#read or gpgme_wait.  An exception goes straight to the Ruby
     code that called.  */
  fn ((VALUE)arg);
  return 0;
}

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
static VALUE
rb_s_gpgme_get_dirinfo (VALUE dummy, VALUE vwhat)
{
  const char *result = gpgme_get_dirinfo (StringValueCStr(vwhat));
  return result ? rb_str_new2 (result) : Qnil;
}
#endif

static VALUE
rb_s_gpgme_check_version (VALUE dummy, VALUE vreq)
{
  const char *result = gpgme_check_version (NIL_P(vreq) ? NULL :
                                            StringValueCStr(vreq));
  return result ? rb_str_new2 (result) : Qnil;
}

static VALUE
rb_s_gpgme_engine_check_version (VALUE dummy, VALUE vproto)
{
  gpgme_error_t err = gpgme_engine_check_version (NUM2INT(vproto));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_engine_info (VALUE dummy, VALUE rinfo)
{
  gpgme_engine_info_t info;
  gpgme_error_t err;
  long idx;

  err = gpgme_get_engine_info (&info);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      for (idx = 0; info; info = info->next, idx++)
        {
          VALUE vinfo = rb_class_new_instance (0, NULL, cEngineInfo);
          rb_iv_set (vinfo, "@protocol", INT2FIX(info->protocol));
          if (info->file_name)
            rb_iv_set (vinfo, "@file_name", rb_str_new2 (info->file_name));
          if (info->version)
            rb_iv_set (vinfo, "@version", rb_str_new2 (info->version));
          if (info->req_version)
            rb_iv_set (vinfo, "@req_version", rb_str_new2 (info->req_version));
          if (info->home_dir)
            rb_iv_set (vinfo, "@home_dir", rb_str_new2 (info->home_dir));
          rb_ary_store (rinfo, idx, vinfo);
        }
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_set_engine_info (VALUE dummy, VALUE vproto, VALUE vfile_name,
                            VALUE vhome_dir)
{
  gpgme_error_t err = gpgme_set_engine_info (NUM2INT(vproto),
                                             NIL_P(vfile_name) ? NULL :
                                             StringValueCStr(vfile_name),
                                             NIL_P(vhome_dir) ? NULL :
                                             StringValueCStr(vhome_dir));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_ctx_get_engine_info (VALUE dummy, VALUE vctx, VALUE rinfo)
{
  long idx;

  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_engine_info_t info = gpgme_ctx_get_engine_info (ctx);
      for (idx = 0; info; info = info->next, idx++)
        {
          VALUE vinfo = rb_class_new_instance (0, NULL, cEngineInfo);
          rb_iv_set (vinfo, "@protocol", INT2FIX(info->protocol));
          if (info->file_name)
            rb_iv_set (vinfo, "@file_name", rb_str_new2 (info->file_name));
          if (info->version)
            rb_iv_set (vinfo, "@version", rb_str_new2 (info->version));
          if (info->req_version)
            rb_iv_set (vinfo, "@req_version", rb_str_new2 (info->req_version));
          if (info->home_dir)
            rb_iv_set (vinfo, "@home_dir", rb_str_new2 (info->home_dir));
          rb_ary_store (rinfo, idx, vinfo);
        }
  return Qnil;
}

static VALUE
rb_s_gpgme_ctx_set_engine_info (VALUE dummy, VALUE vctx, VALUE vproto, VALUE vfile_name,
                            VALUE vhome_dir)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_error_t err = gpgme_ctx_set_engine_info (ctx,
               NUM2INT(vproto),
                                             NIL_P(vfile_name) ? NULL :
                                             StringValueCStr(vfile_name),
                                             NIL_P(vhome_dir) ? NULL :
                                             StringValueCStr(vhome_dir));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_pubkey_algo_name (VALUE dummy, VALUE valgo)
{
  const char *name = gpgme_pubkey_algo_name (NUM2INT(valgo));
  if (name)
    return rb_str_new2 (name);
  return Qnil;
}

static VALUE
rb_s_gpgme_hash_algo_name (VALUE dummy, VALUE valgo)
{
  const char *name = gpgme_hash_algo_name (NUM2INT(valgo));
  if (name)
    return rb_str_new2 (name);
  return Qnil;
}

static VALUE
rb_s_gpgme_err_code (VALUE dummy, VALUE verr)
{
  return INT2FIX(gpgme_err_code (NUM2UINT(verr)));
}

static VALUE
rb_s_gpgme_err_source (VALUE dummy, VALUE verr)
{
  return INT2FIX(gpgme_err_source (NUM2UINT(verr)));
}

static VALUE
rb_s_gpgme_strerror (VALUE dummy, VALUE verr)
{
  return rb_str_new2 (gpgme_strerror (NUM2UINT(verr)));
}

static VALUE
rb_s_gpgme_data_new (VALUE dummy, VALUE rdh)
{
  gpgme_data_t dh;
  gpgme_error_t err = gpgme_data_new (&dh);

  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    rb_ary_store (rdh, 0, WRAP_GPGME_DATA(dh));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_new_from_mem (VALUE dummy, VALUE rdh, VALUE vbuffer,
                              VALUE vsize)
{
  gpgme_data_t dh;
  VALUE vdh;
  size_t size = NUM2UINT(vsize);
  gpgme_error_t err;

  StringValue(vbuffer);
  if ((size_t)RSTRING_LEN(vbuffer) < size)
    rb_raise (rb_eArgError, "argument out of range");

  err = gpgme_data_new_from_mem (&dh, RSTRING_PTR(vbuffer), size, 1);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      vdh = WRAP_GPGME_DATA(dh);
      rb_ary_store (rdh, 0, vdh);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_new_from_fd (VALUE dummy, VALUE rdh, VALUE vfd)
{
  gpgme_data_t dh;
  gpgme_error_t err = gpgme_data_new_from_fd (&dh, NUM2INT(vfd));
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    rb_ary_store (rdh, 0, WRAP_GPGME_DATA(dh));
  return LONG2NUM(err);
}

/* Arguments and result of a data callback.  The callbacks build Ruby
   objects, so the Ruby side runs with the GVL through callback_run.  */
struct data_cb_args
{
  VALUE vcb;
  void *buffer;
  size_t size;
  off_t offset;
  int whence;
  long ret;
  int err;
};

static VALUE
read_cb_ruby (VALUE arg)
{
  struct data_cb_args *a = (struct data_cb_args *)arg;
  VALUE vcbs, vhook_value, vbuffer;

  vcbs = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  vbuffer = rb_funcall (vcbs, rb_intern ("read"), 2, vhook_value,
                        LONG2NUM(a->size));
  if (NIL_P(vbuffer))
    {
      a->ret = 0;
      return Qnil;
    }
  StringValue(vbuffer);
  /* Never copy more than libgpgme asked for. */
  if ((size_t)RSTRING_LEN(vbuffer) > a->size)
    {
      a->err = EINVAL;
      return Qnil;
    }
  memcpy (a->buffer, RSTRING_PTR(vbuffer), RSTRING_LEN(vbuffer));
  a->ret = RSTRING_LEN(vbuffer);
  return Qnil;
}

static ssize_t
read_cb (void *handle, void *buffer, size_t size)
{
  struct data_cb_args a = { (VALUE)handle, buffer, size, 0, 0, -1, EIO };

  if (callback_run (read_cb_ruby, &a) < 0 || a.ret < 0)
    {
      errno = a.err;
      return -1;
    }
  return a.ret;
}

static VALUE
write_cb_ruby (VALUE arg)
{
  struct data_cb_args *a = (struct data_cb_args *)arg;
  VALUE vcbs, vhook_value, vbuffer, vnwrite;
  rb_encoding *enc;

  vcbs = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);
  vbuffer = rb_str_new (a->buffer, a->size);

  /* Associate encoding with the buffer string.
   * Use default internal encoding if set, otherwise use binary encoding.
   * This allows the app author to control the encoding via
   * Encoding.default_internal while maintaining backward compatibility. */
  enc = rb_default_internal_encoding ();
  if (!enc)
    enc = rb_ascii8bit_encoding ();
  rb_enc_associate (vbuffer, enc);

  vnwrite = rb_funcall (vcbs, rb_intern ("write"), 3,
                        vhook_value, vbuffer, LONG2NUM(a->size));
  a->ret = NUM2LONG(vnwrite);
  return Qnil;
}

static ssize_t
write_cb (void *handle, const void *buffer, size_t size)
{
  struct data_cb_args a = { (VALUE)handle, (void *)buffer, size, 0, 0, -1,
                            EIO };

  if (callback_run (write_cb_ruby, &a) < 0)
    {
      errno = a.err;
      return -1;
    }
  return a.ret;
}

static VALUE
seek_cb_ruby (VALUE arg)
{
  struct data_cb_args *a = (struct data_cb_args *)arg;
  VALUE vcbs, vhook_value, vpos;
  ID id_seek = rb_intern ("seek");

  vcbs = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  if (rb_respond_to (vcbs, id_seek))
    {
      vpos = rb_funcall (vcbs, id_seek, 3,
                         vhook_value, LONG2NUM(a->offset),
                         INT2FIX(a->whence));
      a->ret = NUM2LONG(vpos);
      return Qnil;
    }
  a->err = ENOSYS;
  return Qnil;
}

static off_t
seek_cb (void *handle, off_t offset, int whence)
{
  struct data_cb_args a = { (VALUE)handle, NULL, 0, offset, whence, -1,
                            EIO };

  if (callback_run (seek_cb_ruby, &a) < 0 || a.ret < 0)
    {
      errno = a.err;
      return -1;
    }
  return a.ret;
}

static struct gpgme_data_cbs cbs =
  {
    .read = read_cb,
    .write = write_cb,
    .seek = seek_cb,
    .release = NULL
  };

static VALUE
rb_s_gpgme_data_new_from_cbs (VALUE dummy, VALUE rdh, VALUE vcbs,
                              VALUE vhandle)
{
  gpgme_data_t dh;
  gpgme_error_t err;
  VALUE vcbs_handle = rb_ary_new ();

  rb_ary_push (vcbs_handle, vcbs);
  rb_ary_push (vcbs_handle, vhandle);

  err = gpgme_data_new_from_cbs (&dh, &cbs, (void*)vcbs_handle);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      VALUE vdh = WRAP_GPGME_DATA(dh);
      /* Keep a reference to avoid GC. */
      rb_iv_set (vdh, "@cbs_handle", vcbs_handle);
      owner_ref_set (dh, DATA_REF_CBS, vcbs_handle);
      rb_ary_store (rdh, 0, vdh);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_read (VALUE dummy, VALUE vdh, VALUE vlength)
{
  gpgme_data_t dh;
  ssize_t length = NUM2LONG(vlength), nread;
  VALUE vbuffer;

  UNWRAP_GPGME_DATA(vdh, dh);

  /* Read straight into a string.  A read callback can raise out of
     gpgme_data_read, and a separate buffer would then leak.  No other
     code can see the string, and the reference on this stack keeps GC
     from moving it.  */
  vbuffer = rb_str_buf_new (length);
  nread = gpgme_data_read (dh, RSTRING_PTR(vbuffer), length);
  if (nread < 0)
    rb_sys_fail ("rb_s_gpgme_data_read");
  if (nread == 0)
    return Qnil;
  rb_str_set_len (vbuffer, nread);
  return vbuffer;
}

static VALUE
rb_s_gpgme_data_seek (VALUE dummy, VALUE vdh, VALUE voffset, VALUE vwhence)
{
  gpgme_data_t dh;
  off_t pos;

  UNWRAP_GPGME_DATA(vdh, dh);
  pos = gpgme_data_seek (dh, NUM2LONG(voffset), NUM2INT(vwhence));
  if (pos < 0)
    rb_sys_fail ("rb_s_gpgme_data_seek");
  return LONG2NUM(pos);
}

static VALUE
rb_s_gpgme_data_write (VALUE dummy, VALUE vdh, VALUE vbuf, VALUE vlen)
{
  gpgme_data_t dh;
  ssize_t nwrite;
  size_t length = NUM2SIZET(vlen);

  UNWRAP_GPGME_DATA(vdh, dh);
  StringValue(vbuf);
  if (length > (size_t)RSTRING_LEN(vbuf))
    rb_raise (rb_eArgError, "length is larger than the buffer");
  nwrite = gpgme_data_write (dh, RSTRING_PTR(vbuf), length);
  if (nwrite < 0)
    rb_sys_fail ("rb_s_gpgme_data_write");
  return LONG2NUM(nwrite);
}

static VALUE
rb_s_gpgme_data_get_encoding (VALUE dummy, VALUE vdh)
{
  gpgme_data_t dh;
  gpgme_error_t err;

  UNWRAP_GPGME_DATA(vdh, dh);
  err = gpgme_data_get_encoding (dh);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_set_encoding (VALUE dummy, VALUE vdh, VALUE venc)
{
  gpgme_data_t dh;
  gpgme_error_t err;

  UNWRAP_GPGME_DATA(vdh, dh);
  err = gpgme_data_set_encoding (dh, NUM2INT(venc));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_get_file_name (VALUE dummy, VALUE vdh)
{
  gpgme_data_t dh;

  UNWRAP_GPGME_DATA(vdh, dh);
  const char *result = gpgme_data_get_file_name (dh);
  return result ? rb_str_new2 (result) : Qnil;
}

static VALUE
rb_s_gpgme_data_set_file_name (VALUE dummy, VALUE vdh, VALUE vfile_name)
{
  gpgme_data_t dh;
  gpgme_error_t err;

  UNWRAP_GPGME_DATA(vdh, dh);
  err = gpgme_data_set_file_name (dh,
      NIL_P(vfile_name) ? NULL : StringValueCStr(vfile_name));
  return LONG2NUM(err);
}

struct ctx_objects_insert_args
{
  gpgme_ctx_t ctx;
  struct ctx_entry *entry;
};

static VALUE
ctx_objects_insert (VALUE arg)
{
  struct ctx_objects_insert_args *args = (struct ctx_objects_insert_args *)arg;

  st_insert (ctx_objects, (st_data_t)args->ctx, (st_data_t)args->entry);
  return Qnil;
}

static VALUE
rb_s_gpgme_new (VALUE dummy, VALUE rctx)
{
  struct ctx_objects_insert_args args;
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  VALUE vctx;
  int state;

  /* Allocate the wrapper and the entry before the context exists, so
     an exception from either leaks nothing.  The wrapper holds NULL
     until it owns the context.  */
  vctx = WRAP_GPGME_CTX(NULL);
  args.entry = ALLOC(struct ctx_entry);
  err = gpgme_new (&ctx);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR)
    {
      xfree (args.entry);
      return LONG2NUM(err);
    }
  RTYPEDDATA_DATA(vctx) = ctx;
  args.entry->object = vctx;

  /* st_insert raises NoMemoryError if it can't grow the table.  The
     wrapper already owns the context and frees it, but the entry is
     not in the table yet, so free it here.  */
  args.ctx = ctx;
  rb_protect (ctx_objects_insert, (VALUE)&args, &state);
  if (state)
    {
      xfree (args.entry);
      rb_jump_tag (state);
    }
  rb_ary_store (rctx, 0, vctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_release (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  /* A callback must not release the context of the running call.  */
  if (st_lookup (busy_objects, (st_data_t)ctx, NULL))
    rb_raise (rb_eThreadError, "GPGME::Ctx is in use");
  gpgme_ctx_free (ctx);
  RTYPEDDATA_DATA(vctx) = NULL;
  return Qnil;
}

static VALUE
rb_s_gpgme_set_ctx_flag (VALUE dummy, VALUE vctx, VALUE vname, VALUE vstr)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  char* name;
  char* str;

  name = StringValueCStr(vname);
  str = StringValueCStr(vstr);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_set_ctx_flag(ctx, name, str);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_ctx_flag (VALUE dummy, VALUE vctx, VALUE vname)
{
  gpgme_ctx_t ctx;
  const char* name;

  name = StringValueCStr(vname);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  const char* result;
  result = gpgme_get_ctx_flag(ctx, name);
  if (result == NULL)
    rb_raise (rb_eArgError, "incorrect ctx flag name");

  return rb_str_new_cstr(result);
}

static VALUE
rb_s_gpgme_set_protocol (VALUE dummy, VALUE vctx, VALUE vproto)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_set_protocol (ctx, NUM2INT(vproto));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_protocol (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_protocol_t proto;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  proto = gpgme_get_protocol (ctx);
  return INT2FIX(proto);
}

static VALUE
rb_s_gpgme_set_armor (VALUE dummy, VALUE vctx, VALUE vyes)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_armor (ctx, NUM2INT(vyes));

  return Qnil;
}

static VALUE
rb_s_gpgme_get_armor (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int yes;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  yes = gpgme_get_armor (ctx);
  return INT2FIX(yes);
}

static VALUE
rb_s_gpgme_set_ignore_mdc_error (VALUE dummy, VALUE vctx, VALUE vyes)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  int yes;

  yes = NUM2INT(vyes);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_set_ctx_flag(ctx, "ignore-mdc-error", yes ? "1" : "");
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_ignore_mdc_error (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int yes;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  const char* result;
  result = gpgme_get_ctx_flag(ctx, "ignore-mdc-error");
  if (result == NULL)
    rb_raise (rb_eArgError, "incorrect ctx flag name");

  yes = (result && *result)? !!atoi (result) : 0;
  return INT2FIX(yes);
}

static VALUE
rb_s_gpgme_set_textmode (VALUE dummy, VALUE vctx, VALUE vyes)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_textmode (ctx, NUM2INT(vyes));
  return Qnil;
}

static VALUE
rb_s_gpgme_get_textmode (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int yes;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  yes = gpgme_get_textmode (ctx);
  return INT2FIX(yes);
}

static VALUE
rb_s_gpgme_set_include_certs (VALUE dummy, VALUE vctx, VALUE vnr_of_certs)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_include_certs (ctx, NUM2INT(vnr_of_certs));
  return Qnil;
}

static VALUE
rb_s_gpgme_get_include_certs (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_get_include_certs (ctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_set_keylist_mode (VALUE dummy, VALUE vctx, VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_set_keylist_mode (ctx, NUM2INT(vmode));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_keylist_mode (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int mode;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  mode = gpgme_get_keylist_mode (ctx);
  return INT2FIX(mode);
}

/* Arguments of a context callback.  */
struct ctx_cb_args
{
  VALUE vcb;
  const char *s1;
  const char *s2;
  int i1;
  int i2;
  int i3;
};

/* The error a context callback returns when its Ruby code raised.  */
#define CALLBACK_FAILED gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_CANCELED)

static VALUE
passphrase_cb_ruby (VALUE arg)
{
  struct ctx_cb_args *a = (struct ctx_cb_args *)arg;
  VALUE vpassfunc, vhook_value;

  vpassfunc = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  rb_funcall (vpassfunc, rb_intern ("call"), 5,
              vhook_value,
              a->s1 ? rb_str_new2 (a->s1) : Qnil,
              a->s2 ? rb_str_new2 (a->s2) : Qnil,
              INT2FIX(a->i1),
              INT2NUM(a->i2));
  return Qnil;
}

static gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint, const char *passphrase_info,
               int prev_was_bad, int fd)
{
  struct ctx_cb_args a = { (VALUE)hook, uid_hint, passphrase_info,
                           prev_was_bad, fd, 0 };

  if (callback_run (passphrase_cb_ruby, &a) < 0)
    return CALLBACK_FAILED;
  return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR);
}

static VALUE
rb_s_gpgme_set_passphrase_cb (VALUE dummy, VALUE vctx, VALUE vpassfunc,
                              VALUE vhook_value)
{
  gpgme_ctx_t ctx;
  VALUE vcb = rb_ary_new ();

  rb_ary_push (vcb, vpassfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@passphrase_cb", vcb);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  owner_ref_set (ctx, CTX_REF_PASSPHRASE_CB, vcb);
  gpgme_set_passphrase_cb (ctx, passphrase_cb, (void*)vcb);
  return Qnil;
}

static VALUE
rb_s_gpgme_get_passphrase_cb (VALUE dummy, VALUE vctx, VALUE rpassfunc,
                              VALUE rhook_value)
{
  VALUE vcb = rb_iv_get (vctx, "@passphrase_cb");

  /* No need to call gpgme_get_passphrase_cb. */
  /* VCB is nil if no callback was set. */
  rb_ary_store (rpassfunc, 0, NIL_P(vcb) ? Qnil : RARRAY_AREF(vcb, 0));
  rb_ary_store (rhook_value, 0, NIL_P(vcb) ? Qnil : RARRAY_AREF(vcb, 1));
  return Qnil;
}

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010600
static VALUE
status_cb_ruby (VALUE arg)
{
  struct ctx_cb_args *a = (struct ctx_cb_args *)arg;
  VALUE vstatusfunc, vhook_value;

  vstatusfunc = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  rb_funcall (vstatusfunc, rb_intern ("call"), 3,
              vhook_value,
              a->s1 ? rb_str_new2 (a->s1) : Qnil,
              a->s2 ? rb_str_new2 (a->s2) : Qnil);
  return Qnil;
}

static gpgme_error_t
status_cb (void *hook, const char *keyword, const char *args)
{
  struct ctx_cb_args a = { (VALUE)hook, keyword, args, 0, 0, 0 };

  if (callback_run (status_cb_ruby, &a) < 0)
    return CALLBACK_FAILED;
  return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR);
}

static VALUE
rb_s_gpgme_set_status_cb (VALUE dummy, VALUE vctx, VALUE vstatusfunc,
                          VALUE vhook_value)
{
  gpgme_ctx_t ctx;
  VALUE vcb = rb_ary_new ();

  rb_ary_push (vcb, vstatusfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@status_cb", vcb);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  owner_ref_set (ctx, CTX_REF_STATUS_CB, vcb);
  gpgme_set_status_cb (ctx, status_cb, (void*)vcb);
  return Qnil;
}

static VALUE
rb_s_gpgme_get_status_cb (VALUE dummy, VALUE vctx, VALUE rstatusfunc,
                          VALUE rhook_value)
{
  VALUE vcb = rb_iv_get (vctx, "@status_cb");

  /* No need to call gpgme_get_status_cb. */
  /* VCB is nil if no callback was set. */
  rb_ary_store (rstatusfunc, 0, NIL_P(vcb) ? Qnil : RARRAY_AREF(vcb, 0));
  rb_ary_store (rhook_value, 0, NIL_P(vcb) ? Qnil : RARRAY_AREF(vcb, 1));
  return Qnil;
}
#endif

static VALUE
progress_cb_ruby (VALUE arg)
{
  struct ctx_cb_args *a = (struct ctx_cb_args *)arg;
  VALUE vprogfunc, vhook_value;

  vprogfunc = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  rb_funcall (vprogfunc, rb_intern ("call"), 5, vhook_value,
              rb_str_new2 (a->s1), INT2NUM(a->i1), INT2NUM(a->i2),
              INT2NUM(a->i3));
  return Qnil;
}

static void
progress_cb (void *hook, const char *what, int type, int current, int total)
{
  struct ctx_cb_args a = { (VALUE)hook, what, NULL, type, current, total };

  /* libgpgme ignores the result.  A failure is raised after the call. */
  callback_run (progress_cb_ruby, &a);
}

static VALUE
rb_s_gpgme_set_progress_cb (VALUE dummy, VALUE vctx, VALUE vprogfunc,
                            VALUE vhook_value)
{
  gpgme_ctx_t ctx;
  VALUE vcb = rb_ary_new ();

  rb_ary_push (vcb, vprogfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@progress_cb", vcb);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  owner_ref_set (ctx, CTX_REF_PROGRESS_CB, vcb);
  gpgme_set_progress_cb (ctx, progress_cb, (void*)vcb);

  return Qnil;
}

static VALUE
rb_s_gpgme_get_progress_cb (VALUE dummy, VALUE vctx, VALUE rprogfunc,
                            VALUE rhook_value)
{
  VALUE vcb = rb_iv_get (vctx, "@progress_cb");
  /* VCB is nil if no callback was set. */
  rb_ary_store (rprogfunc, 0, NIL_P(vcb) ? Qnil : RARRAY_AREF(vcb, 0));
  rb_ary_store (rhook_value, 0, NIL_P(vcb) ? Qnil : RARRAY_AREF(vcb, 1));
  return Qnil;
}

static VALUE
rb_s_gpgme_set_locale (VALUE dummy, VALUE vctx, VALUE vcategory, VALUE vvalue)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_set_locale (ctx, NUM2INT(vcategory), StringValueCStr(vvalue));
  return LONG2NUM(err);
}

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010400
static VALUE
rb_s_gpgme_set_pinentry_mode (VALUE dummy, VALUE vctx, VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_set_pinentry_mode (ctx, NUM2INT(vmode));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_pinentry_mode (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_pinentry_mode_t mode;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  mode = gpgme_get_pinentry_mode (ctx);
  return INT2FIX(mode);
}
#endif

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010600
static VALUE
rb_s_gpgme_set_offline (VALUE dummy, VALUE vctx, VALUE vyes)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_set_offline (ctx, vyes == Qtrue);
  return Qnil;
}

static VALUE
rb_s_gpgme_get_offline (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int yes;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  yes = gpgme_get_offline (ctx);
  return yes ? Qtrue : Qfalse;
}
#endif

/* Return a new array with each element of VARY converted to a String
   with no NUL bytes.  This runs any to_str conversions, and raises on
   bad input, before the caller allocates C memory.  */
static VALUE
string_array_new (VALUE vary)
{
  VALUE vstrs;
  long i;

  Check_Type (vary, T_ARRAY);
  vstrs = rb_ary_new_capa (RARRAY_LEN(vary));
  for (i = 0; i < RARRAY_LEN(vary); i++)
    {
      VALUE vstr = RARRAY_AREF(vary, i);

      StringValueCStr(vstr);
      rb_ary_push (vstrs, vstr);
    }
  return vstrs;
}

/* The libgpgme calls that gpgme_call_run makes without the GVL.  */
#define GPGME_CALL(name, expr)                                          \
  static void call_##name (gpgme_call_t *c) { c->err = (expr); }

GPGME_CALL(op_keylist_start,
           gpgme_op_keylist_start (c->ctx, c->str, (int)c->u[0]))
GPGME_CALL(op_keylist_ext_start,
           gpgme_op_keylist_ext_start (c->ctx, c->strv, (int)c->u[0], 0))
GPGME_CALL(op_keylist_next, gpgme_op_keylist_next (c->ctx, &c->key))
GPGME_CALL(op_keylist_end, gpgme_op_keylist_end (c->ctx))
GPGME_CALL(get_key, gpgme_get_key (c->ctx, c->str, &c->key, (int)c->u[0]))
GPGME_CALL(op_genkey,
           gpgme_op_genkey (c->ctx, c->str, c->p[0], c->p[1]))
GPGME_CALL(op_genkey_start,
           gpgme_op_genkey_start (c->ctx, c->str, c->p[0], c->p[1]))
GPGME_CALL(op_export,
           gpgme_op_export (c->ctx, c->str, (unsigned int)c->u[0], c->p[0]))
GPGME_CALL(op_export_start,
           gpgme_op_export_start (c->ctx, c->str, (unsigned int)c->u[0],
                                  c->p[0]))
GPGME_CALL(op_export_ext,
           gpgme_op_export_ext (c->ctx, c->strv, (unsigned int)c->u[0],
                                c->p[0]))
GPGME_CALL(op_export_ext_start,
           gpgme_op_export_ext_start (c->ctx, c->strv, (unsigned int)c->u[0],
                                      c->p[0]))
#ifdef HAVE_GPGME_OP_EXPORT_KEYS
GPGME_CALL(op_export_keys,
           gpgme_op_export_keys (c->ctx, c->keys, (unsigned int)c->u[0],
                                 c->p[0]))
GPGME_CALL(op_export_keys_start,
           gpgme_op_export_keys_start (c->ctx, c->keys, (unsigned int)c->u[0],
                                       c->p[0]))
GPGME_CALL(op_import_keys, gpgme_op_import_keys (c->ctx, c->keys))
GPGME_CALL(op_import_keys_start,
           gpgme_op_import_keys_start (c->ctx, c->keys))
#endif
GPGME_CALL(op_import, gpgme_op_import (c->ctx, c->p[0]))
GPGME_CALL(op_import_start, gpgme_op_import_start (c->ctx, c->p[0]))
GPGME_CALL(op_delete,
           gpgme_op_delete (c->ctx, c->key_in, (int)c->u[0]))
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010901
GPGME_CALL(op_delete_ext,
           gpgme_op_delete_ext (c->ctx, c->key_in, (unsigned int)c->u[0]))
#endif
GPGME_CALL(op_delete_start,
           gpgme_op_delete_start (c->ctx, c->key_in, (int)c->u[0]))
GPGME_CALL(op_decrypt, gpgme_op_decrypt (c->ctx, c->p[0], c->p[1]))
GPGME_CALL(op_decrypt_start,
           gpgme_op_decrypt_start (c->ctx, c->p[0], c->p[1]))
GPGME_CALL(op_verify, gpgme_op_verify (c->ctx, c->p[0], c->p[1], c->p[2]))
GPGME_CALL(op_verify_start,
           gpgme_op_verify_start (c->ctx, c->p[0], c->p[1], c->p[2]))
GPGME_CALL(op_decrypt_verify,
           gpgme_op_decrypt_verify (c->ctx, c->p[0], c->p[1]))
GPGME_CALL(op_decrypt_verify_start,
           gpgme_op_decrypt_verify_start (c->ctx, c->p[0], c->p[1]))
GPGME_CALL(op_sign,
           gpgme_op_sign (c->ctx, c->p[0], c->p[1], (int)c->u[0]))
GPGME_CALL(op_sign_start,
           gpgme_op_sign_start (c->ctx, c->p[0], c->p[1], (int)c->u[0]))
GPGME_CALL(op_encrypt,
           gpgme_op_encrypt (c->ctx, c->keys, (int)c->u[0], c->p[0],
                             c->p[1]))
GPGME_CALL(op_encrypt_start,
           gpgme_op_encrypt_start (c->ctx, c->keys, (int)c->u[0], c->p[0],
                                   c->p[1]))
GPGME_CALL(op_encrypt_sign,
           gpgme_op_encrypt_sign (c->ctx, c->keys, (int)c->u[0], c->p[0],
                                  c->p[1]))
GPGME_CALL(op_encrypt_sign_start,
           gpgme_op_encrypt_sign_start (c->ctx, c->keys, (int)c->u[0],
                                        c->p[0], c->p[1]))
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
GPGME_CALL(op_spawn,
           gpgme_op_spawn (c->ctx, c->str, c->strv, c->p[0], c->p[1],
                           c->p[2], (unsigned int)c->u[0]))
GPGME_CALL(op_spawn_start,
           gpgme_op_spawn_start (c->ctx, c->str, c->strv, c->p[0], c->p[1],
                                 c->p[2], (unsigned int)c->u[0]))
#endif
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
GPGME_CALL(op_random_bytes,
           gpgme_op_random_bytes (c->ctx, (int)c->u[0], c->p[0], c->u[1]))
GPGME_CALL(op_random_value,
           gpgme_op_random_value (c->ctx, c->u[0], &c->size))
#endif
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
GPGME_CALL(op_trustlist_start,
           gpgme_op_trustlist_start (c->ctx, c->str, (int)c->u[0]))
GPGME_CALL(op_trustlist_next, gpgme_op_trustlist_next (c->ctx, &c->item))
GPGME_CALL(op_trustlist_end, gpgme_op_trustlist_end (c->ctx))
#endif


static VALUE
rb_s_gpgme_op_keylist_start (VALUE dummy, VALUE vctx, VALUE vpattern,
                             VALUE vsecret_only)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_keylist_start, ctx);
  if (!NIL_P(vpattern))
    StringValueCStr(vpattern);
  c.u[0] = NUM2INT(vsecret_only);
  if (!NIL_P(vpattern))
    gpgme_call_str (&c, vpattern);
  err = gpgme_call_run (&c);
  if (gpgme_err_code (err) == GPG_ERR_NO_ERROR)
    SET_KEYLIST_IN_PROGRESS(vctx);
  return LONG2NUM(err);
}

// https://github.com/rwinlib/gpgme/blob/v1.16.0/include/gpgme.h#L2013-L2015
static VALUE
rb_s_gpgme_op_keylist_ext_start (VALUE dummy, VALUE vctx, VALUE vpattern,
                                 VALUE vsecret_only)
{
  gpgme_ctx_t ctx;
  VALUE vstrs = Qnil;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_keylist_ext_start, ctx);
  c.u[0] = NUM2INT(vsecret_only);
  if (!NIL_P(vpattern))
    {
      vstrs = string_array_new (vpattern);
      gpgme_call_strv (&c, vstrs);
    }

  err = gpgme_call_run (&c);
  if (gpgme_err_code (err) == GPG_ERR_NO_ERROR)
    SET_KEYLIST_IN_PROGRESS(vctx);
  RB_GC_GUARD(vstrs);
  return LONG2NUM(err);
}

static VALUE
utf8_str_new (const char *data)
{
    VALUE string = rb_str_new2 (data);
#ifdef HAVE_RUBY_ENCODING_H
    /* We assume all the C strings from GPGME are in UTF-8 encoding.
       If there is any string which cannot be represented in UTF-8,
       set the string's encoding to ASCII-8BIT and leave the caller to
       detect the encoding.  */
    rb_enc_associate_index (string, rb_enc_find_index ("UTF-8"));
    if (rb_enc_str_coderange (string) == ENC_CODERANGE_BROKEN)
      rb_enc_associate_index (string, rb_enc_find_index ("ASCII-8BIT"));
#endif
    return string;
}

static VALUE
save_gpgme_key_attrs (VALUE vkey, gpgme_key_t key)
{
  VALUE vsubkeys, vuids;
  gpgme_subkey_t subkey;
  gpgme_user_id_t user_id;

  rb_iv_set (vkey, "@keylist_mode", INT2FIX(key->keylist_mode));
  rb_iv_set (vkey, "@revoked", INT2FIX(key->revoked));
  rb_iv_set (vkey, "@expired", INT2FIX(key->expired));
  rb_iv_set (vkey, "@disabled", INT2FIX(key->disabled));
  rb_iv_set (vkey, "@invalid", INT2FIX(key->invalid));
  rb_iv_set (vkey, "@can_encrypt", INT2FIX(key->can_encrypt));
  rb_iv_set (vkey, "@can_sign", INT2FIX(key->can_sign));
  rb_iv_set (vkey, "@can_certify", INT2FIX(key->can_certify));
  rb_iv_set (vkey, "@can_authenticate", INT2FIX(key->can_authenticate));
  rb_iv_set (vkey, "@secret", INT2FIX(key->secret));
  rb_iv_set (vkey, "@protocol", INT2FIX(key->protocol));
  if (key->issuer_serial)
    rb_iv_set (vkey, "@issuer_serial", rb_str_new2 (key->issuer_serial));
  if (key->issuer_name)
    rb_iv_set (vkey, "@issuer_name", utf8_str_new (key->issuer_name));
  if (key->chain_id)
    rb_iv_set (vkey, "@chain_id", rb_str_new2 (key->chain_id));
  rb_iv_set (vkey, "@owner_trust", INT2FIX(key->owner_trust));
  vsubkeys = rb_ary_new ();
  rb_iv_set (vkey, "@subkeys", vsubkeys);
  for (subkey = key->subkeys; subkey; subkey = subkey->next)
    {
      VALUE vsubkey = rb_class_new_instance(0, NULL, cSubKey);
      rb_iv_set (vsubkey, "@revoked", INT2FIX(subkey->revoked));
      rb_iv_set (vsubkey, "@expired", INT2FIX(subkey->expired));
      rb_iv_set (vsubkey, "@disabled", INT2FIX(subkey->disabled));
      rb_iv_set (vsubkey, "@invalid", INT2FIX(subkey->invalid));
      rb_iv_set (vsubkey, "@can_encrypt", INT2FIX(subkey->can_encrypt));
      rb_iv_set (vsubkey, "@can_sign", INT2FIX(subkey->can_sign));
      rb_iv_set (vsubkey, "@can_certify", INT2FIX(subkey->can_certify));
      rb_iv_set (vsubkey, "@can_authenticate",
                 INT2FIX(subkey->can_authenticate));
      rb_iv_set (vsubkey, "@secret", INT2FIX(subkey->secret));
      rb_iv_set (vsubkey, "@pubkey_algo", INT2FIX(subkey->pubkey_algo));
      rb_iv_set (vsubkey, "@length", UINT2NUM(subkey->length));
      rb_iv_set (vsubkey, "@keyid", rb_str_new2 (subkey->keyid));
      if (subkey->fpr)
        rb_iv_set (vsubkey, "@fpr", rb_str_new2 (subkey->fpr));
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
      rb_iv_set (vsubkey, "@timestamp", ULONG2NUM(subkey->timestamp));
      rb_iv_set (vsubkey, "@expires", ULONG2NUM(subkey->expires));
#else
      rb_iv_set (vsubkey, "@timestamp", LONG2NUM(subkey->timestamp));
      rb_iv_set (vsubkey, "@expires", LONG2NUM(subkey->expires));
#endif
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
      if (subkey->curve)
        rb_iv_set (vsubkey, "@curve", rb_str_new2 (subkey->curve));
#endif
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
      rb_iv_set (vsubkey, "@subkey_match", INT2FIX(subkey->subkey_match));
#endif
      rb_ary_push (vsubkeys, vsubkey);
    }
  vuids = rb_ary_new ();
  rb_iv_set (vkey, "@uids", vuids);
  for (user_id = key->uids; user_id; user_id = user_id->next)
    {
      VALUE vuser_id, vsignatures;
      gpgme_key_sig_t key_sig;

      vuser_id = rb_class_new_instance(0, NULL, cUserID);
      rb_iv_set (vuser_id, "@revoked", INT2FIX(user_id->revoked));
      rb_iv_set (vuser_id, "@invalid", INT2FIX(user_id->invalid));
      rb_iv_set (vuser_id, "@validity", INT2FIX(user_id->validity));
      rb_iv_set (vuser_id, "@name", utf8_str_new (user_id->name));
      rb_iv_set (vuser_id, "@uid", utf8_str_new (user_id->uid));
      rb_iv_set (vuser_id, "@comment", utf8_str_new (user_id->comment));
      rb_iv_set (vuser_id, "@email", utf8_str_new (user_id->email));

      vsignatures = rb_ary_new ();
      rb_iv_set (vuser_id, "@signatures", vsignatures);
      for (key_sig = user_id->signatures; key_sig; key_sig = key_sig->next)
        {
          VALUE vkey_sig = rb_class_new_instance(0, NULL, cKeySig);
          rb_iv_set (vkey_sig, "@revoked", INT2FIX(key_sig->revoked));
          rb_iv_set (vkey_sig, "@expired", INT2FIX(key_sig->expired));
          rb_iv_set (vkey_sig, "@invalid", INT2FIX(key_sig->invalid));
          rb_iv_set (vkey_sig, "@exportable", INT2FIX(key_sig->exportable));
          rb_iv_set (vkey_sig, "@pubkey_algo", INT2FIX(key_sig->pubkey_algo));
          rb_iv_set (vkey_sig, "@keyid", rb_str_new2 (key_sig->keyid));
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
          rb_iv_set (vkey_sig, "@timestamp", ULONG2NUM(key_sig->timestamp));
          rb_iv_set (vkey_sig, "@expires", ULONG2NUM(key_sig->expires));
#else
          rb_iv_set (vkey_sig, "@timestamp", LONG2NUM(key_sig->timestamp));
          rb_iv_set (vkey_sig, "@expires", LONG2NUM(key_sig->expires));
#endif
          rb_ary_push (vsignatures, vkey_sig);
        }
      rb_ary_push (vuids, vuser_id);
    }
  return vkey;
}

static VALUE
rb_s_gpgme_op_keylist_next (VALUE dummy, VALUE vctx, VALUE rkey)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_keylist_next, ctx);
  err = gpgme_call_run (&c);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      VALUE vkey = WRAP_GPGME_KEY(c.key);
      save_gpgme_key_attrs (vkey, c.key);
      rb_ary_store (rkey, 0, vkey);
    }

  RB_GC_GUARD(vctx);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_keylist_end (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_keylist_end, ctx);
  err = gpgme_call_run (&c);
  RESET_KEYLIST_IN_PROGRESS(vctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_key (VALUE dummy, VALUE vctx, VALUE vfpr, VALUE rkey,
                    VALUE vsecret)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_call_init (&c, call_get_key, ctx);
  StringValueCStr(vfpr);
  c.u[0] = NUM2INT(vsecret);
  gpgme_call_str (&c, vfpr);
  err = gpgme_call_run (&c);

  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      VALUE vkey = WRAP_GPGME_KEY(c.key);
      save_gpgme_key_attrs (vkey, c.key);
      rb_ary_store (rkey, 0, vkey);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_genkey (VALUE dummy, VALUE vctx, VALUE vparms, VALUE vpubkey,
                      VALUE vseckey)
{
  gpgme_ctx_t ctx;
  gpgme_data_t pubkey = NULL, seckey = NULL;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  if (!NIL_P(vpubkey))
    UNWRAP_GPGME_DATA(vpubkey, pubkey);
  if (!NIL_P(vseckey))
    UNWRAP_GPGME_DATA(vseckey, seckey);

  gpgme_call_init (&c, call_op_genkey, ctx);
  StringValueCStr(vparms);
  c.p[0] = pubkey;
  c.p[1] = seckey;
  gpgme_call_use (&c, pubkey);
  gpgme_call_use (&c, seckey);
  gpgme_call_str (&c, vparms);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vpubkey);
  RB_GC_GUARD(vseckey);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_genkey_start (VALUE dummy, VALUE vctx, VALUE vparms,
                            VALUE vpubkey, VALUE vseckey)
{
  gpgme_ctx_t ctx;
  gpgme_data_t pubkey = NULL, seckey = NULL;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  if (!NIL_P(vpubkey))
    UNWRAP_GPGME_DATA(vpubkey, pubkey);
  if (!NIL_P(vseckey))
    UNWRAP_GPGME_DATA(vseckey, seckey);

  gpgme_call_init (&c, call_op_genkey_start, ctx);
  StringValueCStr(vparms);
  c.p[0] = pubkey;
  c.p[1] = seckey;
  gpgme_call_use (&c, pubkey);
  gpgme_call_use (&c, seckey);
  c.op_args = rb_ary_new_from_args (2, vpubkey, vseckey);
  gpgme_call_str (&c, vparms);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vpubkey);
  RB_GC_GUARD(vseckey);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export (VALUE dummy, VALUE vctx, VALUE vpattern, VALUE vmode,
                      VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  gpgme_call_init (&c, call_op_export, ctx);
  StringValueCStr(vpattern);
  c.u[0] = NUM2UINT(vmode);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  gpgme_call_str (&c, vpattern);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vkeydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_start (VALUE dummy, VALUE vctx, VALUE vpattern,
                            VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  gpgme_call_init (&c, call_op_export_start, ctx);
  StringValueCStr(vpattern);
  c.u[0] = NUM2UINT(vmode);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  c.op_args = rb_ary_new_from_args (1, vkeydata);
  gpgme_call_str (&c, vpattern);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_ext (VALUE dummy, VALUE vctx, VALUE vpattern, VALUE vmode,
                          VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  VALUE vstrs;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);
  gpgme_call_init (&c, call_op_export_ext, ctx);
  c.u[0] = NUM2UINT(vmode);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  vstrs = string_array_new (vpattern);
  gpgme_call_strv (&c, vstrs);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(vstrs);
  RB_GC_GUARD(vkeydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_ext_start (VALUE dummy, VALUE vctx, VALUE vpattern,
                            VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  VALUE vstrs;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);
  gpgme_call_init (&c, call_op_export_ext_start, ctx);
  c.u[0] = NUM2UINT(vmode);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  c.op_args = rb_ary_new_from_args (1, vkeydata);
  vstrs = string_array_new (vpattern);
  gpgme_call_strv (&c, vstrs);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(vstrs);
  RB_GC_GUARD(vkeydata);
  return LONG2NUM(err);
}

#ifdef HAVE_GPGME_OP_EXPORT_KEYS
static VALUE
rb_s_gpgme_op_export_keys (VALUE dummy, VALUE vctx, VALUE vkeys,
                           VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  UNWRAP_GPGME_DATA(vkeydata, keydata);

  gpgme_call_init (&c, call_op_export_keys, ctx);
  c.u[0] = NUM2UINT(vmode);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  gpgme_call_keys (&c, vkeys);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(vkeydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_keys_start (VALUE dummy, VALUE vctx, VALUE vkeys,
                                 VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  UNWRAP_GPGME_DATA(vkeydata, keydata);

  gpgme_call_init (&c, call_op_export_keys_start, ctx);
  c.u[0] = NUM2UINT(vmode);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  c.op_args = rb_ary_new_from_args (1, vkeydata);
  gpgme_call_keys (&c, vkeys);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(vkeydata);
  return LONG2NUM(err);
}
#endif        /*HAVE_GPGME_OP_EXPORT_KEYS*/

static VALUE
rb_s_gpgme_op_import (VALUE dummy, VALUE vctx, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  gpgme_call_init (&c, call_op_import, ctx);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vkeydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_import_start (VALUE dummy, VALUE vctx, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  gpgme_call_init (&c, call_op_import_start, ctx);
  c.p[0] = keydata;
  gpgme_call_use (&c, keydata);
  c.op_args = rb_ary_new_from_args (1, vkeydata);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

#ifdef HAVE_GPGME_OP_EXPORT_KEYS
static VALUE
rb_s_gpgme_op_import_keys (VALUE dummy, VALUE vctx, VALUE vkeys)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_import_keys, ctx);
  gpgme_call_keys (&c, vkeys);

  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_import_keys_start (VALUE dummy, VALUE vctx, VALUE vkeys)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_import_keys_start, ctx);
  gpgme_call_keys (&c, vkeys);

  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}
#endif        /*HAVE_GPGME_OP_EXPORT_KEYS*/

static VALUE
rb_s_gpgme_op_import_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_import_result_t result;
  gpgme_import_status_t status;
  VALUE vresult, vimports;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_import_result (ctx);
  if (!result)
    rb_raise (rb_eArgError, "no result");

  vresult = rb_class_new_instance (0, NULL, cImportResult);
  rb_iv_set (vresult, "@considered", INT2NUM(result->considered));
  rb_iv_set (vresult, "@no_user_id", INT2NUM(result->no_user_id));
  rb_iv_set (vresult, "@imported", INT2NUM(result->imported));
  rb_iv_set (vresult, "@imported_rsa", INT2NUM(result->imported_rsa));
  rb_iv_set (vresult, "@unchanged", INT2NUM(result->unchanged));
  rb_iv_set (vresult, "@new_user_ids", INT2NUM(result->new_user_ids));
  rb_iv_set (vresult, "@new_sub_keys", INT2NUM(result->new_sub_keys));
  rb_iv_set (vresult, "@new_signatures", INT2NUM(result->new_signatures));
  rb_iv_set (vresult, "@new_revocations", INT2NUM(result->new_revocations));
  rb_iv_set (vresult, "@secret_read", INT2NUM(result->secret_read));
  rb_iv_set (vresult, "@secret_imported", INT2NUM(result->secret_imported));
  rb_iv_set (vresult, "@secret_unchanged", INT2NUM(result->secret_unchanged));
  rb_iv_set (vresult, "@not_imported", INT2NUM(result->not_imported));
  vimports = rb_ary_new ();
  rb_iv_set (vresult, "@imports", vimports);
  for (status = result->imports; status;
       status = status->next)
    {
      VALUE vstatus =
        rb_class_new_instance (0, NULL, cImportStatus);
      rb_iv_set (vstatus, "@fpr", rb_str_new2 (status->fpr));
      rb_iv_set (vstatus, "@result", LONG2NUM(status->result));
      rb_iv_set (vstatus, "@status", UINT2NUM(status->status));
      rb_ary_push (vimports, vstatus);
    }
  return vresult;
}

static VALUE
rb_s_gpgme_op_delete (VALUE dummy, VALUE vctx, VALUE vkey, VALUE vallow_secret)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);

  gpgme_call_init (&c, call_op_delete, ctx);
  c.u[0] = NUM2INT(vallow_secret);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

/* This method was added in 1.9.1. */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010901
static VALUE
rb_s_gpgme_op_delete_ext (VALUE dummy, VALUE vctx, VALUE vkey, VALUE vflags)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);

  gpgme_call_init (&c, call_op_delete_ext, ctx);
  c.u[0] = NUM2INT(vflags);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}
#endif

static VALUE
rb_s_gpgme_op_delete_start (VALUE dummy, VALUE vctx, VALUE vkey,
                            VALUE vallow_secret)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);

  gpgme_call_init (&c, call_op_delete_start, ctx);
  c.u[0] = NUM2INT(vallow_secret);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

/*
 * Key Edit Interface
 *
 * GPGME 2.0.0 deprecated gpgme_op_edit, gpgme_op_edit_start, gpgme_op_card_edit,
 * and gpgme_op_card_edit_start in favor of gpgme_op_interact and gpgme_op_interact_start.
 *
 * The new interact callback has a different signature:
 *   Old: gpgme_error_t (*)(void *opaque, gpgme_status_code_t status, const char *args, int fd)
 *   New: gpgme_error_t (*)(void *opaque, const char *keyword, const char *args, int fd)
 *
 * For backward compatibility, we keep the same Ruby interface (gpgme_op_edit, etc.)
 * but internally use gpgme_op_interact for GPGME 2.0.0+, converting keyword strings
 * to status codes in the callback shim.
 */

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
/*
 * GPGME 2.0.0+: Use gpgme_op_interact internally, but expose the same
 * gpgme_op_edit interface to Ruby for backward compatibility.
 *
 * The shim callback converts keyword strings to status codes.
 */

/* Macro to define keyword-to-status mapping entries */
#define STATUS_ENTRY(x) { #x, GPGME_STATUS_##x }

/* Mapping table from keyword strings to status codes */
static struct {
  const char *keyword;
  gpgme_status_code_t status;
} keyword_to_status[] = {
  STATUS_ENTRY(EOF),
  STATUS_ENTRY(ENTER),
  STATUS_ENTRY(LEAVE),
  STATUS_ENTRY(ABORT),
  STATUS_ENTRY(GOODSIG),
  STATUS_ENTRY(BADSIG),
  STATUS_ENTRY(ERRSIG),
  STATUS_ENTRY(BADARMOR),
  STATUS_ENTRY(RSA_OR_IDEA),
  STATUS_ENTRY(KEYEXPIRED),
  STATUS_ENTRY(KEYREVOKED),
  STATUS_ENTRY(TRUST_UNDEFINED),
  STATUS_ENTRY(TRUST_NEVER),
  STATUS_ENTRY(TRUST_MARGINAL),
  STATUS_ENTRY(TRUST_FULLY),
  STATUS_ENTRY(TRUST_ULTIMATE),
  STATUS_ENTRY(SHM_INFO),
  STATUS_ENTRY(SHM_GET),
  STATUS_ENTRY(SHM_GET_BOOL),
  STATUS_ENTRY(SHM_GET_HIDDEN),
  STATUS_ENTRY(NEED_PASSPHRASE),
  STATUS_ENTRY(VALIDSIG),
  STATUS_ENTRY(SIG_ID),
  STATUS_ENTRY(ENC_TO),
  STATUS_ENTRY(NODATA),
  STATUS_ENTRY(BAD_PASSPHRASE),
  STATUS_ENTRY(NO_PUBKEY),
  STATUS_ENTRY(NO_SECKEY),
  STATUS_ENTRY(NEED_PASSPHRASE_SYM),
  STATUS_ENTRY(DECRYPTION_FAILED),
  STATUS_ENTRY(DECRYPTION_OKAY),
  STATUS_ENTRY(MISSING_PASSPHRASE),
  STATUS_ENTRY(GOOD_PASSPHRASE),
  STATUS_ENTRY(GOODMDC),
  STATUS_ENTRY(BADMDC),
  STATUS_ENTRY(ERRMDC),
  STATUS_ENTRY(IMPORTED),
  STATUS_ENTRY(IMPORT_OK),
  STATUS_ENTRY(IMPORT_PROBLEM),
  STATUS_ENTRY(IMPORT_RES),
  STATUS_ENTRY(FILE_START),
  STATUS_ENTRY(FILE_DONE),
  STATUS_ENTRY(FILE_ERROR),
  STATUS_ENTRY(BEGIN_DECRYPTION),
  STATUS_ENTRY(END_DECRYPTION),
  STATUS_ENTRY(BEGIN_ENCRYPTION),
  STATUS_ENTRY(END_ENCRYPTION),
  STATUS_ENTRY(DELETE_PROBLEM),
  STATUS_ENTRY(GET_BOOL),
  STATUS_ENTRY(GET_LINE),
  STATUS_ENTRY(GET_HIDDEN),
  STATUS_ENTRY(GOT_IT),
  STATUS_ENTRY(PROGRESS),
  STATUS_ENTRY(SIG_CREATED),
  STATUS_ENTRY(SESSION_KEY),
  STATUS_ENTRY(NOTATION_NAME),
  STATUS_ENTRY(NOTATION_DATA),
  STATUS_ENTRY(POLICY_URL),
  STATUS_ENTRY(BEGIN_STREAM),
  STATUS_ENTRY(END_STREAM),
  STATUS_ENTRY(KEY_CREATED),
  STATUS_ENTRY(USERID_HINT),
  STATUS_ENTRY(UNEXPECTED),
  STATUS_ENTRY(INV_RECP),
  STATUS_ENTRY(NO_RECP),
  STATUS_ENTRY(ALREADY_SIGNED),
  STATUS_ENTRY(SIGEXPIRED),
  STATUS_ENTRY(EXPSIG),
  STATUS_ENTRY(EXPKEYSIG),
  STATUS_ENTRY(TRUNCATED),
  STATUS_ENTRY(ERROR),
  STATUS_ENTRY(NEWSIG),
  STATUS_ENTRY(REVKEYSIG),
  STATUS_ENTRY(SIG_SUBPACKET),
  STATUS_ENTRY(NEED_PASSPHRASE_PIN),
  STATUS_ENTRY(SC_OP_FAILURE),
  STATUS_ENTRY(SC_OP_SUCCESS),
  STATUS_ENTRY(CARDCTRL),
  STATUS_ENTRY(BACKUP_KEY_CREATED),
  STATUS_ENTRY(PKA_TRUST_BAD),
  STATUS_ENTRY(PKA_TRUST_GOOD),
  STATUS_ENTRY(PLAINTEXT),
  STATUS_ENTRY(INV_SGNR),
  STATUS_ENTRY(NO_SGNR),
  STATUS_ENTRY(SUCCESS),
  STATUS_ENTRY(DECRYPTION_INFO),
  STATUS_ENTRY(PLAINTEXT_LENGTH),
  STATUS_ENTRY(MOUNTPOINT),
  STATUS_ENTRY(PINENTRY_LAUNCHED),
  STATUS_ENTRY(ATTRIBUTE),
  STATUS_ENTRY(BEGIN_SIGNING),
  STATUS_ENTRY(KEY_NOT_CREATED),
  STATUS_ENTRY(INQUIRE_MAXLEN),
  STATUS_ENTRY(FAILURE),
  STATUS_ENTRY(KEY_CONSIDERED),
  STATUS_ENTRY(TOFU_USER),
  STATUS_ENTRY(TOFU_STATS),
  STATUS_ENTRY(TOFU_STATS_LONG),
  STATUS_ENTRY(NOTATION_FLAGS),
  STATUS_ENTRY(DECRYPTION_COMPLIANCE_MODE),
  STATUS_ENTRY(VERIFICATION_COMPLIANCE_MODE),
  STATUS_ENTRY(CANCELED_BY_USER),
  { NULL, GPGME_STATUS_EOF }
};

#undef STATUS_ENTRY

static gpgme_status_code_t
keyword_to_status_code (const char *keyword)
{
  size_t i;

  if (!keyword)
    return GPGME_STATUS_EOF;

  for (i = 0; keyword_to_status[i].keyword != NULL; i++)
    {
      if (strcmp (keyword, keyword_to_status[i].keyword) == 0)
        return keyword_to_status[i].status;
    }

  /* Unknown keyword - return EOF as fallback */
  return GPGME_STATUS_EOF;
}

/*
 * Shim callback that converts keyword strings to status codes
 * for backward compatibility with existing Ruby callbacks.
 */
static VALUE
edit_cb_ruby (VALUE arg)
{
  struct ctx_cb_args *a = (struct ctx_cb_args *)arg;
  VALUE veditfunc, vhook_value;

  veditfunc = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  rb_funcall (veditfunc, rb_intern ("call"), 4, vhook_value, INT2FIX(a->i1),
              rb_str_new2 (a->s1 ? a->s1 : ""), INT2NUM(a->i2));
  return Qnil;
}

static gpgme_error_t
edit_cb_shim (void *hook, const char *keyword, const char *args, int fd)
{
  struct ctx_cb_args a = { (VALUE)hook, args, NULL,
                           keyword_to_status_code (keyword), fd, 0 };

  if (callback_run (edit_cb_ruby, &a) < 0)
    return CALLBACK_FAILED;
  return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR);
}

GPGME_CALL(op_interact,
           gpgme_op_interact (c->ctx, c->key_in, (unsigned int)c->u[0],
                              edit_cb_shim, c->p[1], c->p[0]))
GPGME_CALL(op_interact_start,
           gpgme_op_interact_start (c->ctx, c->key_in, (unsigned int)c->u[0],
                                    edit_cb_shim, c->p[1], c->p[0]))

static VALUE
rb_s_gpgme_op_edit (VALUE dummy, VALUE vctx, VALUE vkey,
                    VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS (vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@edit_cb", vcb);

  /* Pin the callback array, whose address libgpgme gets. */
  owner_ref_set (ctx, CTX_REF_EDIT_CB, vcb);
  /* gpgme_op_interact with the shim, which converts keywords to status
     codes. */
  gpgme_call_init (&c, call_op_interact, ctx);
  c.u[0] = 0;
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vcb);
  RB_GC_GUARD(vout);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_edit_start (VALUE dummy, VALUE vctx, VALUE vkey,
                          VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@edit_cb", vcb);

  /* gpgme_op_interact_start with the shim, which converts keywords to
     status codes. */
  gpgme_call_init (&c, call_op_interact_start, ctx);
  c.u[0] = 0;
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  c.op_args = rb_ary_new_from_args (1, vout);
  c.edit_cb = vcb;
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_card_edit (VALUE dummy, VALUE vctx, VALUE vkey,
                    VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@card_edit_cb", vcb);

  /* Pin the callback array, whose address libgpgme gets. */
  owner_ref_set (ctx, CTX_REF_EDIT_CB, vcb);
  /* gpgme_op_interact with the shim, which converts keywords to status
     codes. */
  gpgme_call_init (&c, call_op_interact, ctx);
  c.u[0] = GPGME_INTERACT_CARD;
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vcb);
  RB_GC_GUARD(vout);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_card_edit_start (VALUE dummy, VALUE vctx, VALUE vkey,
                               VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@card_edit_cb", vcb);

  /* gpgme_op_interact_start with the shim, which converts keywords to
     status codes. */
  gpgme_call_init (&c, call_op_interact_start, ctx);
  c.u[0] = GPGME_INTERACT_CARD;
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  c.op_args = rb_ary_new_from_args (1, vout);
  c.edit_cb = vcb;
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

#else
/* GPGME < 2.0.0: Use the original gpgme_op_edit functions directly */

static VALUE
edit_cb_ruby (VALUE arg)
{
  struct ctx_cb_args *a = (struct ctx_cb_args *)arg;
  VALUE veditfunc, vhook_value;

  veditfunc = RARRAY_AREF(a->vcb, 0);
  vhook_value = RARRAY_AREF(a->vcb, 1);

  rb_funcall (veditfunc, rb_intern ("call"), 4, vhook_value, INT2FIX(a->i1),
              rb_str_new2 (a->s1), INT2NUM(a->i2));
  return Qnil;
}

static gpgme_error_t
edit_cb (void *hook, gpgme_status_code_t status, const char *args, int fd)
{
  struct ctx_cb_args a = { (VALUE)hook, args, NULL, status, fd, 0 };

  if (callback_run (edit_cb_ruby, &a) < 0)
    return CALLBACK_FAILED;
  return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR);
}

GPGME_CALL(op_edit,
           gpgme_op_edit (c->ctx, c->key_in, edit_cb, c->p[1], c->p[0]))
GPGME_CALL(op_edit_start,
           gpgme_op_edit_start (c->ctx, c->key_in, edit_cb, c->p[1], c->p[0]))
GPGME_CALL(op_card_edit,
           gpgme_op_card_edit (c->ctx, c->key_in, edit_cb, c->p[1], c->p[0]))
GPGME_CALL(op_card_edit_start,
           gpgme_op_card_edit_start (c->ctx, c->key_in, edit_cb, c->p[1],
                                     c->p[0]))

static VALUE
rb_s_gpgme_op_edit (VALUE dummy, VALUE vctx, VALUE vkey,
                    VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@edit_cb", vcb);

  /* Pin the callback array, whose address libgpgme gets. */
  owner_ref_set (ctx, CTX_REF_EDIT_CB, vcb);
  gpgme_call_init (&c, call_op_edit, ctx);
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vcb);
  RB_GC_GUARD(vout);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_edit_start (VALUE dummy, VALUE vctx, VALUE vkey,
                          VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@edit_cb", vcb);

  gpgme_call_init (&c, call_op_edit_start, ctx);
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  c.op_args = rb_ary_new_from_args (1, vout);
  c.edit_cb = vcb;
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_card_edit (VALUE dummy, VALUE vctx, VALUE vkey,
                    VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@card_edit_cb", vcb);

  /* Pin the callback array, whose address libgpgme gets. */
  owner_ref_set (ctx, CTX_REF_EDIT_CB, vcb);
  gpgme_call_init (&c, call_op_card_edit, ctx);
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  RB_GC_GUARD(vcb);
  RB_GC_GUARD(vout);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_card_edit_start (VALUE dummy, VALUE vctx, VALUE vkey,
                               VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  rb_check_typeddata (vkey, &gpgme_key_type);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@card_edit_cb", vcb);

  gpgme_call_init (&c, call_op_card_edit_start, ctx);
  c.p[0] = out;
  c.p[1] = (void *)vcb;
  gpgme_call_use (&c, out);
  c.op_args = rb_ary_new_from_args (1, vout);
  c.edit_cb = vcb;
  gpgme_call_key (&c, vkey);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}
#endif /* GPGME_VERSION_NUMBER >= 0x020000 */

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
static VALUE
rb_s_gpgme_op_trustlist_start (VALUE dummy, VALUE vctx, VALUE vpattern,
                               VALUE vmax_level)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_call_init (&c, call_op_trustlist_start, ctx);
  StringValueCStr(vpattern);
  c.u[0] = NUM2INT(vmax_level);
  gpgme_call_str (&c, vpattern);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_trustlist_next (VALUE dummy, VALUE vctx, VALUE ritem)
{
  gpgme_ctx_t ctx;
  gpgme_trust_item_t item;
  gpgme_error_t err;
  VALUE vitem;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_trustlist_next, ctx);
  err = gpgme_call_run (&c);
  item = c.item;
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      vitem = WRAP_GPGME_TRUST_ITEM(item);
      rb_iv_set (vitem, "@keyid", rb_str_new2 (item->keyid));
      rb_iv_set (vitem, "@type", INT2FIX(item->type));
      rb_iv_set (vitem, "@level", INT2FIX(item->level));
      if (item->owner_trust)
        rb_iv_set (vitem, "@owner_trust", rb_str_new2 (item->owner_trust));
      rb_iv_set (vitem, "@validity", rb_str_new2 (item->validity));
      if (item->name)
        rb_iv_set (vitem, "@name", rb_str_new2 (item->name));
      rb_ary_store (ritem, 0, vitem);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_trustlist_end (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_trustlist_end, ctx);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}
#endif

static VALUE
rb_s_gpgme_op_decrypt (VALUE dummy, VALUE vctx, VALUE vcipher, VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  gpgme_call_init (&c, call_op_decrypt, ctx);
  c.p[0] = cipher;
  c.p[1] = plain;
  gpgme_call_use (&c, cipher);
  gpgme_call_use (&c, plain);
  err = gpgme_call_run (&c);

  RB_GC_GUARD(vctx);
  RB_GC_GUARD(vcipher);
  RB_GC_GUARD(vplain);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt_start (VALUE dummy, VALUE vctx, VALUE vcipher,
                             VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  gpgme_call_init (&c, call_op_decrypt_start, ctx);
  c.p[0] = cipher;
  c.p[1] = plain;
  gpgme_call_use (&c, cipher);
  gpgme_call_use (&c, plain);
  c.op_args = rb_ary_new_from_args (2, vcipher, vplain);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_decrypt_result_t result;
  gpgme_recipient_t recipient;
  VALUE vresult, vrecipients;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_decrypt_result (ctx);
  if (!result)
    rb_raise (rb_eArgError, "no result");

  vresult = rb_class_new_instance (0, NULL, cDecryptResult);
  if (result->unsupported_algorithm)
    rb_iv_set (vresult, "@unsupported_algorithm",
               rb_str_new2 (result->unsupported_algorithm));
  rb_iv_set (vresult, "@wrong_key_usage", INT2FIX(result->wrong_key_usage));
  vrecipients = rb_ary_new ();
  rb_iv_set (vresult, "@recipients", vrecipients);
  for (recipient = result->recipients; recipient; recipient = recipient->next)
    {
      VALUE vrecipient = rb_class_new_instance (0, NULL, cRecipient);
      rb_iv_set (vrecipient, "@pubkey_algo", INT2FIX(recipient->pubkey_algo));
      rb_iv_set (vrecipient, "@keyid", rb_str_new2 (recipient->keyid));
      rb_iv_set (vrecipient, "@status", UINT2NUM(recipient->status));
      rb_ary_push (vrecipients, vrecipient);
    }
  if (result->file_name)
    rb_iv_set (vresult, "@file_name", rb_str_new2 (result->file_name));
  return vresult;
}

static VALUE
rb_s_gpgme_op_verify (VALUE dummy, VALUE vctx, VALUE vsig, VALUE vsigned_text,
                      VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t sig, signed_text = NULL, plain = NULL;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vsig, sig);
  if (!NIL_P(vsigned_text))
    UNWRAP_GPGME_DATA(vsigned_text, signed_text);
  if (!NIL_P(vplain))
    UNWRAP_GPGME_DATA(vplain, plain);

  gpgme_call_init (&c, call_op_verify, ctx);
  c.p[0] = sig;
  c.p[1] = signed_text;
  c.p[2] = plain;
  gpgme_call_use (&c, sig);
  gpgme_call_use (&c, signed_text);
  gpgme_call_use (&c, plain);
  err = gpgme_call_run (&c);

  RB_GC_GUARD(vctx);
  RB_GC_GUARD(vsig);
  RB_GC_GUARD(vsigned_text);
  RB_GC_GUARD(vplain);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_verify_start (VALUE dummy, VALUE vctx, VALUE vsig,
                            VALUE vsigned_text, VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t sig, signed_text = NULL, plain = NULL;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vsig, sig);
  if (!NIL_P(vsigned_text))
    UNWRAP_GPGME_DATA(vsigned_text, signed_text);
  if (!NIL_P(vplain))
    UNWRAP_GPGME_DATA(vplain, plain);

  gpgme_call_init (&c, call_op_verify_start, ctx);
  c.p[0] = sig;
  c.p[1] = signed_text;
  c.p[2] = plain;
  gpgme_call_use (&c, sig);
  gpgme_call_use (&c, signed_text);
  gpgme_call_use (&c, plain);
  c.op_args = rb_ary_new_from_args (3, vsig, vsigned_text, vplain);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_verify_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_verify_result_t verify_result;
  gpgme_signature_t signature;
  VALUE vverify_result, vsignatures = rb_ary_new ();

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  verify_result = gpgme_op_verify_result (ctx);
  if (!verify_result)
    rb_raise (rb_eArgError, "no result");

  vverify_result = rb_class_new_instance(0, NULL, cVerifyResult);
  rb_iv_set (vverify_result, "@signatures", vsignatures);
  for (signature = verify_result->signatures; signature;
       signature = signature->next)
    {
      VALUE vsignature = rb_class_new_instance(0, NULL, cSignature),
        vnotations = rb_ary_new ();
      gpgme_sig_notation_t notation;
      rb_iv_set (vsignature, "@summary", INT2FIX(signature->summary));
      rb_iv_set (vsignature, "@fpr", rb_str_new2 (signature->fpr));
      rb_iv_set (vsignature, "@status", LONG2NUM(signature->status));
      rb_iv_set (vsignature, "@notations", vnotations);
      for (notation = signature->notations; notation;
           notation = notation->next)
        {
          VALUE vnotation = rb_class_new_instance(0, NULL, cSigNotation);
          /* The docs say:
           * The name of the notation field. If this is NULL, then the member
           * value will contain a policy URL. */
          if (notation->name == NULL)
            rb_iv_set (vnotation, "@name", Qnil);
          else
            rb_iv_set (vnotation, "@name", rb_str_new2 (notation->name));
          rb_iv_set (vnotation, "@value", rb_str_new2 (notation->value));
          rb_ary_push (vnotations, vnotation);
        }
      rb_iv_set (vsignature, "@timestamp", ULONG2NUM(signature->timestamp));
      rb_iv_set (vsignature, "@exp_timestamp",
                 ULONG2NUM(signature->exp_timestamp));
      rb_iv_set (vsignature, "@wrong_key_usage",
                 INT2FIX(signature->wrong_key_usage));
      rb_iv_set (vsignature, "@validity", INT2FIX(signature->validity));
      rb_iv_set (vsignature, "@validity_reason",
                 LONG2NUM(signature->validity_reason));
      /* PKA related fields were added in 1.1.1. */
#ifdef GPGME_STATUS_PKA_TRUST_BAD
      rb_iv_set (vsignature, "@pka_trust", INT2FIX(signature->pka_trust));
      rb_iv_set (vsignature, "@pka_address",
                 rb_str_new2 (signature->pka_address));
#endif
      rb_ary_push (vsignatures, vsignature);
    }
  return vverify_result;
}

static VALUE
rb_s_gpgme_op_decrypt_verify (VALUE dummy, VALUE vctx, VALUE vcipher,
                              VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  gpgme_call_init (&c, call_op_decrypt_verify, ctx);
  c.p[0] = cipher;
  c.p[1] = plain;
  gpgme_call_use (&c, cipher);
  gpgme_call_use (&c, plain);
  err = gpgme_call_run (&c);

  RB_GC_GUARD(vctx);
  RB_GC_GUARD(vcipher);
  RB_GC_GUARD(vplain);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt_verify_start (VALUE dummy, VALUE vctx, VALUE vcipher,
                                    VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  gpgme_call_init (&c, call_op_decrypt_verify_start, ctx);
  c.p[0] = cipher;
  c.p[1] = plain;
  gpgme_call_use (&c, cipher);
  gpgme_call_use (&c, plain);
  c.op_args = rb_ary_new_from_args (2, vcipher, vplain);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_signers_clear (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_signers_clear (ctx);
  return Qnil;
}

static VALUE
rb_s_gpgme_signers_add (VALUE dummy, VALUE vctx, VALUE vkey)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);

  err = gpgme_signers_add (ctx, key);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_signers_enum (VALUE dummy, VALUE vctx, VALUE vseq)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  key = gpgme_signers_enum (ctx, NUM2INT(vseq));
  if (!key)
    return Qnil;
  return WRAP_GPGME_KEY(key);
}

static VALUE
rb_s_gpgme_op_sign (VALUE dummy, VALUE vctx, VALUE vplain, VALUE vsig,
                    VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, sig;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vsig, sig);

  gpgme_call_init (&c, call_op_sign, ctx);
  c.u[0] = NUM2INT(vmode);
  c.p[0] = plain;
  c.p[1] = sig;
  gpgme_call_use (&c, plain);
  gpgme_call_use (&c, sig);
  err = gpgme_call_run (&c);

  RB_GC_GUARD(vctx);
  RB_GC_GUARD(vplain);
  RB_GC_GUARD(vsig);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_sign_start (VALUE dummy, VALUE vctx, VALUE vplain, VALUE vsig,
                          VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, sig;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vsig, sig);

  gpgme_call_init (&c, call_op_sign_start, ctx);
  c.u[0] = NUM2INT(vmode);
  c.p[0] = plain;
  c.p[1] = sig;
  gpgme_call_use (&c, plain);
  gpgme_call_use (&c, sig);
  c.op_args = rb_ary_new_from_args (2, vplain, vsig);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_sign_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_sign_result_t result;
  gpgme_invalid_key_t invalid_key;
  gpgme_new_signature_t new_signature;
  VALUE vresult, vinvalid_signers, vsignatures;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_sign_result (ctx);
  if (!result)
    rb_raise (rb_eArgError, "no result");

  vresult = rb_class_new_instance (0, NULL, cSignResult);
  vinvalid_signers = rb_ary_new ();
  rb_iv_set (vresult, "@invalid_signers", vinvalid_signers);
  for (invalid_key = result->invalid_signers; invalid_key;
       invalid_key = invalid_key->next)
    {
      VALUE vinvalid_key =
        rb_class_new_instance (0, NULL, cInvalidKey);
      rb_iv_set (vinvalid_key, "@fpr", rb_str_new2 (invalid_key->fpr));
      rb_iv_set (vinvalid_key, "@reason", LONG2NUM(invalid_key->reason));
      rb_ary_push (vinvalid_signers, vinvalid_key);
    }
  vsignatures = rb_ary_new ();
  rb_iv_set (vresult, "@signatures", vsignatures);
  for (new_signature = result->signatures; new_signature;
       new_signature = new_signature->next)
    {
      VALUE vnew_signature =
        rb_class_new_instance (0, NULL, cNewSignature);
      rb_iv_set (vnew_signature, "@type", INT2FIX(new_signature->type));
      rb_iv_set (vnew_signature, "@pubkey_algo",
                 INT2FIX(new_signature->pubkey_algo));
      rb_iv_set (vnew_signature, "@hash_algo",
                 INT2FIX(new_signature->hash_algo));
      rb_iv_set (vnew_signature, "@sig_class",
                 UINT2NUM(new_signature->sig_class));
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
      rb_iv_set (vnew_signature, "@timestamp",
                 ULONG2NUM(new_signature->timestamp));
#else
      rb_iv_set (vnew_signature, "@timestamp",
                 LONG2NUM(new_signature->timestamp));
#endif
      rb_iv_set (vnew_signature, "@fpr", rb_str_new2 (new_signature->fpr));
      rb_ary_push (vsignatures, vnew_signature);
    }
  return vresult;
}

static VALUE
rb_s_gpgme_op_encrypt (VALUE dummy, VALUE vctx, VALUE vrecp, VALUE vflags,
                       VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  gpgme_call_init (&c, call_op_encrypt, ctx);
  c.u[0] = NUM2INT(vflags);
  c.p[0] = plain;
  c.p[1] = cipher;
  gpgme_call_use (&c, plain);
  gpgme_call_use (&c, cipher);
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    gpgme_call_keys (&c, vrecp);
  err = gpgme_call_run (&c);

  RB_GC_GUARD(vctx);
  RB_GC_GUARD(vrecp);
  RB_GC_GUARD(vplain);
  RB_GC_GUARD(vcipher);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_encrypt_start (VALUE dummy, VALUE vctx, VALUE vrecp,
                             VALUE vflags, VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  gpgme_call_init (&c, call_op_encrypt_start, ctx);
  c.u[0] = NUM2INT(vflags);
  c.p[0] = plain;
  c.p[1] = cipher;
  gpgme_call_use (&c, plain);
  gpgme_call_use (&c, cipher);
  c.op_args = rb_ary_new_from_args (2, vplain, vcipher);
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    gpgme_call_keys (&c, vrecp);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_encrypt_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_encrypt_result_t result;
  gpgme_invalid_key_t invalid_key;
  VALUE vresult, vinvalid_recipients;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_encrypt_result (ctx);
  if (!result)
    rb_raise (rb_eArgError, "no result");

  vresult = rb_class_new_instance (0, NULL, cEncryptResult);
  vinvalid_recipients = rb_ary_new ();
  rb_iv_set (vresult, "@invalid_recipients", vinvalid_recipients);
  for (invalid_key = result->invalid_recipients; invalid_key;
       invalid_key = invalid_key->next)
    {
      VALUE vinvalid_key =
        rb_class_new_instance (0, NULL, cInvalidKey);
      rb_iv_set (vinvalid_key, "@fpr", rb_str_new2 (invalid_key->fpr));
      rb_iv_set (vinvalid_key, "@reason", LONG2NUM(invalid_key->reason));
      rb_ary_push (vinvalid_recipients, vinvalid_key);
    }
  return vresult;
}

static VALUE
rb_s_gpgme_op_encrypt_sign (VALUE dummy, VALUE vctx, VALUE vrecp, VALUE vflags,
                            VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  gpgme_call_init (&c, call_op_encrypt_sign, ctx);
  c.u[0] = NUM2INT(vflags);
  c.p[0] = plain;
  c.p[1] = cipher;
  gpgme_call_use (&c, plain);
  gpgme_call_use (&c, cipher);
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    gpgme_call_keys (&c, vrecp);
  err = gpgme_call_run (&c);

  RB_GC_GUARD(vctx);
  RB_GC_GUARD(vrecp);
  RB_GC_GUARD(vplain);
  RB_GC_GUARD(vcipher);

  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_encrypt_sign_start (VALUE dummy, VALUE vctx, VALUE vrecp,
                                  VALUE vflags, VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  gpgme_call_init (&c, call_op_encrypt_sign_start, ctx);
  c.u[0] = NUM2INT(vflags);
  c.p[0] = plain;
  c.p[1] = cipher;
  gpgme_call_use (&c, plain);
  gpgme_call_use (&c, cipher);
  c.op_args = rb_ary_new_from_args (2, vplain, vcipher);
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    gpgme_call_keys (&c, vrecp);
  err = gpgme_call_run (&c);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_wait (VALUE dummy, VALUE vctx, VALUE rstatus, VALUE vhang)
{
  gpgme_ctx_t ctx = NULL, ret;
  gpgme_error_t status;
  int hang = NUM2INT(vhang);

  /* gpgme_wait keeps the GVL.  Even with a CTX, it does the I/O of
     every context with an asynchronous operation in progress, and those
     contexts and their data objects can belong to other threads.  With
     the GVL held, no Ruby code can use them meanwhile.  */
  if (!NIL_P(vctx))
    {
      st_data_t refs;

      UNWRAP_GPGME_CTX(vctx, ctx);
      if (!ctx)
        rb_raise (rb_eArgError, "released ctx");
      /* A call without the GVL could still be using CTX's data.  */
      if (st_lookup (owner_refs, (st_data_t)ctx, &refs)
          && RARRAY_LEN((VALUE)refs) > CTX_REF_OP_ARGS)
        {
          VALUE vargs = RARRAY_AREF((VALUE)refs, CTX_REF_OP_ARGS);
          long i;

          for (i = 0; !NIL_P(vargs) && i < RARRAY_LEN(vargs); i++)
            if (!NIL_P(RARRAY_AREF(vargs, i)))
              check_not_busy (RTYPEDDATA_DATA(RARRAY_AREF(vargs, i)),
                              "GPGME::Data");
        }
    }

  ret = gpgme_wait (ctx, &status, hang);
  if (ret)
    {
      rb_ary_store (rstatus, 0, INT2NUM(status));
      /* The operation is done, so libgpgme no longer uses its data. */
      owner_ref_clear (ret, CTX_REF_OP_ARGS);
      if (ret != ctx)
        {
          st_data_t value;

          /* Return the object that already owns RET.  Wrapping it again
             would make two objects free the same context.  */
          if (!st_lookup (ctx_objects, (st_data_t)ret, &value))
            rb_raise (rb_eRuntimeError, "gpgme_wait returned an unknown ctx");
          vctx = ((struct ctx_entry *)value)->object;
        }
      return vctx;
    }
  return Qnil;
}

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
static VALUE
rb_s_gpgme_op_spawn_start (VALUE dummy, VALUE vctx, VALUE vfile,
                           VALUE vargv, VALUE vdatain, VALUE vdataout,
                           VALUE vdataerr, VALUE vflags)
{
  gpgme_ctx_t ctx;
  VALUE vstrs = Qnil;
  gpgme_call_t c;
  gpgme_data_t datain = NULL;
  gpgme_data_t dataout = NULL;
  gpgme_data_t dataerr = NULL;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  UNWRAP_GPGME_DATA(vdatain, datain);
  UNWRAP_GPGME_DATA(vdataout, dataout);
  UNWRAP_GPGME_DATA(vdataerr, dataerr);
  gpgme_call_init (&c, call_op_spawn_start, ctx);
  c.u[0] = NUM2INT(vflags);
  c.p[0] = datain;
  c.p[1] = dataout;
  c.p[2] = dataerr;
  gpgme_call_use (&c, datain);
  gpgme_call_use (&c, dataout);
  gpgme_call_use (&c, dataerr);
  if (!NIL_P(vargv))
    vstrs = string_array_new (vargv);
  StringValueCStr(vfile);
  c.op_args = rb_ary_new_from_args (3, vdatain, vdataout, vdataerr);
  gpgme_call_str (&c, vfile);
  if (!NIL_P(vargv))
    gpgme_call_strv (&c, vstrs);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(vstrs);
  RB_GC_GUARD(vfile);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_spawn (VALUE dummy, VALUE vctx, VALUE vfile,
                     VALUE vargv, VALUE vdatain, VALUE vdataout,
                     VALUE vdataerr, VALUE vflags)
{
  gpgme_ctx_t ctx;
  VALUE vstrs = Qnil;
  gpgme_call_t c;
  gpgme_data_t datain = NULL;
  gpgme_data_t dataout = NULL;
  gpgme_data_t dataerr = NULL;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  UNWRAP_GPGME_DATA(vdatain, datain);
  UNWRAP_GPGME_DATA(vdataout, dataout);
  UNWRAP_GPGME_DATA(vdataerr, dataerr);
  gpgme_call_init (&c, call_op_spawn, ctx);
  c.u[0] = NUM2INT(vflags);
  c.p[0] = datain;
  c.p[1] = dataout;
  c.p[2] = dataerr;
  gpgme_call_use (&c, datain);
  gpgme_call_use (&c, dataout);
  gpgme_call_use (&c, dataerr);
  if (!NIL_P(vargv))
    vstrs = string_array_new (vargv);
  StringValueCStr(vfile);
  gpgme_call_str (&c, vfile);
  if (!NIL_P(vargv))
    gpgme_call_strv (&c, vstrs);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(vstrs);
  RB_GC_GUARD(vfile);
  return LONG2NUM(err);
}
#endif

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
static VALUE
rb_s_gpgme_op_random_bytes (VALUE dummy, VALUE vctx, VALUE vsize, VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  size_t size;
  VALUE result;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  gpgme_call_init (&c, call_op_random_bytes, ctx);
  c.u[0] = NUM2INT(vmode);
  size = NUM2SIZET(vsize);
  c.u[1] = size;
  /* libgpgme fills the string directly.  No other thread can see it,
     and the reference on this stack keeps GC from moving it.  */
  result = rb_str_new (NULL, size);
  c.p[0] = RSTRING_PTR(result);

  err = gpgme_call_run (&c);
  RB_GC_GUARD(result);
  if (err)
    return LONG2NUM(err);
  return result;
}

static VALUE
rb_s_gpgme_op_random_value (VALUE dummy, VALUE vctx, VALUE vlimit)
{
  gpgme_ctx_t ctx;
  size_t limit;
  gpgme_error_t err;
  gpgme_call_t c;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  limit = NUM2SIZET(vlimit);
  gpgme_call_init (&c, call_op_random_value, ctx);
  c.u[0] = limit;
  err = gpgme_call_run (&c);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    return SIZET2NUM(c.size);
  return LONG2NUM(err);
}
#endif

void
Init_gpgme_n (void)
{
  VALUE mGPGME;

  mGPGME = rb_define_module ("GPGME");

  owner_refs = st_init_numtable ();
  ctx_objects = st_init_numtable ();
  busy_objects = st_init_numtable ();

#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
  rb_define_module_function (mGPGME, "gpgme_get_dirinfo",
                             rb_s_gpgme_get_dirinfo, 1);
#endif
  rb_define_module_function (mGPGME, "gpgme_check_version",
                             rb_s_gpgme_check_version, 1);
  rb_define_module_function (mGPGME, "gpgme_engine_check_version",
                             rb_s_gpgme_engine_check_version, 1);
  rb_define_module_function (mGPGME, "gpgme_get_engine_info",
                             rb_s_gpgme_get_engine_info, 1);
  rb_define_module_function (mGPGME, "gpgme_set_engine_info",
                             rb_s_gpgme_set_engine_info, 3);
  rb_define_module_function (mGPGME, "gpgme_ctx_get_engine_info",
           rb_s_gpgme_ctx_get_engine_info, 2);
  rb_define_module_function (mGPGME, "gpgme_ctx_set_engine_info",
           rb_s_gpgme_ctx_set_engine_info, 4);
  rb_define_module_function (mGPGME, "gpgme_pubkey_algo_name",
                             rb_s_gpgme_pubkey_algo_name, 1);
  rb_define_module_function (mGPGME, "gpgme_hash_algo_name",
                             rb_s_gpgme_hash_algo_name, 1);

  rb_define_module_function (mGPGME, "gpgme_err_code",
                             rb_s_gpgme_err_code, 1);
  rb_define_module_function (mGPGME, "gpgme_err_source",
                             rb_s_gpgme_err_source, 1);
  rb_define_module_function (mGPGME, "gpgme_strerror",
                             rb_s_gpgme_strerror, 1);

  cEngineInfo =
    rb_define_class_under (mGPGME, "EngineInfo", rb_cObject);
  cCtx =
    rb_define_class_under (mGPGME, "Ctx", rb_cObject);
  rb_undef_alloc_func(cCtx);
  cData =
    rb_define_class_under (mGPGME, "Data", rb_cObject);
  rb_undef_alloc_func(cData);
  cKey =
    rb_define_class_under (mGPGME, "Key", rb_cObject);
  rb_undef_alloc_func(cKey);
  cSubKey =
    rb_define_class_under (mGPGME, "SubKey", rb_cObject);
  cUserID =
    rb_define_class_under (mGPGME, "UserID", rb_cObject);
  cKeySig =
    rb_define_class_under (mGPGME, "KeySig", rb_cObject);
  cRecipient =
    rb_define_class_under (mGPGME, "Recipient", rb_cObject);
  cDecryptResult =
    rb_define_class_under (mGPGME, "DecryptResult", rb_cObject);
  cVerifyResult =
    rb_define_class_under (mGPGME, "VerifyResult", rb_cObject);
  cSignResult =
    rb_define_class_under (mGPGME, "SignResult", rb_cObject);
  cEncryptResult =
    rb_define_class_under (mGPGME, "EncryptResult", rb_cObject);
  cSignature =
    rb_define_class_under (mGPGME, "Signature", rb_cObject);
  cSigNotation =
    rb_define_class_under (mGPGME, "SigNotation", rb_cObject);
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
  cTrustItem =
    rb_define_class_under (mGPGME, "TrustItem", rb_cObject);
#endif
  cInvalidKey =
    rb_define_class_under (mGPGME, "InvalidKey", rb_cObject);
  cNewSignature =
    rb_define_class_under (mGPGME, "NewSignature", rb_cObject);
  cImportResult =
    rb_define_class_under (mGPGME, "ImportResult", rb_cObject);
  cImportStatus =
    rb_define_class_under (mGPGME, "ImportStatus", rb_cObject);

  /* Creating Data Buffers
   *
   * gpgme_data_new_from_filepart is not currently supported.
   */
  rb_define_module_function (mGPGME, "gpgme_data_new",
                             rb_s_gpgme_data_new, 1);
  rb_define_module_function (mGPGME, "gpgme_data_new_from_mem",
                             rb_s_gpgme_data_new_from_mem, 3);
  rb_define_module_function (mGPGME, "gpgme_data_new_from_fd",
                             rb_s_gpgme_data_new_from_fd, 2);
  rb_define_module_function (mGPGME, "gpgme_data_new_from_cbs",
                             rb_s_gpgme_data_new_from_cbs, 3);

  /* Manipulating Data Buffers */
  rb_define_module_function (mGPGME, "gpgme_data_read",
                             rb_s_gpgme_data_read, 2);
  rb_define_module_function (mGPGME, "gpgme_data_seek",
                             rb_s_gpgme_data_seek, 3);
  rb_define_module_function (mGPGME, "gpgme_data_write",
                             rb_s_gpgme_data_write, 3);
  rb_define_module_function (mGPGME, "gpgme_data_get_encoding",
                             rb_s_gpgme_data_get_encoding, 1);
  rb_define_module_function (mGPGME, "gpgme_data_set_encoding",
                             rb_s_gpgme_data_set_encoding, 2);
  rb_define_module_function (mGPGME, "gpgme_data_get_file_name",
                             rb_s_gpgme_data_get_file_name, 1);
  rb_define_module_function (mGPGME, "gpgme_data_set_file_name",
                             rb_s_gpgme_data_set_file_name, 2);

  /* Creating Contexts */
  rb_define_module_function (mGPGME, "gpgme_new",
                             rb_s_gpgme_new, 1);
  rb_define_module_function (mGPGME, "gpgme_release",
                             rb_s_gpgme_release, 1);

  /* Context Attributes */
  rb_define_module_function (mGPGME, "gpgme_set_ctx_flag",
                             rb_s_gpgme_set_ctx_flag, 3);
  rb_define_module_function (mGPGME, "gpgme_get_ctx_flag",
                             rb_s_gpgme_get_ctx_flag, 2);
  rb_define_module_function (mGPGME, "gpgme_set_protocol",
                             rb_s_gpgme_set_protocol, 2);
  rb_define_module_function (mGPGME, "gpgme_get_protocol",
                             rb_s_gpgme_get_protocol, 1);
  rb_define_module_function (mGPGME, "gpgme_set_armor",
                             rb_s_gpgme_set_armor, 2);
  rb_define_module_function (mGPGME, "gpgme_get_armor",
                             rb_s_gpgme_get_armor, 1);
  rb_define_module_function (mGPGME, "gpgme_set_ignore_mdc_error",
                             rb_s_gpgme_set_ignore_mdc_error, 2);
  rb_define_module_function (mGPGME, "gpgme_get_ignore_mdc_error",
                             rb_s_gpgme_get_ignore_mdc_error, 1);
  rb_define_module_function (mGPGME, "gpgme_set_textmode",
                             rb_s_gpgme_set_textmode, 2);
  rb_define_module_function (mGPGME, "gpgme_get_textmode",
                             rb_s_gpgme_get_textmode, 1);
  rb_define_module_function (mGPGME, "gpgme_set_include_certs",
                             rb_s_gpgme_set_include_certs, 2);
  rb_define_module_function (mGPGME, "gpgme_get_include_certs",
                             rb_s_gpgme_get_include_certs, 1);
  rb_define_module_function (mGPGME, "gpgme_set_keylist_mode",
                             rb_s_gpgme_set_keylist_mode, 2);
  rb_define_module_function (mGPGME, "gpgme_get_keylist_mode",
                             rb_s_gpgme_get_keylist_mode, 1);
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010400
  rb_define_module_function (mGPGME, "gpgme_set_pinentry_mode",
                             rb_s_gpgme_set_pinentry_mode, 2);
  rb_define_module_function (mGPGME, "gpgme_get_pinentry_mode",
                             rb_s_gpgme_get_pinentry_mode, 1);
#endif
  rb_define_module_function (mGPGME, "gpgme_set_passphrase_cb",
                             rb_s_gpgme_set_passphrase_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_get_passphrase_cb",
                             rb_s_gpgme_get_passphrase_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_set_progress_cb",
                             rb_s_gpgme_set_progress_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_get_progress_cb",
                             rb_s_gpgme_get_progress_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_set_locale",
                             rb_s_gpgme_set_locale, 3);
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010600
  rb_define_module_function (mGPGME, "gpgme_set_offline",
                             rb_s_gpgme_set_offline, 2);
  rb_define_module_function (mGPGME, "gpgme_get_offline",
                             rb_s_gpgme_get_offline, 1);
  rb_define_module_function (mGPGME, "gpgme_set_status_cb",
                             rb_s_gpgme_set_status_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_get_status_cb",
                             rb_s_gpgme_get_status_cb, 3);
#endif

  /* Key Management */
  rb_define_module_function (mGPGME, "gpgme_op_keylist_start",
                             rb_s_gpgme_op_keylist_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_keylist_ext_start",
                             rb_s_gpgme_op_keylist_ext_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_keylist_next",
                             rb_s_gpgme_op_keylist_next, 2);
  rb_define_module_function (mGPGME, "gpgme_op_keylist_end",
                             rb_s_gpgme_op_keylist_end, 1);
  rb_define_module_function (mGPGME, "gpgme_get_key",
                             rb_s_gpgme_get_key, 4);
  rb_define_module_function (mGPGME, "gpgme_op_genkey",
                             rb_s_gpgme_op_genkey, 4);
  rb_define_module_function (mGPGME, "gpgme_op_genkey_start",
                             rb_s_gpgme_op_genkey_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export",
                             rb_s_gpgme_op_export, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_start",
                             rb_s_gpgme_op_export_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_ext",
                             rb_s_gpgme_op_export_ext, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_ext_start",
                             rb_s_gpgme_op_export_ext_start, 4);
#ifdef HAVE_GPGME_OP_EXPORT_KEYS
  rb_define_module_function (mGPGME, "gpgme_op_export_keys",
                             rb_s_gpgme_op_export_keys, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_keys_start",
                             rb_s_gpgme_op_export_keys_start, 4);
#endif
  rb_define_module_function (mGPGME, "gpgme_op_import",
                             rb_s_gpgme_op_import, 2);
  rb_define_module_function (mGPGME, "gpgme_op_import_start",
                             rb_s_gpgme_op_import_start, 2);
#ifdef HAVE_GPGME_OP_EXPORT_KEYS
  rb_define_module_function (mGPGME, "gpgme_op_import_keys",
                             rb_s_gpgme_op_import_keys, 2);
  rb_define_module_function (mGPGME, "gpgme_op_import_keys_start",
                             rb_s_gpgme_op_import_keys_start, 2);
#endif
  rb_define_module_function (mGPGME, "gpgme_op_import_result",
                             rb_s_gpgme_op_import_result, 1);
  rb_define_module_function (mGPGME, "gpgme_op_delete",
                             rb_s_gpgme_op_delete, 3);
  rb_define_module_function (mGPGME, "gpgme_op_delete_ext",
                             rb_s_gpgme_op_delete_ext, 3);
  rb_define_module_function (mGPGME, "gpgme_op_delete_start",
                             rb_s_gpgme_op_delete_start, 3);

  /* Key Edit Interface
   * For GPGME 2.0.0+, these functions use gpgme_op_interact internally
   * with a shim to maintain backward compatibility with existing callbacks.
   */
  rb_define_module_function (mGPGME, "gpgme_op_edit",
                             rb_s_gpgme_op_edit, 5);
  rb_define_module_function (mGPGME, "gpgme_op_edit_start",
                             rb_s_gpgme_op_edit_start, 5);
  rb_define_module_function (mGPGME, "gpgme_op_card_edit",
                             rb_s_gpgme_op_card_edit, 5);
  rb_define_module_function (mGPGME, "gpgme_op_card_edit_start",
                             rb_s_gpgme_op_card_edit_start, 5);

  /* Trust Item Management */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
  rb_define_module_function (mGPGME, "gpgme_op_trustlist_start",
                             rb_s_gpgme_op_trustlist_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_trustlist_next",
                             rb_s_gpgme_op_trustlist_next, 2);
  rb_define_module_function (mGPGME, "gpgme_op_trustlist_end",
                             rb_s_gpgme_op_trustlist_end, 1);
#endif

  /* Decrypt */
  rb_define_module_function (mGPGME, "gpgme_op_decrypt",
                             rb_s_gpgme_op_decrypt, 3);
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_start",
                             rb_s_gpgme_op_decrypt_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_result",
                             rb_s_gpgme_op_decrypt_result, 1);

  /* Verify */
  rb_define_module_function (mGPGME, "gpgme_op_verify",
                             rb_s_gpgme_op_verify, 4);
  rb_define_module_function (mGPGME, "gpgme_op_verify_start",
                             rb_s_gpgme_op_verify_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_verify_result",
                             rb_s_gpgme_op_verify_result, 1);

  /* Decrypt and Verify */
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_verify",
                             rb_s_gpgme_op_decrypt_verify, 3);
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_verify_start",
                             rb_s_gpgme_op_decrypt_verify_start, 3);

  /* Sign */
  rb_define_module_function (mGPGME, "gpgme_signers_clear",
                             rb_s_gpgme_signers_clear, 1);
  rb_define_module_function (mGPGME, "gpgme_signers_add",
                             rb_s_gpgme_signers_add, 2);
  rb_define_module_function (mGPGME, "gpgme_signers_enum",
                             rb_s_gpgme_signers_enum, 2);
  rb_define_module_function (mGPGME, "gpgme_op_sign",
                             rb_s_gpgme_op_sign, 4);
  rb_define_module_function (mGPGME, "gpgme_op_sign_start",
                             rb_s_gpgme_op_sign_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_sign_result",
                             rb_s_gpgme_op_sign_result, 1);

  /* Encrypt */
  rb_define_module_function (mGPGME, "gpgme_op_encrypt",
                             rb_s_gpgme_op_encrypt, 5);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_start",
                             rb_s_gpgme_op_encrypt_start, 5);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_result",
                             rb_s_gpgme_op_encrypt_result, 1);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_sign",
                             rb_s_gpgme_op_encrypt_sign, 5);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_sign_start",
                             rb_s_gpgme_op_encrypt_sign_start, 5);

  /* Run Control */
  rb_define_module_function (mGPGME, "gpgme_wait",
                             rb_s_gpgme_wait, 3);

  /* Running other Programs */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
  rb_define_module_function (mGPGME, "gpgme_op_spawn",
                             rb_s_gpgme_op_spawn, 7);
  rb_define_module_function (mGPGME, "gpgme_op_spawn_start",
                             rb_s_gpgme_op_spawn_start, 7);
#endif

  /* Random Number Generation */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
  rb_define_module_function (mGPGME, "gpgme_op_random_bytes",
                             rb_s_gpgme_op_random_bytes, 3);
  rb_define_module_function (mGPGME, "gpgme_op_random_value",
                             rb_s_gpgme_op_random_value, 2);
#endif

  /* gpgme_pubkey_algo_t */
  rb_define_const (mGPGME, "GPGME_PK_RSA", INT2FIX(GPGME_PK_RSA));
  rb_define_const (mGPGME, "GPGME_PK_DSA", INT2FIX(GPGME_PK_DSA));
  rb_define_const (mGPGME, "GPGME_PK_ELG", INT2FIX(GPGME_PK_ELG));
  rb_define_const (mGPGME, "GPGME_PK_ELG_E", INT2FIX(GPGME_PK_ELG_E));
  /* This algorithm was added in 1.5.0. */
#ifdef GPGME_PK_ECC
  rb_define_const (mGPGME, "GPGME_PK_ECC", INT2FIX(GPGME_PK_ECC));
#endif

  /* gpgme_hash_algo_t */
  rb_define_const (mGPGME, "GPGME_MD_MD5", INT2FIX(GPGME_MD_MD5));
  rb_define_const (mGPGME, "GPGME_MD_SHA1", INT2FIX(GPGME_MD_SHA1));
  rb_define_const (mGPGME, "GPGME_MD_RMD160", INT2FIX(GPGME_MD_RMD160));
  rb_define_const (mGPGME, "GPGME_MD_MD2", INT2FIX(GPGME_MD_MD2));
  rb_define_const (mGPGME, "GPGME_MD_TIGER", INT2FIX(GPGME_MD_TIGER));
  rb_define_const (mGPGME, "GPGME_MD_HAVAL", INT2FIX(GPGME_MD_HAVAL));
  /* This algorithm was added in 1.5.0. */
#ifdef GPGME_MD_SHA224
  rb_define_const (mGPGME, "GPGME_MD_SHA224", INT2FIX(GPGME_MD_SHA224));
#endif
  rb_define_const (mGPGME, "GPGME_MD_SHA256", INT2FIX(GPGME_MD_SHA256));
  rb_define_const (mGPGME, "GPGME_MD_SHA384", INT2FIX(GPGME_MD_SHA384));
  rb_define_const (mGPGME, "GPGME_MD_SHA512", INT2FIX(GPGME_MD_SHA512));
  rb_define_const (mGPGME, "GPGME_MD_MD4", INT2FIX(GPGME_MD_MD4));
  rb_define_const (mGPGME, "GPGME_MD_CRC32", INT2FIX(GPGME_MD_CRC32));
  rb_define_const (mGPGME, "GPGME_MD_CRC32_RFC1510",
                   INT2FIX(GPGME_MD_CRC32_RFC1510));
  rb_define_const (mGPGME, "GPGME_MD_CRC24_RFC2440",
                   INT2FIX(GPGME_MD_CRC24_RFC2440));

  /* gpgme_err_code_t */
  rb_define_const (mGPGME, "GPG_ERR_EOF",
                   INT2FIX(GPG_ERR_EOF));
  rb_define_const (mGPGME, "GPG_ERR_NO_ERROR",
                   INT2FIX(GPG_ERR_NO_ERROR));
  rb_define_const (mGPGME, "GPG_ERR_GENERAL",
                   INT2FIX(GPG_ERR_GENERAL));
  rb_define_const (mGPGME, "GPG_ERR_ENOMEM",
                   INT2FIX(GPG_ERR_ENOMEM));
  rb_define_const (mGPGME, "GPG_ERR_INV_VALUE",
                   INT2FIX(GPG_ERR_INV_VALUE));
  rb_define_const (mGPGME, "GPG_ERR_UNUSABLE_PUBKEY",
                   INT2FIX(GPG_ERR_UNUSABLE_PUBKEY));
  rb_define_const (mGPGME, "GPG_ERR_UNUSABLE_SECKEY",
                   INT2FIX(GPG_ERR_UNUSABLE_SECKEY));
  rb_define_const (mGPGME, "GPG_ERR_NO_DATA",
                   INT2FIX(GPG_ERR_NO_DATA));
  rb_define_const (mGPGME, "GPG_ERR_CONFLICT",
                   INT2FIX(GPG_ERR_CONFLICT));
  rb_define_const (mGPGME, "GPG_ERR_NOT_IMPLEMENTED",
                   INT2FIX(GPG_ERR_NOT_IMPLEMENTED));
  rb_define_const (mGPGME, "GPG_ERR_DECRYPT_FAILED",
                   INT2FIX(GPG_ERR_DECRYPT_FAILED));
  rb_define_const (mGPGME, "GPG_ERR_BAD_PASSPHRASE",
                   INT2FIX(GPG_ERR_BAD_PASSPHRASE));
  rb_define_const (mGPGME, "GPG_ERR_KEY_EXPIRED",
                   INT2FIX(GPG_ERR_KEY_EXPIRED));
  rb_define_const (mGPGME, "GPG_ERR_SIG_EXPIRED",
                   INT2FIX(GPG_ERR_SIG_EXPIRED));
  rb_define_const (mGPGME, "GPG_ERR_CANCELED",
                   INT2FIX(GPG_ERR_CANCELED));
  rb_define_const (mGPGME, "GPG_ERR_INV_ENGINE",
                   INT2FIX(GPG_ERR_INV_ENGINE));
  rb_define_const (mGPGME, "GPG_ERR_AMBIGUOUS_NAME",
                   INT2FIX(GPG_ERR_AMBIGUOUS_NAME));
  rb_define_const (mGPGME, "GPG_ERR_WRONG_KEY_USAGE",
                   INT2FIX(GPG_ERR_WRONG_KEY_USAGE));
  rb_define_const (mGPGME, "GPG_ERR_CERT_REVOKED",
                   INT2FIX(GPG_ERR_CERT_REVOKED));
  rb_define_const (mGPGME, "GPG_ERR_CERT_EXPIRED",
                   INT2FIX(GPG_ERR_CERT_EXPIRED));
  rb_define_const (mGPGME, "GPG_ERR_NO_CRL_KNOWN",
                   INT2FIX(GPG_ERR_NO_CRL_KNOWN));
  rb_define_const (mGPGME, "GPG_ERR_NO_POLICY_MATCH",
                   INT2FIX(GPG_ERR_NO_POLICY_MATCH));
  rb_define_const (mGPGME, "GPG_ERR_NO_SECKEY",
                   INT2FIX(GPG_ERR_NO_SECKEY));
  rb_define_const (mGPGME, "GPG_ERR_MISSING_CERT",
                   INT2FIX(GPG_ERR_MISSING_CERT));
  rb_define_const (mGPGME, "GPG_ERR_BAD_CERT_CHAIN",
                   INT2FIX(GPG_ERR_BAD_CERT_CHAIN));
  rb_define_const (mGPGME, "GPG_ERR_UNSUPPORTED_ALGORITHM",
                   INT2FIX(GPG_ERR_UNSUPPORTED_ALGORITHM));
  rb_define_const (mGPGME, "GPG_ERR_BAD_SIGNATURE",
                   INT2FIX(GPG_ERR_BAD_SIGNATURE));
  rb_define_const (mGPGME, "GPG_ERR_NO_PUBKEY",
                   INT2FIX(GPG_ERR_NO_PUBKEY));

  /* gpgme_err_source_t */
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_UNKNOWN",
                   INT2FIX(GPG_ERR_SOURCE_UNKNOWN));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_GPGME",
                   INT2FIX(GPG_ERR_SOURCE_GPGME));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_GPG",
                   INT2FIX(GPG_ERR_SOURCE_GPG));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_GPGSM",
                   INT2FIX(GPG_ERR_SOURCE_GPGSM));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_GCRYPT",
                   INT2FIX(GPG_ERR_SOURCE_GCRYPT));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_GPGAGENT",
                   INT2FIX(GPG_ERR_SOURCE_GPGAGENT));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_PINENTRY",
                   INT2FIX(GPG_ERR_SOURCE_PINENTRY));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_SCD",
                   INT2FIX(GPG_ERR_SOURCE_SCD));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_KEYBOX",
                   INT2FIX(GPG_ERR_SOURCE_KEYBOX));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_USER_1",
                   INT2FIX(GPG_ERR_SOURCE_USER_1));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_USER_2",
                   INT2FIX(GPG_ERR_SOURCE_USER_2));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_USER_3",
                   INT2FIX(GPG_ERR_SOURCE_USER_3));
  rb_define_const (mGPGME, "GPG_ERR_SOURCE_USER_4",
                   INT2FIX(GPG_ERR_SOURCE_USER_4));

  /* gpgme_data_encoding_t */
  rb_define_const (mGPGME, "GPGME_DATA_ENCODING_NONE",
                   INT2FIX(GPGME_DATA_ENCODING_NONE));
  rb_define_const (mGPGME, "GPGME_DATA_ENCODING_BINARY",
                   INT2FIX(GPGME_DATA_ENCODING_BINARY));
  rb_define_const (mGPGME, "GPGME_DATA_ENCODING_BASE64",
                   INT2FIX(GPGME_DATA_ENCODING_BASE64));
  rb_define_const (mGPGME, "GPGME_DATA_ENCODING_ARMOR",
                   INT2FIX(GPGME_DATA_ENCODING_ARMOR));

  /* gpgme_sig_stat_t */
  rb_define_const (mGPGME, "GPGME_SIG_STAT_NONE",
                   INT2FIX(GPGME_SIG_STAT_NONE));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_GOOD",
                   INT2FIX(GPGME_SIG_STAT_GOOD));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_BAD",
                   INT2FIX(GPGME_SIG_STAT_BAD));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_NOKEY",
                   INT2FIX(GPGME_SIG_STAT_NOKEY));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_NOSIG",
                   INT2FIX(GPGME_SIG_STAT_NOSIG));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_ERROR",
                   INT2FIX(GPGME_SIG_STAT_ERROR));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_DIFF",
                   INT2FIX(GPGME_SIG_STAT_DIFF));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_GOOD_EXP",
                   INT2FIX(GPGME_SIG_STAT_GOOD_EXP));
  rb_define_const (mGPGME, "GPGME_SIG_STAT_GOOD_EXPKEY",
                   INT2FIX(GPGME_SIG_STAT_GOOD_EXPKEY));

  /* gpgme_sigsum_t */
  rb_define_const (mGPGME, "GPGME_SIGSUM_VALID",
                   INT2FIX(GPGME_SIGSUM_VALID));
  rb_define_const (mGPGME, "GPGME_SIGSUM_GREEN",
                   INT2FIX(GPGME_SIGSUM_GREEN));
  rb_define_const (mGPGME, "GPGME_SIGSUM_RED",
                   INT2FIX(GPGME_SIGSUM_RED));
  rb_define_const (mGPGME, "GPGME_SIGSUM_KEY_REVOKED",
                   INT2FIX(GPGME_SIGSUM_KEY_REVOKED));
  rb_define_const (mGPGME, "GPGME_SIGSUM_KEY_EXPIRED",
                   INT2FIX(GPGME_SIGSUM_KEY_EXPIRED));
  rb_define_const (mGPGME, "GPGME_SIGSUM_SIG_EXPIRED",
                   INT2FIX(GPGME_SIGSUM_SIG_EXPIRED));
  rb_define_const (mGPGME, "GPGME_SIGSUM_KEY_MISSING",
                   INT2FIX(GPGME_SIGSUM_KEY_MISSING));
  rb_define_const (mGPGME, "GPGME_SIGSUM_CRL_MISSING",
                   INT2FIX(GPGME_SIGSUM_CRL_MISSING));
  rb_define_const (mGPGME, "GPGME_SIGSUM_CRL_TOO_OLD",
                   INT2FIX(GPGME_SIGSUM_CRL_TOO_OLD));
  rb_define_const (mGPGME, "GPGME_SIGSUM_BAD_POLICY",
                   INT2FIX(GPGME_SIGSUM_BAD_POLICY));
  rb_define_const (mGPGME, "GPGME_SIGSUM_SYS_ERROR",
                   INT2FIX(GPGME_SIGSUM_SYS_ERROR));

  /* gpgme_sig_mode_t */
  rb_define_const (mGPGME, "GPGME_SIG_MODE_NORMAL",
                   INT2FIX(GPGME_SIG_MODE_NORMAL));
  rb_define_const (mGPGME, "GPGME_SIG_MODE_DETACH",
                   INT2FIX(GPGME_SIG_MODE_DETACH));
  rb_define_const (mGPGME, "GPGME_SIG_MODE_CLEAR",
                   INT2FIX(GPGME_SIG_MODE_CLEAR));

  /* gpgme_attr_t */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER < 0x020000
  rb_define_const (mGPGME, "GPGME_ATTR_KEYID",
                   INT2FIX(GPGME_ATTR_KEYID));
  rb_define_const (mGPGME, "GPGME_ATTR_FPR",
                   INT2FIX(GPGME_ATTR_FPR));
  rb_define_const (mGPGME, "GPGME_ATTR_ALGO",
                   INT2FIX(GPGME_ATTR_ALGO));
  rb_define_const (mGPGME, "GPGME_ATTR_LEN",
                   INT2FIX(GPGME_ATTR_LEN));
  rb_define_const (mGPGME, "GPGME_ATTR_CREATED",
                   INT2FIX(GPGME_ATTR_CREATED));
  rb_define_const (mGPGME, "GPGME_ATTR_EXPIRE",
                   INT2FIX(GPGME_ATTR_EXPIRE));
  rb_define_const (mGPGME, "GPGME_ATTR_OTRUST",
                   INT2FIX(GPGME_ATTR_OTRUST));
  rb_define_const (mGPGME, "GPGME_ATTR_USERID",
                   INT2FIX(GPGME_ATTR_USERID));
  rb_define_const (mGPGME, "GPGME_ATTR_NAME",
                   INT2FIX(GPGME_ATTR_NAME));
  rb_define_const (mGPGME, "GPGME_ATTR_EMAIL",
                   INT2FIX(GPGME_ATTR_EMAIL));
  rb_define_const (mGPGME, "GPGME_ATTR_COMMENT",
                   INT2FIX(GPGME_ATTR_COMMENT));
  rb_define_const (mGPGME, "GPGME_ATTR_VALIDITY",
                   INT2FIX(GPGME_ATTR_VALIDITY));
  rb_define_const (mGPGME, "GPGME_ATTR_LEVEL",
                   INT2FIX(GPGME_ATTR_LEVEL));
  rb_define_const (mGPGME, "GPGME_ATTR_TYPE",
                   INT2FIX(GPGME_ATTR_TYPE));
  rb_define_const (mGPGME, "GPGME_ATTR_IS_SECRET",
                   INT2FIX(GPGME_ATTR_IS_SECRET));
  rb_define_const (mGPGME, "GPGME_ATTR_KEY_REVOKED",
                   INT2FIX(GPGME_ATTR_KEY_REVOKED));
  rb_define_const (mGPGME, "GPGME_ATTR_KEY_INVALID",
                   INT2FIX(GPGME_ATTR_KEY_INVALID));
  rb_define_const (mGPGME, "GPGME_ATTR_UID_REVOKED",
                   INT2FIX(GPGME_ATTR_UID_REVOKED));
  rb_define_const (mGPGME, "GPGME_ATTR_UID_INVALID",
                   INT2FIX(GPGME_ATTR_UID_INVALID));
  rb_define_const (mGPGME, "GPGME_ATTR_KEY_CAPS",
                   INT2FIX(GPGME_ATTR_KEY_CAPS));
  rb_define_const (mGPGME, "GPGME_ATTR_CAN_ENCRYPT",
                   INT2FIX(GPGME_ATTR_CAN_ENCRYPT));
  rb_define_const (mGPGME, "GPGME_ATTR_CAN_SIGN",
                   INT2FIX(GPGME_ATTR_CAN_SIGN));
  rb_define_const (mGPGME, "GPGME_ATTR_CAN_CERTIFY",
                   INT2FIX(GPGME_ATTR_CAN_CERTIFY));
  rb_define_const (mGPGME, "GPGME_ATTR_KEY_EXPIRED",
                   INT2FIX(GPGME_ATTR_KEY_EXPIRED));
  rb_define_const (mGPGME, "GPGME_ATTR_KEY_DISABLED",
                   INT2FIX(GPGME_ATTR_KEY_DISABLED));
  rb_define_const (mGPGME, "GPGME_ATTR_SERIAL",
                   INT2FIX(GPGME_ATTR_SERIAL));
  rb_define_const (mGPGME, "GPGME_ATTR_ISSUER",
                   INT2FIX(GPGME_ATTR_ISSUER));
  rb_define_const (mGPGME, "GPGME_ATTR_CHAINID",
                   INT2FIX(GPGME_ATTR_CHAINID));
  rb_define_const (mGPGME, "GPGME_ATTR_SIG_STATUS",
                   INT2FIX(GPGME_ATTR_SIG_STATUS));
  rb_define_const (mGPGME, "GPGME_ATTR_ERRTOK",
                   INT2FIX(GPGME_ATTR_ERRTOK));
  rb_define_const (mGPGME, "GPGME_ATTR_SIG_SUMMARY",
                   INT2FIX(GPGME_ATTR_SIG_SUMMARY));
#endif

  /* gpgme_validity_t */
  rb_define_const (mGPGME, "GPGME_VALIDITY_UNKNOWN",
                   INT2FIX(GPGME_VALIDITY_UNKNOWN));
  rb_define_const (mGPGME, "GPGME_VALIDITY_UNDEFINED",
                   INT2FIX(GPGME_VALIDITY_UNDEFINED));
  rb_define_const (mGPGME, "GPGME_VALIDITY_NEVER",
                   INT2FIX(GPGME_VALIDITY_NEVER));
  rb_define_const (mGPGME, "GPGME_VALIDITY_MARGINAL",
                   INT2FIX(GPGME_VALIDITY_MARGINAL));
  rb_define_const (mGPGME, "GPGME_VALIDITY_FULL",
                   INT2FIX(GPGME_VALIDITY_FULL));
  rb_define_const (mGPGME, "GPGME_VALIDITY_ULTIMATE",
                   INT2FIX(GPGME_VALIDITY_ULTIMATE));

  /* gpgme_protocol_t */
  rb_define_const (mGPGME, "GPGME_PROTOCOL_OpenPGP",
                   INT2FIX(GPGME_PROTOCOL_OpenPGP));
  rb_define_const (mGPGME, "GPGME_PROTOCOL_CMS",
                   INT2FIX(GPGME_PROTOCOL_CMS));
  /* This protocol was added in 1.2.0. */
#ifdef GPGME_PROTOCOL_ASSUAN
  rb_define_const (mGPGME, "GPGME_PROTOCOL_ASSUAN",
                   INT2FIX(GPGME_PROTOCOL_ASSUAN))
#endif
  /* This protocol was added in 1.5.0. */
#ifdef GPGME_PROTOCOL_SPAWN
  rb_define_const (mGPGME, "GPGME_PROTOCOL_SPAWN",
                   INT2FIX(GPGME_PROTOCOL_SPAWN));
#endif

  /* gpgme_status_code_t */
  rb_define_const (mGPGME, "GPGME_STATUS_EOF",
                   INT2FIX(GPGME_STATUS_EOF));
  /* mkstatus starts here */
  rb_define_const (mGPGME, "GPGME_STATUS_ENTER",
                   INT2FIX(GPGME_STATUS_ENTER));
  rb_define_const (mGPGME, "GPGME_STATUS_LEAVE",
                   INT2FIX(GPGME_STATUS_LEAVE));
  rb_define_const (mGPGME, "GPGME_STATUS_ABORT",
                   INT2FIX(GPGME_STATUS_ABORT));

  rb_define_const (mGPGME, "GPGME_STATUS_GOODSIG",
                   INT2FIX(GPGME_STATUS_GOODSIG));
  rb_define_const (mGPGME, "GPGME_STATUS_BADSIG",
                   INT2FIX(GPGME_STATUS_BADSIG));
  rb_define_const (mGPGME, "GPGME_STATUS_ERRSIG",
                   INT2FIX(GPGME_STATUS_ERRSIG));

  rb_define_const (mGPGME, "GPGME_STATUS_BADARMOR",
                   INT2FIX(GPGME_STATUS_BADARMOR));

  rb_define_const (mGPGME, "GPGME_STATUS_RSA_OR_IDEA",
                   INT2FIX(GPGME_STATUS_RSA_OR_IDEA));
  rb_define_const (mGPGME, "GPGME_STATUS_KEYEXPIRED",
                   INT2FIX(GPGME_STATUS_KEYEXPIRED));
  rb_define_const (mGPGME, "GPGME_STATUS_KEYREVOKED",
                   INT2FIX(GPGME_STATUS_KEYREVOKED));

  rb_define_const (mGPGME, "GPGME_STATUS_TRUST_UNDEFINED",
                   INT2FIX(GPGME_STATUS_TRUST_UNDEFINED));
  rb_define_const (mGPGME, "GPGME_STATUS_TRUST_NEVER",
                   INT2FIX(GPGME_STATUS_TRUST_NEVER));
  rb_define_const (mGPGME, "GPGME_STATUS_TRUST_MARGINAL",
                   INT2FIX(GPGME_STATUS_TRUST_MARGINAL));
  rb_define_const (mGPGME, "GPGME_STATUS_TRUST_FULLY",
                   INT2FIX(GPGME_STATUS_TRUST_FULLY));
  rb_define_const (mGPGME, "GPGME_STATUS_TRUST_ULTIMATE",
                   INT2FIX(GPGME_STATUS_TRUST_ULTIMATE));

  rb_define_const (mGPGME, "GPGME_STATUS_SHM_INFO",
                   INT2FIX(GPGME_STATUS_SHM_INFO));
  rb_define_const (mGPGME, "GPGME_STATUS_SHM_GET",
                   INT2FIX(GPGME_STATUS_SHM_GET));
  rb_define_const (mGPGME, "GPGME_STATUS_SHM_GET_BOOL",
                   INT2FIX(GPGME_STATUS_SHM_GET_BOOL));
  rb_define_const (mGPGME, "GPGME_STATUS_SHM_GET_HIDDEN",
                   INT2FIX(GPGME_STATUS_SHM_GET_HIDDEN));

  rb_define_const (mGPGME, "GPGME_STATUS_NEED_PASSPHRASE",
                   INT2FIX(GPGME_STATUS_NEED_PASSPHRASE));
  rb_define_const (mGPGME, "GPGME_STATUS_VALIDSIG",
                   INT2FIX(GPGME_STATUS_VALIDSIG));
  rb_define_const (mGPGME, "GPGME_STATUS_SIG_ID",
                   INT2FIX(GPGME_STATUS_SIG_ID));
  rb_define_const (mGPGME, "GPGME_STATUS_ENC_TO",
                   INT2FIX(GPGME_STATUS_ENC_TO));
  rb_define_const (mGPGME, "GPGME_STATUS_NODATA",
                   INT2FIX(GPGME_STATUS_NODATA));
  rb_define_const (mGPGME, "GPGME_STATUS_BAD_PASSPHRASE",
                   INT2FIX(GPGME_STATUS_BAD_PASSPHRASE));
  rb_define_const (mGPGME, "GPGME_STATUS_NO_PUBKEY",
                   INT2FIX(GPGME_STATUS_NO_PUBKEY));
  rb_define_const (mGPGME, "GPGME_STATUS_NO_SECKEY",
                   INT2FIX(GPGME_STATUS_NO_SECKEY));
  rb_define_const (mGPGME, "GPGME_STATUS_NEED_PASSPHRASE_SYM",
                   INT2FIX(GPGME_STATUS_NEED_PASSPHRASE_SYM));
  rb_define_const (mGPGME, "GPGME_STATUS_DECRYPTION_FAILED",
                   INT2FIX(GPGME_STATUS_DECRYPTION_FAILED));
  rb_define_const (mGPGME, "GPGME_STATUS_DECRYPTION_OKAY",
                   INT2FIX(GPGME_STATUS_DECRYPTION_OKAY));
  rb_define_const (mGPGME, "GPGME_STATUS_MISSING_PASSPHRASE",
                   INT2FIX(GPGME_STATUS_MISSING_PASSPHRASE));
  rb_define_const (mGPGME, "GPGME_STATUS_GOOD_PASSPHRASE",
                   INT2FIX(GPGME_STATUS_GOOD_PASSPHRASE));
  rb_define_const (mGPGME, "GPGME_STATUS_GOODMDC",
                   INT2FIX(GPGME_STATUS_GOODMDC));
  rb_define_const (mGPGME, "GPGME_STATUS_BADMDC",
                   INT2FIX(GPGME_STATUS_BADMDC));
  rb_define_const (mGPGME, "GPGME_STATUS_ERRMDC",
                   INT2FIX(GPGME_STATUS_ERRMDC));
  rb_define_const (mGPGME, "GPGME_STATUS_IMPORTED",
                   INT2FIX(GPGME_STATUS_IMPORTED));
  rb_define_const (mGPGME, "GPGME_STATUS_IMPORT_RES",
                   INT2FIX(GPGME_STATUS_IMPORT_RES));
  rb_define_const (mGPGME, "GPGME_STATUS_FILE_START",
                   INT2FIX(GPGME_STATUS_FILE_START));
  rb_define_const (mGPGME, "GPGME_STATUS_FILE_DONE",
                   INT2FIX(GPGME_STATUS_FILE_DONE));
  rb_define_const (mGPGME, "GPGME_STATUS_FILE_ERROR",
                   INT2FIX(GPGME_STATUS_FILE_ERROR));

  rb_define_const (mGPGME, "GPGME_STATUS_BEGIN_DECRYPTION",
                   INT2FIX(GPGME_STATUS_BEGIN_DECRYPTION));
  rb_define_const (mGPGME, "GPGME_STATUS_END_DECRYPTION",
                   INT2FIX(GPGME_STATUS_END_DECRYPTION));
  rb_define_const (mGPGME, "GPGME_STATUS_BEGIN_ENCRYPTION",
                   INT2FIX(GPGME_STATUS_BEGIN_ENCRYPTION));
  rb_define_const (mGPGME, "GPGME_STATUS_END_ENCRYPTION",
                   INT2FIX(GPGME_STATUS_END_ENCRYPTION));

  rb_define_const (mGPGME, "GPGME_STATUS_DELETE_PROBLEM",
                   INT2FIX(GPGME_STATUS_DELETE_PROBLEM));
  rb_define_const (mGPGME, "GPGME_STATUS_GET_BOOL",
                   INT2FIX(GPGME_STATUS_GET_BOOL));
  rb_define_const (mGPGME, "GPGME_STATUS_GET_LINE",
                   INT2FIX(GPGME_STATUS_GET_LINE));
  rb_define_const (mGPGME, "GPGME_STATUS_GET_HIDDEN",
                   INT2FIX(GPGME_STATUS_GET_HIDDEN));
  rb_define_const (mGPGME, "GPGME_STATUS_GOT_IT",
                   INT2FIX(GPGME_STATUS_GOT_IT));
  rb_define_const (mGPGME, "GPGME_STATUS_PROGRESS",
                   INT2FIX(GPGME_STATUS_PROGRESS));
  rb_define_const (mGPGME, "GPGME_STATUS_SIG_CREATED",
                   INT2FIX(GPGME_STATUS_SIG_CREATED));
  rb_define_const (mGPGME, "GPGME_STATUS_SESSION_KEY",
                   INT2FIX(GPGME_STATUS_SESSION_KEY));
  rb_define_const (mGPGME, "GPGME_STATUS_NOTATION_NAME",
                   INT2FIX(GPGME_STATUS_NOTATION_NAME));
  rb_define_const (mGPGME, "GPGME_STATUS_NOTATION_DATA",
                   INT2FIX(GPGME_STATUS_NOTATION_DATA));
  rb_define_const (mGPGME, "GPGME_STATUS_POLICY_URL",
                   INT2FIX(GPGME_STATUS_POLICY_URL));
  rb_define_const (mGPGME, "GPGME_STATUS_BEGIN_STREAM",
                   INT2FIX(GPGME_STATUS_BEGIN_STREAM));
  rb_define_const (mGPGME, "GPGME_STATUS_END_STREAM",
                   INT2FIX(GPGME_STATUS_END_STREAM));
  rb_define_const (mGPGME, "GPGME_STATUS_KEY_CREATED",
                   INT2FIX(GPGME_STATUS_KEY_CREATED));
  rb_define_const (mGPGME, "GPGME_STATUS_USERID_HINT",
                   INT2FIX(GPGME_STATUS_USERID_HINT));
  rb_define_const (mGPGME, "GPGME_STATUS_UNEXPECTED",
                   INT2FIX(GPGME_STATUS_UNEXPECTED));
  rb_define_const (mGPGME, "GPGME_STATUS_INV_RECP",
                   INT2FIX(GPGME_STATUS_INV_RECP));
  rb_define_const (mGPGME, "GPGME_STATUS_NO_RECP",
                   INT2FIX(GPGME_STATUS_NO_RECP));
  rb_define_const (mGPGME, "GPGME_STATUS_ALREADY_SIGNED",
                   INT2FIX(GPGME_STATUS_ALREADY_SIGNED));
  rb_define_const (mGPGME, "GPGME_STATUS_SIGEXPIRED",
                   INT2FIX(GPGME_STATUS_SIGEXPIRED));
  rb_define_const (mGPGME, "GPGME_STATUS_EXPSIG",
                   INT2FIX(GPGME_STATUS_EXPSIG));
  rb_define_const (mGPGME, "GPGME_STATUS_EXPKEYSIG",
                   INT2FIX(GPGME_STATUS_EXPKEYSIG));
  rb_define_const (mGPGME, "GPGME_STATUS_TRUNCATED",
                   INT2FIX(GPGME_STATUS_TRUNCATED));
  rb_define_const (mGPGME, "GPGME_STATUS_ERROR",
                   INT2FIX(GPGME_STATUS_ERROR));
  /* These status codes have been available since 1.1.1. */
#ifdef GPGME_STATUS_PKA_TRUST_BAD
  rb_define_const (mGPGME, "GPGME_STATUS_PKA_TRUST_BAD",
                   INT2FIX(GPGME_STATUS_PKA_TRUST_BAD));
  rb_define_const (mGPGME, "GPGME_STATUS_PKA_TRUST_GOOD",
                   INT2FIX(GPGME_STATUS_PKA_TRUST_GOOD));
#endif
  /* These status codes were added in 1.5.0. */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
  rb_define_const (mGPGME, "GPGME_STATUS_PLAINTEXT_LENGTH",
                   INT2FIX(GPGME_STATUS_PLAINTEXT_LENGTH));
  rb_define_const (mGPGME, "GPGME_STATUS_MOUNTPOINT",
                   INT2FIX(GPGME_STATUS_MOUNTPOINT));
  rb_define_const (mGPGME, "GPGME_STATUS_PINENTRY_LAUNCHED",
                   INT2FIX(GPGME_STATUS_PINENTRY_LAUNCHED));
  rb_define_const (mGPGME, "GPGME_STATUS_ATTRIBUTE",
                   INT2FIX(GPGME_STATUS_ATTRIBUTE));
  rb_define_const (mGPGME, "GPGME_STATUS_BEGIN_SIGNING",
                   INT2FIX(GPGME_STATUS_BEGIN_SIGNING));
  rb_define_const (mGPGME, "GPGME_STATUS_KEY_NOT_CREATED",
                   INT2FIX(GPGME_STATUS_KEY_NOT_CREATED));
#endif

  /* The available keylist mode flags.  */
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_LOCAL",
                   INT2FIX(GPGME_KEYLIST_MODE_LOCAL));
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_EXTERN",
                   INT2FIX(GPGME_KEYLIST_MODE_EXTERN));
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_SIGS",
                   INT2FIX(GPGME_KEYLIST_MODE_SIGS));
  /* This flag was added in 1.1.1. */
#ifdef GPGME_KEYLIST_MODE_SIG_NOTATIONS
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_SIG_NOTATIONS",
                   INT2FIX(GPGME_KEYLIST_MODE_SIG_NOTATIONS));
#endif
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_VALIDATE",
                   INT2FIX(GPGME_KEYLIST_MODE_VALIDATE));
  /* This flag was added in 1.2.0. */
#ifdef GPGME_KEYLIST_MODE_EPHEMERAL
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_EPHEMERAL",
                   INT2FIX(GPGME_KEYLIST_MODE_EPHEMERAL));
#endif
  /* This flag was added in 1.5.1. */
#ifdef GPGME_KEYLIST_MODE_WITH_SECRET
  rb_define_const (mGPGME, "GPGME_KEYLIST_MODE_WITH_SECRET",
                   INT2FIX(GPGME_KEYLIST_MODE_WITH_SECRET));
#endif

  /* The available flags for status field of gpgme_import_status_t.  */
  rb_define_const (mGPGME, "GPGME_IMPORT_NEW", INT2FIX(GPGME_IMPORT_NEW));
  rb_define_const (mGPGME, "GPGME_IMPORT_UID", INT2FIX(GPGME_IMPORT_UID));
  rb_define_const (mGPGME, "GPGME_IMPORT_SIG", INT2FIX(GPGME_IMPORT_SIG));
  rb_define_const (mGPGME, "GPGME_IMPORT_SUBKEY",
                   INT2FIX(GPGME_IMPORT_SUBKEY));
  rb_define_const (mGPGME, "GPGME_IMPORT_SECRET",
                   INT2FIX(GPGME_IMPORT_SECRET));

  /* The available flags for gpgme_op_encrypt.  */
  rb_define_const (mGPGME, "GPGME_ENCRYPT_ALWAYS_TRUST",
                   INT2FIX(GPGME_ENCRYPT_ALWAYS_TRUST));
#ifdef HAVE_CONST_GPGME_ENCRYPT_NO_ENCRYPT_TO
  rb_define_const (mGPGME, "GPGME_ENCRYPT_NO_ENCRYPT_TO",
                   INT2FIX(GPGME_ENCRYPT_NO_ENCRYPT_TO));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_PREPARE
  rb_define_const (mGPGME, "GPGME_ENCRYPT_PREPARE",
                   INT2FIX(GPGME_ENCRYPT_PREPARE));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_EXPECT_SIGN
  rb_define_const (mGPGME, "GPGME_ENCRYPT_EXPECT_SIGN",
                   INT2FIX(GPGME_ENCRYPT_EXPECT_SIGN));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_NO_COMPRESS
  rb_define_const (mGPGME, "GPGME_ENCRYPT_NO_COMPRESS",
                   INT2FIX(GPGME_ENCRYPT_NO_COMPRESS));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_UNSIGNED_INTEGRITY_CHECK
  rb_define_const (mGPGME, "GPGME_ENCRYPT_UNSIGNED_INTEGRITY_CHECK",
                   INT2FIX(GPGME_ENCRYPT_UNSIGNED_INTEGRITY_CHECK));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_SYMMETRIC
  rb_define_const (mGPGME, "GPGME_ENCRYPT_SYMMETRIC",
                   INT2FIX(GPGME_ENCRYPT_SYMMETRIC));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_THROW_KEYIDS
  rb_define_const (mGPGME, "GPGME_ENCRYPT_THROW_KEYIDS",
                   INT2FIX(GPGME_ENCRYPT_THROW_KEYIDS));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_WRAP
  rb_define_const (mGPGME, "GPGME_ENCRYPT_WRAP",
                   INT2FIX(GPGME_ENCRYPT_WRAP));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_WANT_ADDRESS
  rb_define_const (mGPGME, "GPGME_ENCRYPT_WANT_ADDRESS",
                   INT2FIX(GPGME_ENCRYPT_WANT_ADDRESS));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_ARCHIVE
  rb_define_const (mGPGME, "GPGME_ENCRYPT_ARCHIVE",
                   INT2FIX(GPGME_ENCRYPT_ARCHIVE));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_FILE
  rb_define_const (mGPGME, "GPGME_ENCRYPT_FILE",
                   INT2FIX(GPGME_ENCRYPT_FILE));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_ADD_RECP
  rb_define_const (mGPGME, "GPGME_ENCRYPT_ADD_RECP",
                   INT2FIX(GPGME_ENCRYPT_ADD_RECP));
#endif
#ifdef HAVE_CONST_GPGME_ENCRYPT_CHG_RECP
  rb_define_const (mGPGME, "GPGME_ENCRYPT_CHG_RECP",
                   INT2FIX(GPGME_ENCRYPT_CHG_RECP));
#endif

  /* Random number generation mode flags added in 2.0.0 */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
  rb_define_const (mGPGME, "GPGME_RANDOM_MODE_NORMAL",
                   INT2FIX(GPGME_RANDOM_MODE_NORMAL));
  rb_define_const (mGPGME, "GPGME_RANDOM_MODE_ZBASE32",
                   INT2FIX(GPGME_RANDOM_MODE_ZBASE32));
#endif

  /* Decrypt flags added in 2.0.0 */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
  rb_define_const (mGPGME, "GPGME_DECRYPT_LISTONLY",
                   INT2FIX(GPGME_DECRYPT_LISTONLY));
#endif

  /* Key generation flags added in 2.0.0 */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x020000
  rb_define_const (mGPGME, "GPGME_CREATE_GROUP",
                   INT2FIX(GPGME_CREATE_GROUP));
#endif

  /* These flags were added in 1.4.0. */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010400
  rb_define_const (mGPGME, "GPGME_PINENTRY_MODE_DEFAULT",
                   INT2FIX(GPGME_PINENTRY_MODE_DEFAULT));
  rb_define_const (mGPGME, "GPGME_PINENTRY_MODE_ASK",
                   INT2FIX(GPGME_PINENTRY_MODE_ASK));
  rb_define_const (mGPGME, "GPGME_PINENTRY_MODE_CANCEL",
                   INT2FIX(GPGME_PINENTRY_MODE_CANCEL));
  rb_define_const (mGPGME, "GPGME_PINENTRY_MODE_ERROR",
                   INT2FIX(GPGME_PINENTRY_MODE_ERROR));
  rb_define_const (mGPGME, "GPGME_PINENTRY_MODE_LOOPBACK",
                   INT2FIX(GPGME_PINENTRY_MODE_LOOPBACK));
#endif

  /* These flags were added in 1.5.0. */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010500
  rb_define_const (mGPGME, "GPGME_SPAWN_DETACHED",
                   INT2FIX(GPGME_SPAWN_DETACHED));
  rb_define_const (mGPGME, "GPGME_SPAWN_ALLOW_SET_FG",
                   INT2FIX(GPGME_SPAWN_ALLOW_SET_FG));
#endif

  /* This flag was added in 1.2.0. */
#ifdef GPGME_EXPORT_MODE_EXTERN
  rb_define_const (mGPGME, "GPGME_EXPORT_MODE_EXTERN",
                   INT2FIX(GPGME_EXPORT_MODE_EXTERN));
#endif

  /* This flag was added in 1.3.0. */
#ifdef GPGME_EXPORT_MODE_MINIMAL
  rb_define_const (mGPGME, "GPGME_EXPORT_MODE_MINIMAL",
                   INT2FIX(GPGME_EXPORT_MODE_MINIMAL));
#endif

  /* These flags were added in 1.6.0. */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010600
  rb_define_const (mGPGME, "GPGME_EXPORT_MODE_SECRET",
                   INT2FIX(GPGME_EXPORT_MODE_SECRET));
  rb_define_const (mGPGME, "GPGME_EXPORT_MODE_RAW",
                   INT2FIX(GPGME_EXPORT_MODE_RAW));
  rb_define_const (mGPGME, "GPGME_EXPORT_MODE_PKCS12",
                   INT2FIX(GPGME_EXPORT_MODE_PKCS12));
#endif

/* These flags were added in 1.9.1. */
#if defined(GPGME_VERSION_NUMBER) && GPGME_VERSION_NUMBER >= 0x010901
  rb_define_const (mGPGME, "GPGME_DELETE_ALLOW_SECRET",
                   INT2FIX(GPGME_DELETE_ALLOW_SECRET));
  rb_define_const (mGPGME, "GPGME_DELETE_FORCE",
                   INT2FIX(GPGME_DELETE_FORCE));
#endif
}

