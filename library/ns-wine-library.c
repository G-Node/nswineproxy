/*
 * Copyright © 2011 Christian Kellner <kellner@bio.lmu.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the licence, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Christian Kellner <kellner@bio.lmu.de>
 */

#include <glib.h>
#include <glib/gprintf.h>
#include <gio/gio.h>

#include <arpa/inet.h>
#include <string.h>

#include "ns-wine-library.h"

typedef struct _LibraryContext LibraryContext;
struct _LibraryContext {

  guint       listen_port;
  GMutex     *listen_lock;
  GCond      *listen_cond;
  gboolean    is_listening;
  GError     *error;

  GPrivate   *error_private;

  GHashTable *file_handle_map;
  GMutex     *file_handle_lock;
  GCond      *file_handle_cond;
  guint32     file_handle_count;

  GList      *floating_handles;
  gboolean    debug;
};


typedef struct _FileHandle FileHandle;
struct _FileHandle {

  LibraryContext *ctx;

  guint32         id;
  guint32         remote_id;
  char           *cookie;
  gboolean        is_ready;


  guint32         serial;
  GSocket        *sock;

  NsByteOrder     byteorder;
};


typedef struct _DllInfo DllInfo;
struct _DllInfo {
  const char *name;
  char       *location;
};

typedef struct _FTEntry FTEntry;
struct _FTEntry {
  const char *file_type;
  const char *dll_name;
};

static FTEntry known_file_types[] = {
  {"mcd", "nsMCDLibrary.dll"},
  {"plx", "nsPlxLibrary.dll"},
  {"map", "nsAOLibrary.dll" },
  {"nev", "nsNEVLibrary.dll"},
  {"nex", "NeuroExplorerNeuroShareLibrary.dll"},
  {NULL, }
};

static DllInfo dll_infos[] = {
  {"nsAOLibrary.dll",  NULL},
  {"nsMCDLibrary.dll", NULL},
  {"nsNEVLibrary.dll", NULL},
  {"nsPlxLibrary.dll", NULL},
  {"nsTDTLib.dll",     NULL},
  {"NeuroExplorerNeuroShareLibrary.dll", NULL},
  {NULL, NULL}
};


void initialize_library (void) __attribute__((constructor));

static char *
path_convert_to_win32 (const char *path)
{
  char **strv;
  char  *tmp;
  char  *path_converted;
  char  *tmp_path;

  if (path == NULL)
    return NULL;

  if (! g_path_is_absolute (path))
    {
      char *cur_dir;
      cur_dir = g_get_current_dir ();
      tmp_path = g_build_filename (cur_dir, path, NULL);
      g_free (cur_dir);
    }
  else
    tmp_path = (char *) path;

  strv = g_strsplit (tmp_path, "/", -1);
  tmp = g_build_pathv ("\\", strv);

  g_strfreev (strv);
  path_converted = g_strdup_printf ("Z:\\%s", tmp);
  g_free (tmp);

  if (tmp_path != path)
    g_free (tmp_path);
    
  return path_converted;
}

static char *
find_dll_by_name (const char *dll_name)
{
  char *home_loc;
  char *location;
  const char **c_iter;
  const char *c_dir;
  gboolean found;
  static const char *wkl[] = {
    "/usr/local/lib/neuroshare",
    "/usr/lib/neuroshare",
    NULL
  };

  location = NULL;
  c_iter = wkl;

  home_loc = g_build_filename (g_get_home_dir (), ".neuroshare", NULL);
  c_dir = home_loc;

  do {

    g_free (location);
    location = g_build_filename (c_dir, dll_name, NULL);
    found = g_file_test (location, G_FILE_TEST_EXISTS);

    c_dir = *c_iter++;

  } while (found == FALSE && c_dir != NULL);

  g_free (home_loc);


  return c_dir ? location : NULL;
}

static const char *
get_dll_for_file (const char *filename)
{
  FTEntry *iter;
  DllInfo *info;
  size_t len;
  char suffix[4] = {0, };

  if (filename == NULL)
    return NULL;

  
  len = strlen (filename);
  if (len < 3)
    return NULL;

  suffix[0] = filename[len - 3];
  suffix[1] = filename[len - 2];
  suffix[2] = filename[len - 1];

  for (iter = known_file_types; iter->file_type; iter++)
    {
      if (! g_ascii_strcasecmp (suffix, iter->file_type))
	break;
    }

  if (iter->file_type == NULL)
    return NULL;

  for (info = dll_infos; info->name; info++)
    {
     
      if (g_str_equal (info->name, iter->dll_name))
	break;
    }

  if (info->name == NULL)
    return NULL;

  return info->location;
}

static void
scan_for_libraries (LibraryContext *ctx)
{
  DllInfo *dll;

  if (G_UNLIKELY (ctx->debug))
    g_debug ("Scanning for dlls");

  for (dll = dll_infos; dll->name != NULL; dll++)
    {
      char *path, *win_path;
      
      path = find_dll_by_name (dll->name);
      win_path = path_convert_to_win32 (path);
      g_free (path);

      if (win_path == NULL)
	continue;

      dll->location = win_path;

       if (G_UNLIKELY (ctx->debug))
	 g_debug ("Found %s at %s\n", dll->name, dll->location);
    }
}

/* *************** */

static void
file_handle_set_socket (FileHandle *fh, GSocket *sock)
{
  LibraryContext *ctx;
  
  ctx = fh->ctx;

  g_mutex_lock (ctx->file_handle_lock);

  fh->sock = g_object_ref (sock);
  fh->is_ready = TRUE; //FIXME useless, use socket?

  g_cond_broadcast (ctx->file_handle_cond);
  g_mutex_unlock (ctx->file_handle_lock);

}

static gboolean
file_handle_wait_for_connection (FileHandle *fh,
				 GError     *error)
{
  LibraryContext *ctx;

  ctx = fh->ctx;

  g_mutex_lock (ctx->file_handle_lock);

  if (G_UNLIKELY (ctx->debug))
    g_debug ("Waiting for connection ... (%u)", fh->id);

  while (fh->is_ready == FALSE)
    g_cond_wait (ctx->file_handle_cond, ctx->file_handle_lock);

  g_mutex_unlock (ctx->file_handle_lock);

  if (G_UNLIKELY (ctx->debug))
    g_debug ("Connection now ready");

  return TRUE;
}
  
static void
file_handle_destroy (FileHandle *fh)
{
  LibraryContext *ctx;
  gboolean res;

  ctx = fh->ctx;
  
  g_mutex_lock (ctx->file_handle_lock);

  if (G_UNLIKELY (ctx->debug))
    g_debug ("Destroying Handle  (%u).", fh->id);
  
  res = g_hash_table_remove (ctx->file_handle_map, &(fh->id));

  if (res == FALSE)
    {
      g_warning ("Handle %d not removed!", fh->id);
    }

  g_socket_close (fh->sock, NULL); //FIXME: ignore errors?
  g_object_unref (fh->sock);

  g_free (fh->cookie);
  g_free (fh);

  g_mutex_unlock (ctx->file_handle_lock);
}

static uint32
file_handle_generate_serial (FileHandle *fh)
{
  return ++(fh->serial);
}

static FileHandle *
library_new_file_handle (LibraryContext *ctx, const char *filename)
{
  FileHandle *fh;

  fh = g_new0 (FileHandle, 1);

  g_mutex_lock (ctx->file_handle_lock);
  fh->ctx = ctx;

  fh->id = ++ctx->file_handle_count;
  fh->cookie = g_compute_checksum_for_string (G_CHECKSUM_MD5,
					      filename, -1);

  g_hash_table_insert (ctx->file_handle_map, &(fh->id), fh);
  g_mutex_unlock (ctx->file_handle_lock);

  if (G_UNLIKELY (ctx->debug))
    g_debug ("New FileHandle %p %u (%s)", fh, fh->id, fh->cookie);

  return fh;
}

static ns_RESULT
ns_result_from_error_msg (FileHandle *fh, NsMsg *error_msg)
{
  LibraryContext *ctx;
  ns_RESULT       ns_res;
  NsErrorId       error_id;
  char           *err_str;
  int             pos;

  ctx = fh->ctx;

  error_id = 0;

  pos = 0;
  error_id = ns_msg_read_int32 (error_msg, &pos);

  if (pos < 0)
    {
      g_private_set (ctx->error_private, (gpointer) g_strdup ("Internal Error"));
      return ns_LIBERROR;
    }

  if (error_id < 0)
    ns_res = error_id;
  else
     ns_res = ns_LIBERROR;
     /* FIXME: appropriate error id or do it in the slave? */

  err_str = ns_msg_read_dup_string (error_msg, &pos);

  if (err_str == NULL)
    g_private_set (ctx->error_private, (gpointer) g_strdup ("Unkown Error"));
  else
    g_private_set (ctx->error_private, (gpointer) err_str);

  return ns_res;
}

static FileHandle *
library_lookup_file_handle (LibraryContext *ctx, guint32 id)
{
  FileHandle *fh;

  g_mutex_lock (ctx->file_handle_lock);
  fh = g_hash_table_lookup (ctx->file_handle_map, &id);
    
  g_mutex_unlock (ctx->file_handle_lock);
  return fh;
}

static gboolean
fh_cookie_finder (gpointer key,
		  gpointer value,
		  gpointer user_data)
{
  FileHandle *fh = value;
  char *cookie = user_data;

  return g_str_equal (fh->cookie, cookie);
}

static FileHandle *
library_lookup_file_handle_by_cookie (LibraryContext *ctx,
				      const char     *cookie)
{
  FileHandle *fh;

  g_mutex_lock (ctx->file_handle_lock);

  fh = g_hash_table_find (ctx->file_handle_map,
			  fh_cookie_finder,
			  (gpointer) cookie);
    
  g_mutex_unlock (ctx->file_handle_lock);

  return fh;
}

static gboolean
socket_receive_all (GSocket *sock, void *buffer, gsize len, GError **error)
{
  unsigned char *bufptr;
  size_t  to_read;

  bufptr = buffer;
  to_read = len;

  while (to_read > 0)
    {
      gssize n;

      n = g_socket_receive (sock,
			    (void *) bufptr,
			    to_read,
			    NULL,
			    error);

      if (n < 1)
	return FALSE;
      
      bufptr += n;
      to_read -= n;
    }
 
  return TRUE;
}


static NsMsg *
socket_receive_message (GSocket *sock, GError **error)
{
  NsMsg  *msg;
  gsize   n_left;
  gboolean res;

  msg = ns_msg_new_from_wire ();

  res = socket_receive_all (sock,
			    (void *) msg,
			    sizeof (NsMsgHeader),
			    error);

  if (res == FALSE)
    {
      ns_msg_free (msg);
      return NULL;
    }

  n_left =  ns_msg_get_body_size (msg);
 
  while (n_left > 0) 
    {
      gssize n;      
      gsize  to_read;
      char   buf[4096] = {0, };
      
      to_read = MIN (n_left, sizeof (buf));

      n = g_socket_receive (sock,
			    (void *) buf,
			    to_read,
			    NULL,
			    error);
      
      if (n < 0)
	{
	  ns_msg_free (msg);
	  return NULL;
	}
     
      n_left = ns_msg_body_read_from_wire (msg, buf, (size_t) n);

    }

  return msg;
}

static gboolean
socket_send_all (GSocket *sock, void *buffer, gsize len, GError **error)
{
  const char *bufptr;
  size_t to_send;
  gssize n;

  if (len == 0)
    return TRUE;

  to_send = len;
  bufptr = (const char *) buffer;

  
  while (to_send > 0) {
    n = g_socket_send (sock, bufptr, to_send, NULL, error);

    if (n <= 0)
      return FALSE; /* FIXME: check EINTR ?? */
    
    to_send -= n;
    bufptr += n;
  }

  return TRUE;
}

static gboolean
filehandle_send_message (FileHandle *fh, NsMsg *msg, GError **error)
{
  gboolean  res;
  void     *body_data;
  size_t    len;
  uint32    serial;
  GSocket  *sock;

  sock = fh->sock;


  serial = file_handle_generate_serial (fh);

  ns_msg_set_serial (msg, serial);

  body_data = ns_msg_prepare_for_io (msg, &len);

  res = socket_send_all (sock, msg, sizeof (NsMsgHeader), error);

  if (res == FALSE)
    return res;

  res = socket_send_all (sock, body_data, len, error);

  return res;
}

static NsMsg *
filehandle_send_and_receive (FileHandle *fh, NsMsg *msg_call, GError **error)
{
  NsMsg *reply;
  gboolean res;
  uint32 serial_msg;
  uint32 serial_reply;

  /* FIXME: XXX guard by lock to make MT save */

  res = filehandle_send_message (fh, msg_call, error);
  if (res == FALSE)
    return NULL;

  reply = socket_receive_message (fh->sock, error);

  if (reply == NULL)
    {
      g_warning ("Did not receive a reply");
      return NULL;
    }

  serial_msg = ns_msg_get_serial (msg_call);
  serial_reply = ns_msg_get_serial (reply);

  if (serial_msg != serial_reply)
    {
      g_error ("Serial numbers of call and reply do not match");
    }

  return reply;
}

static gboolean
connection_do_handshake (LibraryContext *ctx, GSocket *sock, GError **error)
{
  NsMsg *msg;
  FileHandle *fh;
  char *cookie;
  int pos;

  msg = socket_receive_message (sock, error);

  if (msg == NULL)
    return FALSE;

  //ns_msg_dump (msg);
  pos = 0;

  cookie = ns_msg_read_dup_string (msg, &pos);

  fh = library_lookup_file_handle_by_cookie (ctx, cookie);
  if (fh == NULL)
    {
      g_warning ("Unkown file handle!");
      return FALSE;
    }

  file_handle_set_socket (fh, sock);

  return TRUE;
}

static gpointer
listener_loop (gpointer user_data)
{
  LibraryContext     *ctx;
  GSocket            *sock;
  GSocket            *client;
  GError             *error;
  GSocketAddress     *listen_address;
  GInetSocketAddress *inet_sock_addr;;
  GInetAddress       *loopback;
  gboolean            res;

  ctx = (LibraryContext *) user_data;

  g_mutex_lock (ctx->listen_lock);

  sock = g_socket_new (G_SOCKET_FAMILY_IPV4,
		       G_SOCKET_TYPE_STREAM,
		       G_SOCKET_PROTOCOL_TCP,
		       &error);

  if (sock == NULL) {
    g_error ("Error creating socket: %s\n", error->message);
  }
  
  loopback = g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  listen_address = g_inet_socket_address_new (loopback, 0);
  
  res = g_socket_bind (sock, listen_address, TRUE, &error);
  if (res == FALSE) {
    g_error ("Error binding socket: %s\n", error->message);
  }
  
  res = g_socket_listen (sock, &error);
  if (res == FALSE) {
    g_error ("Error creating listening socket: %s\n", error->message);
  }
  
  inet_sock_addr = G_INET_SOCKET_ADDRESS (g_socket_get_local_address (sock, &error));
  
  ctx->is_listening = TRUE;
  ctx->listen_port = g_inet_socket_address_get_port (inet_sock_addr);

  /* signal we are done */
  g_cond_signal (ctx->listen_cond);
  g_mutex_unlock (ctx->listen_lock);

  if (G_UNLIKELY (ctx->debug))
    g_debug ("Waiting for slaves to connecto to port %u", ctx->listen_port);

  while ((client = g_socket_accept (sock, NULL, &error))) {
    GError      *cli_error = NULL;

    if (G_UNLIKELY (ctx->debug))
      g_debug ("New Client");

    res = connection_do_handshake (ctx, client, &cli_error);
    
    if (G_UNLIKELY (ctx->debug))
      g_debug ("\tHandshake %s", res ? "succeeded" : "failed");

    g_object_unref (client);
  }

  if (G_UNLIKELY (ctx->debug))
    g_debug ("Done listening!\n");

  return NULL;
}

static void
error_private_free (gpointer data)
{
  /* Currently just a string, maybe changed later */
  g_free (data); 
}

void
initialize_library (void)
{
  if (!g_thread_supported ())
    g_thread_init (NULL);
  
  g_type_init ();
}

static gpointer
initialize_library_context (gpointer user_data)
{
  LibraryContext *ctx;
  GThread        *listener_thread;
  GError         *error = NULL;
  const char     *debug_env;

  ctx = g_new0 (LibraryContext, 1);

  debug_env = g_getenv ("NS_LIB_DEBUG");
  if (debug_env)
    ctx->debug = TRUE;

  scan_for_libraries (ctx);

  g_assert (NS_CHECK_HDR_ALIGNMENT());

  /* Per thread error message storage */
  ctx->error_private = g_private_new (error_private_free);

  /* Guards for the file handle map */
  ctx->file_handle_lock = g_mutex_new ();
  ctx->file_handle_cond = g_cond_new ();
  ctx->file_handle_map = g_hash_table_new (g_int_hash, g_int_equal);

  /* Initialise our listening socket */

  ctx->listen_lock = g_mutex_new ();
  ctx->listen_cond = g_cond_new ();
  
  listener_thread = g_thread_create (listener_loop, ctx, FALSE, &error);

  g_mutex_lock (ctx->listen_lock);
  
  while (ctx->is_listening == FALSE)
    g_cond_wait (ctx->listen_cond, ctx->listen_lock);

  g_mutex_unlock (ctx->listen_lock);

  return ctx;
}

static LibraryContext *
get_library_context (void)
{
  static GOnce init_ctx_once = G_ONCE_INIT;

  g_once (&init_ctx_once, initialize_library_context, NULL);

  return init_ctx_once.retval;
}



ns_RESULT
ns_GetLibraryInfo (ns_LIBRARYINFO *LibraryInfo, uint32 LibraryInfoSize)
{

  LibraryContext *ctx;

  g_return_val_if_fail (sizeof (ns_LIBRARYINFO) == LibraryInfoSize, ns_LIBERROR);

  g_snprintf (LibraryInfo->szCreator, 64, "ICNF G-Node - http://www.gnode.org");
  g_snprintf (LibraryInfo->szDescription, 64, "Neuroshare Wine Proxy Library");
  
  LibraryInfo->dwAPIVersionMaj = 1;
  LibraryInfo->dwAPIVersionMin = 3;
  
  LibraryInfo->dwLibVersionMaj = 0;
  LibraryInfo->dwLibVersionMin = 1;

  LibraryInfo->dwTime_Year = 2011;
  LibraryInfo->dwTime_Month = 1;
  LibraryInfo->dwTime_Day = 1;
  LibraryInfo->dwFlags = 0;
  LibraryInfo->dwMaxFiles = 256;
  LibraryInfo->dwFileDescCount = 0;

  ctx = get_library_context ();
  g_debug ("Listening port: %u",  ctx->listen_port);

  return ns_OK;
}

ns_RESULT
ns_OpenFile (char *filename, uint32 *file_id)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  GSpawnFlags     spawn_flags;
  char           *port_str;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res = ns_OK;
  uint32          remote_id;
  char           *path_win32;
  const char     *dll_location;
  gboolean        res;
  GPid            child_pid;
  GError         *error = NULL;
  char           *argv[5] = {0, };

  /* Must be first call since it does all the setup */
  ctx = get_library_context ();

  dll_location = get_dll_for_file (filename);
  if (dll_location == NULL)
    {
      /* FIXME: set last error */
      return ns_LIBERROR;
    }

  fh = library_new_file_handle (ctx, filename);

  spawn_flags = G_SPAWN_SEARCH_PATH;
  if (ctx->debug == FALSE)
    {
      spawn_flags |= G_SPAWN_STDERR_TO_DEV_NULL | 
	             G_SPAWN_STDOUT_TO_DEV_NULL;
    }

  argv[0] = (char *) "wine";
  argv[1] = (char *) NS_LIBS_DIR "/nswineslave";
  argv[2] = port_str = g_strdup_printf ("%u", ctx->listen_port);
  argv[3] = fh->cookie;
  argv[4] = NULL;
  
  res = g_spawn_async (NULL, /* wdir */
		       argv /*argvp*/,
		       NULL, /*envp*/
		       spawn_flags,
		       NULL,
		       NULL,
		       &child_pid,
		       &error);

  g_free (port_str);

  if (res == FALSE) {
    g_fprintf (stderr, "Error spawing child %s\n", error->message);
  }
  
  res = file_handle_wait_for_connection (fh, NULL);

  if (res == FALSE) {
    return ns_LIBERROR;
  }

  *file_id = fh->id;

  /* Ok, all set up: Now to the real deal */
  /* Load the library */
  msg = ns_msg_new_call (NS_REQ_LOAD_LIB, 0);
  ns_msg_pack_string (msg, dll_location, -1);

  reply = filehandle_send_and_receive (fh, msg, NULL);

  if (res == FALSE)
    return ns_LIBERROR;

  ns_msg_free (msg);

  if (ns_msg_is_error (reply))
    {
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_free (reply);

  /* library successfully loaded, now open the file */

  msg = ns_msg_new_call (NS_REQ_NS_OPEN_FILE, 0);
  path_win32 = path_convert_to_win32 (filename);
  ns_msg_pack_string (msg, path_win32, -1);
  g_free (path_win32);

  reply = filehandle_send_and_receive (fh, msg, NULL);

  if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply, NS_TYPE_UINT32, &remote_id, NS_TYPE_NONE);

  fh->remote_id = remote_id;

  return ns_OK;
}

ns_RESULT
ns_CloseFile (uint32 file_id)
{
  LibraryContext *ctx;
  FileHandle *fh;
  
  ctx = get_library_context ();
  
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    {
      return ns_BADFILE;
    }

  file_handle_destroy (fh);

  return ns_OK;
}

ns_RESULT
ns_GetFileInfo (uint32 file_id, ns_FILEINFO *FileInfo, uint32 FileInfoSize)
{
  LibraryContext *ctx;
  FileHandle *fh;
  NsMsg *msg, *reply;
  ns_RESULT ns_res;

  if (sizeof (ns_FILEINFO) != FileInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;

  msg = ns_msg_new_call (NS_REQ_NS_GET_FILE_INFO, 0);
  ns_msg_pack_uint32 (msg, fh->remote_id);

  reply = filehandle_send_and_receive (fh, msg, NULL);

  if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_CHAR_ARRAY, 32, FileInfo->szFileType, 
		    NS_TYPE_UINT32, &FileInfo->dwEntityCount,
		    NS_TYPE_DOUBLE, &FileInfo->dTimeStampResolution,
		    NS_TYPE_DOUBLE, &FileInfo->dTimeSpan,
		    NS_TYPE_CHAR_ARRAY, 64, FileInfo->szAppName,
		    NS_TYPE_UINT32, &FileInfo->dwTime_Year,
		    NS_TYPE_UINT32, &FileInfo->dwTime_Month,
		    NS_TYPE_UINT32, &FileInfo->dwTime_DayofWeek,
		    NS_TYPE_UINT32, &FileInfo->dwTime_Day,
		    NS_TYPE_UINT32, &FileInfo->dwTime_Hour,
		    NS_TYPE_UINT32, &FileInfo->dwTime_Min,
		    NS_TYPE_UINT32, &FileInfo->dwTime_Sec,
		    NS_TYPE_UINT32, &FileInfo->dwTime_MilliSec,
		    NS_TYPE_CHAR_ARRAY, 256, FileInfo->szFileComment,
		    NS_TYPE_NONE);

  return ns_OK;
}


ns_RESULT
ns_GetEntityInfo (uint32         file_id,
		  uint32         EntityID,
		  ns_ENTITYINFO *EntityInfo,
		  uint32         EntityInfoSize)
{
  LibraryContext *ctx;
  FileHandle *fh;
  NsMsg *msg, *reply;
  ns_RESULT ns_res;

  if (sizeof (ns_ENTITYINFO) != EntityInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_ENTITY_INFO, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_CHAR_ARRAY, 32, EntityInfo->szEntityLabel,
		    NS_TYPE_UINT32, &EntityInfo->dwEntityType,
		    NS_TYPE_UINT32, &EntityInfo->dwItemCount,
		    NS_TYPE_NONE);
  return ns_OK;
}


ns_RESULT
ns_GetEventInfo (uint32        file_id,
		 uint32        EntityID,
		 ns_EVENTINFO *EventInfo,
		 uint32        EventInfoSize)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  if (sizeof (ns_EVENTINFO) != EventInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_EVENT_INFO, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_UINT32, &EventInfo->dwEventType,
		    NS_TYPE_UINT32, &EventInfo->dwMinDataLength,
		    NS_TYPE_UINT32, &EventInfo->dwMaxDataLength,
		    NS_TYPE_CHAR_ARRAY, 128, EventInfo->szCSVDesc,
		    NS_TYPE_NONE);

  return ns_OK;
}


ns_RESULT
ns_GetEventData (uint32  file_id,
		 uint32  EntityID,
		 uint32  nIndex,
		 double *TimeStamp,
		 void   *Data,
		 uint32  DataSize, 
		 uint32 *DataRetSize)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_EVENT_DATA, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_UINT32, nIndex,
		    NS_TYPE_UINT32, DataSize,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  *DataRetSize = DataSize;

  ns_msg_read_poly (reply,
		    NS_TYPE_ARRAY, DataRetSize, Data,
		    NS_TYPE_DOUBLE, TimeStamp,
		    NS_TYPE_NONE);

  return ns_OK;
}


ns_RESULT
ns_GetAnalogInfo (uint32        file_id,
		 uint32         EntityID,
		 ns_ANALOGINFO *AnalogInfo,
		 uint32         AnalogInfoSize)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  if (sizeof (ns_ANALOGINFO) != AnalogInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_ANALOG_INFO, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_DOUBLE, &AnalogInfo->dSampleRate,
		    NS_TYPE_DOUBLE, &AnalogInfo->dMinVal,
		    NS_TYPE_DOUBLE, &AnalogInfo->dMaxVal,
		    NS_TYPE_CHAR_ARRAY, 16, AnalogInfo->szUnits,
		    NS_TYPE_DOUBLE, &AnalogInfo->dResolution,
		    NS_TYPE_DOUBLE, &AnalogInfo->dLocationX,
		    NS_TYPE_DOUBLE, &AnalogInfo->dLocationY,
		    NS_TYPE_DOUBLE, &AnalogInfo->dLocationZ,
		    NS_TYPE_DOUBLE, &AnalogInfo->dLocationUser,
		    NS_TYPE_DOUBLE, &AnalogInfo->dHighFreqCorner,
		    NS_TYPE_UINT32, &AnalogInfo->dwHighFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, AnalogInfo->szHighFilterType,
		    NS_TYPE_DOUBLE, &AnalogInfo->dLowFreqCorner,
		    NS_TYPE_UINT32, &AnalogInfo->dwLowFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, AnalogInfo->szLowFilterType,
		    NS_TYPE_CHAR_ARRAY, 128, AnalogInfo->szProbeInfo,
		    NS_TYPE_NONE);

  return ns_OK;
}

ns_RESULT ns_GetAnalogData (uint32  file_id,
			    uint32  EntityID,
			    uint32  StartIndex,
			    uint32  IndexCount, 
			    uint32 *ContCount,
			    double *Data)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  ns_RESULT       ns_res;
  NsMsg          *msg;
  NsMsg          *reply;
  uint32          DataRetSize;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    {
      g_private_set (ctx->error_private, (gpointer) "File Handle not found!");
      return ns_BADFILE;
    }

  msg = ns_msg_new_call (NS_REQ_NS_GET_ANALOG_DATA, 0);

  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_UINT32, StartIndex,
		    NS_TYPE_UINT32, IndexCount,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  DataRetSize = sizeof (double) * IndexCount;

  ns_msg_read_poly (reply,
		    NS_TYPE_ARRAY, &DataRetSize, Data,
		    NS_TYPE_UINT32, ContCount,
		    NS_TYPE_NONE);

  return ns_OK;
}

ns_RESULT
ns_GetSegmentInfo (uint32          file_id,
		   uint32          EntityID,
		   ns_SEGMENTINFO *SegmentInfo,
		   uint32          SegmentInfoSize)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  if (sizeof (ns_SEGMENTINFO) != SegmentInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_SEGMENT_INFO, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_UINT32, &SegmentInfo->dwSourceCount,
		    NS_TYPE_UINT32, &SegmentInfo->dwMinSampleCount,
		    NS_TYPE_UINT32, &SegmentInfo->dwMaxSampleCount,
		    NS_TYPE_DOUBLE, &SegmentInfo->dSampleRate,
		    NS_TYPE_CHAR_ARRAY, 32, SegmentInfo->szUnits,
		    NS_TYPE_NONE);
 
  return ns_OK;
}

ns_RESULT
ns_GetSegmentSourceInfo (uint32            file_id,
			 uint32            EntityID,
			 uint32            SourceID,
			 ns_SEGSOURCEINFO *SourceInfo,
			 uint32            SourceInfoSize)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  if (sizeof (ns_SEGSOURCEINFO) != SourceInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_SEGSRC_INFO, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_UINT32, SourceID,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_DOUBLE, &SourceInfo->dMinVal,
		    NS_TYPE_DOUBLE, &SourceInfo->dMaxVal,
		    NS_TYPE_DOUBLE, &SourceInfo->dResolution,
		    NS_TYPE_DOUBLE, &SourceInfo->dSubSampleShift,
		    NS_TYPE_DOUBLE, &SourceInfo->dLocationX,
		    NS_TYPE_DOUBLE, &SourceInfo->dLocationY,
		    NS_TYPE_DOUBLE, &SourceInfo->dLocationZ,
		    NS_TYPE_DOUBLE, &SourceInfo->dLocationUser,
		    NS_TYPE_DOUBLE, &SourceInfo->dHighFreqCorner,
		    NS_TYPE_UINT32, &SourceInfo->dwHighFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, SourceInfo->szHighFilterType,
		    NS_TYPE_DOUBLE, &SourceInfo->dLowFreqCorner,
		    NS_TYPE_UINT32, &SourceInfo->dwLowFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, SourceInfo->szLowFilterType,
		    NS_TYPE_CHAR_ARRAY, 128, SourceInfo->szProbeInfo,
		    NS_TYPE_NONE);

  return ns_OK;
}

ns_RESULT ns_GetSegmentData (uint32  file_id,
			     uint32  EntityID,
			     uint32  Index,
			     double *TimeStamp,
			     double *Data,
			     uint32  DataBufferSize,
			     uint32 *SampleCount,
			     uint32 *UnitID)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  ns_RESULT       ns_res;
  uint32          DataRetSize;
  NsMsg          *msg;
  NsMsg          *reply;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_SEGMENT_DATA, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_UINT32, Index,
		    NS_TYPE_UINT32, DataBufferSize,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  DataRetSize = DataBufferSize;

  ns_msg_read_poly (reply,
		    NS_TYPE_ARRAY, &DataRetSize, Data,
		    NS_TYPE_DOUBLE, TimeStamp,
		    NS_TYPE_UINT32, SampleCount,
		    NS_TYPE_UINT32, UnitID,
		    NS_TYPE_NONE);

  return ns_OK;
}

ns_RESULT
ns_GetNeuralInfo (uint32         file_id,
		  uint32         EntityID,
		  ns_NEURALINFO *NeuralInfo,
		  uint32         NeuralInfoSize)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  if (sizeof (ns_NEURALINFO) != NeuralInfoSize)
    return ns_LIBERROR;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_NEURAL_INFO, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply,
		    NS_TYPE_UINT32, &NeuralInfo->dwSourceEntityID,
		    NS_TYPE_UINT32, &NeuralInfo->dwSourceUnitID,
		    NS_TYPE_CHAR_ARRAY, 128, NeuralInfo->szProbeInfo,
		    NS_TYPE_NONE);
 
  return ns_OK;
}


ns_RESULT ns_GetNeuralData (uint32  file_id,
			    uint32  EntityID,
			    uint32  StartIndex,
			    uint32  IndexCount,
			    double *Data)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  ns_RESULT       ns_res;
  NsMsg          *msg;
  NsMsg          *reply;
  uint32          DataRetSize;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_NEURAL_DATA, 0);
  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_UINT32, StartIndex,
		    NS_TYPE_UINT32, IndexCount,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  DataRetSize = sizeof (double) * IndexCount;

  ns_msg_read_poly (reply,
		    NS_TYPE_ARRAY, &DataRetSize, Data,
		    NS_TYPE_NONE);

  return ns_OK;
}

ns_RESULT
ns_GetTimeByIndex (uint32  file_id,
		   uint32  EntityID,
		   uint32  Index,
		   double *Time)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_TIME_BY_INDEX, 0);

  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_UINT32, Index,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply, NS_TYPE_DOUBLE, &Time);

  return ns_OK;
}

ns_RESULT
ns_GetIndexByTime (uint32  file_id,
		   uint32  EntityID,
		   double  Time,
		   int32   Flags,
		   uint32  *Index)
{
  LibraryContext *ctx;
  FileHandle     *fh;
  NsMsg          *msg;
  NsMsg          *reply;
  ns_RESULT       ns_res;

  ctx = get_library_context ();
  fh = library_lookup_file_handle (ctx, file_id);

  if (fh == NULL)
    return ns_BADFILE;
  
  msg = ns_msg_new_call (NS_REQ_NS_GET_INDEX_BY_TIME, 0);

  ns_msg_pack_poly (msg,
		    NS_TYPE_UINT32, fh->remote_id,
		    NS_TYPE_UINT32, EntityID,
		    NS_TYPE_DOUBLE, Time,
		    NS_TYPE_INT32,  Flags,
		    NS_TYPE_NONE);

  reply = filehandle_send_and_receive (fh, msg, NULL);
  
   if (reply == NULL)
    return ns_LIBERROR;

  if (ns_msg_is_error (reply))
    {
      ns_msg_free (msg);
      ns_res = ns_result_from_error_msg (fh, reply);
      ns_msg_free (reply);
      return ns_res;
    }

  ns_msg_read_poly (reply, NS_TYPE_DOUBLE, &Index);

  return ns_OK;
}


ns_RESULT
ns_GetLastErrorMsg (char   *MsgBuffer,
		    uint32  MsgBufferSize)
{

  LibraryContext *ctx;
  char *err_str;
  gsize max_chars;

  ctx = get_library_context ();

  err_str = g_private_get (ctx->error_private);

  max_chars = MIN (MsgBufferSize, err_str ? strlen (err_str) : 0);
  memcpy (MsgBuffer, err_str, max_chars);

  return ns_OK;
}

