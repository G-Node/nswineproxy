
#include <nsWireProtocol.h>


#if defined (_WIN32)

#ifndef _WIN32_WINNT            
#define _WIN32_WINNT 0x0501 //Minimum requirement is: Windows Server 2003, Windows XP
#endif

#ifdef _MSC_VER
# define _POSIX_
#endif

#define WIN32_LEAN_AND_MEAN 
#include <tchar.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#else

#include <glib.h>
#include <arpa/inet.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#if defined(_WIN32)
#define g_malloc malloc
#define g_realloc realloc
#define g_free free

#ifndef MIN
#define MIN(_a, _b) (_a < _b ? _a : _b)
#endif

#else

#define _tprintf printf
#define TEXT(_txt) _txt
#define _TCHAR char
#endif


#define calc_offset(_mem, _struct_type) ((unsigned char *) _mem + sizeof (_struct_type))

static NsMsg *
ns_msg_new_plain (NsMsgType type, NsReqId req_id, NsMsgFlags flags)
{
  NsMsg *msg;

  msg = g_malloc (sizeof (NsMsg));
 
  NS_MSG_HEADER(msg).type   = type;
  NS_MSG_HEADER(msg).flags  = flags;
  NS_MSG_HEADER(msg).req_id = htons (req_id);

  msg->allocated = 0;
  msg->len = 0;
  msg->body = NULL;

  return msg;
}

NsMsg *
ns_msg_new_sized (NsMsgType type, NsReqId req_id, NsMsgFlags flags, size_t data_size)
{
  NsMsg *msg = NULL;
  size_t buffer_size;

  buffer_size = data_size;

  msg = ns_msg_new_plain (type, req_id, flags);

  msg->body = g_malloc (buffer_size);
  msg->allocated = buffer_size;
  msg->len = 0;
    
  return msg;
}

NsMsg *
ns_msg_new_call (NsReqId req_id, size_t body_size_est)
{
  NsMsg *msg;

  msg = ns_msg_new_sized (NS_MSG_TYPE_CALL, req_id, 0, body_size_est);

  return msg;
}

NsMsg *
ns_msg_new_reply (NsMsg *msg, size_t body_size_est)
{
  NsMsg *reply;
  NsReqId req_id;
  uint32 serial;

  req_id = ns_msg_get_req_id (msg);
  serial = ns_msg_get_serial (msg);

  reply = ns_msg_new_sized (NS_MSG_TYPE_REPLY, req_id, 0, body_size_est);

  ns_msg_set_serial (reply, serial);

  return reply;
}


NsMsg *
ns_msg_new_from_wire (void)
{
  NsMsg *msg;

  msg = g_malloc (sizeof (NsMsg));
  msg->sealed = TRUE;
  msg->body = NULL;
  msg->allocated = 0;
  msg->len = 0;

  return msg;
}

NsMsg *
ns_msg_new_error (NsMsg *call_msg, int32 error_id, const char *error_str)
{
  NsMsg   *error_msg;
  NsReqId  req_id = 0;
  uint32   serial = 0;
  size_t   body_size;
  size_t   str_size;

  if (call_msg != NULL) 
    {
      req_id = ns_msg_get_req_id (call_msg);
      serial = ns_msg_get_serial (call_msg);
      fprintf (stderr, "New Error msg! Serial: %u\n", serial);
    }

  str_size = error_str ? strlen (error_str) + 1 : 0;

  body_size = sizeof (int32) + str_size;
  error_msg = ns_msg_new_sized (NS_MSG_TYPE_ERROR, req_id, 0, body_size);

  ns_msg_set_serial (error_msg, serial);
  ns_msg_pack_int32 (error_msg, error_id);

  if (str_size)
    ns_msg_pack_string (error_msg, error_str, str_size);

  return error_msg;
}

/* 
 * ns_msg_body_read_from_wire:
 * 
 * Appends len bytes from buffer to the message body.
 * 
 * Returns: the number of remaining bytes to read from
 * the wire to complete the message body.
 */
size_t
ns_msg_body_read_from_wire (NsMsg      *msg,
			    const void *buffer,
			    size_t      len)
{
  size_t body_size;
  unsigned char *bufptr;
  
  body_size = ns_msg_get_body_size (msg);

  if (msg->body == NULL)
    msg->body = g_malloc (body_size);

  if (msg->len >= body_size)
    return 0;

  bufptr = (unsigned char *) msg->body;

  /* just a guard so that we are never ever
     write over buffer boundaries */
  len = MIN (len, body_size - msg->len);

  memcpy (bufptr + msg->len, buffer, len);
  msg->len += len;
  
  //fprintf (stderr, "+ ns_msg_body_read_from_wire: %u %u: %u\n", msg->len, len, body_size - msg->len);
  
  return body_size - msg->len;
}

void
ns_msg_free (NsMsg *msg)
{

  if (msg->body != NULL)
    g_free (msg->body);

  g_free (msg);
}

void
ns_msg_set_serial (NsMsg *msg, uint32 serial)
{
  NS_MSG_HEADER (msg).serial = htonl (serial);
}

uint32
ns_msg_get_serial (NsMsg *msg)
{
  return ntohl (NS_MSG_HEADER (msg).serial);
}

uint32
ns_msg_get_body_size (NsMsg *msg)
{
  uint32 res;
  
  if (msg->sealed == TRUE)
    res = ntohl (NS_MSG_HEADER (msg).size) - sizeof (NsMsgHeader);
  else
    res = msg->len;
  
  return res;
}


NsReqId
ns_msg_get_req_id (NsMsg *msg)
{
  return ntohs (NS_MSG_HEADER (msg).req_id);
}


void
ns_msg_set_req_id (NsMsg *msg, NsReqId req_id)
{
  NS_MSG_HEADER (msg).req_id = htons (req_id);
}

NsMsgType
ns_msg_get_msg_type (NsMsg *msg)
{
  return NS_MSG_HEADER (msg).type;
}


void *
ns_msg_prepare_for_io (NsMsg *msg, size_t *len)
{
  *len = msg->len;

  NS_MSG_HEADER (msg).size = htonl (msg->len + sizeof (NsMsgHeader));

  return msg->body;
}


static void
ns_msg_body_ensure_space (NsMsg *msg, uint32 space_request)
{
  size_t new_size;

  new_size = msg->len + space_request;

  //fprintf (stderr, "+ns_msg_ensure space: space_request: %u; new_size: %u, msg->allocated: %u\n",
  //	   space_request, new_size, msg->allocated);

  if (new_size > msg->allocated)
    {
      size_t new_buffer_size = msg->allocated > 0 ? (msg->allocated << 1) : 256;
      //fprintf (stderr, "Increasing buffer size: %u to %u\n", msg->allocated, new_buffer_size);
      msg->body = g_realloc (msg->body, new_buffer_size);    
      msg->allocated = new_buffer_size;
      
      if (msg->body == NULL)
	  fprintf (stderr, "CRITICAL: could not reallocate memory!\n");
    }

}

int
ns_msg_body_pack_raw (NsMsg  *msg,
		      void   *data,
		      size_t  len)
{
  unsigned char *bufptr;

  if (msg->sealed == TRUE)
    {
      fprintf (stderr, "ERROR: Trying to write to a sealed message");
      return -1;
    }

  ns_msg_body_ensure_space (msg, len);
  
  bufptr = msg->body;
  bufptr += msg->len;

  memcpy (bufptr, data, len);
  msg->len += len;
  return 0;
}

void *
ns_msg_pack_raw_start (NsMsg *msg, uint32 max_size_req)
{
  void *ret;
  ns_msg_body_ensure_space (msg, max_size_req + sizeof (uint32));
  ret = (void *) ((unsigned char *) msg->body + sizeof (uint32) + msg->len);
  //fprintf (stdout, "Pack raw start: %p, %p\n", msg->body, ret); 
  return ret;
}


int
ns_msg_pack_raw_finish (NsMsg *msg, uint32 actual_size_req)
{

  ns_msg_pack_uint32 (msg, actual_size_req);
  msg->len += actual_size_req;

  return msg->len;
}


void
ns_msg_pack_string (NsMsg      *msg,
		    const char *str,
		    int         len)
{
  char c = '\0';
  uint32 str_len;

  str_len = (len > 0 ? len : strlen (str)) + 1; /* NUL char */

  ns_msg_pack_uint32 (msg, str_len);

  ns_msg_body_pack_raw (msg, (void *) str, str_len);
  ns_msg_body_pack_raw (msg, (void *) &c, sizeof (char)); /* explicitly NUL terminate */
}

int
ns_msg_pack_uint8 (NsMsg *msg, uint8 value)
{
  int res;

  res = ns_msg_body_pack_raw (msg, &value, sizeof (uint8));
  return res;
}

int
ns_msg_pack_uint16 (NsMsg *msg, uint16 value)
{
  int res;

  res = ns_msg_body_pack_raw (msg, &value, sizeof (uint16));
  return res;
}

int
ns_msg_pack_uint32 (NsMsg *msg, uint32 value)
{
  int res;

  res = ns_msg_body_pack_raw (msg, &value, sizeof (uint32));

  return res;
}

int
ns_msg_pack_int32 (NsMsg *msg, int32 value)
{
  int res;

  res = ns_msg_body_pack_raw (msg, &value, sizeof (int32));

  return res;
}

int
ns_msg_pack_double (NsMsg *msg, double value)
{
  int res;

  res = ns_msg_body_pack_raw (msg, &value, sizeof (double));
  return res;
}


int
ns_msg_pack_poly (NsMsg *msg, NsTypeId first_type, ...)
{
  va_list  ap;
  NsTypeId cur_type;
  unsigned int   ui_val;
  int             i_val;
  //int32     i_val;
  double    d_val;
  unsigned int buf_len;
  char *buf_ptr;

  if (first_type == NS_TYPE_NONE)
    return 0;

  va_start (ap, first_type);
  
  cur_type = first_type;

  do {
    switch (cur_type)
      {
	
      case NS_TYPE_UINT8:
	ui_val = va_arg (ap, unsigned int);
	ns_msg_pack_uint8 (msg, (uint8) ui_val);
	break;

      case NS_TYPE_UINT16:
	ui_val = va_arg (ap, unsigned int);
	ns_msg_pack_uint16 (msg, (uint16) ui_val);
	break;

      case NS_TYPE_UINT32:
	ui_val = va_arg (ap, unsigned int);
	ns_msg_pack_uint32 (msg, (uint32) ui_val);
	break;

      case NS_TYPE_INT32:
	i_val = va_arg (ap, int);
	ns_msg_pack_int32 (msg, (int32) i_val);
	break;

      case NS_TYPE_DOUBLE:
	d_val = va_arg (ap, double);
	ns_msg_pack_double (msg, d_val);
	break;

      case NS_TYPE_CHAR_ARRAY:
	buf_len = va_arg (ap, unsigned int);
	buf_ptr = va_arg (ap, char *);

	ns_msg_pack_uint32 (msg, (uint32) buf_len);
	ns_msg_body_pack_raw (msg, buf_ptr, buf_len); /* FIXME: check error */
	break;

      default:
	fprintf (stderr, "ERROR: Unkown type: %u", cur_type);	
      }

    cur_type = va_arg (ap, unsigned int);
  } while (cur_type != NS_TYPE_NONE);

  va_end (ap);

  return msg->len;
}

int
ns_msg_read_poly (NsMsg *msg, NsTypeId first_type, ...)
{
  va_list  ap;
  NsTypeId cur_type;
  int pos;
  void *data_pos;
  uint8 ui8_val;
  uint32 i32_val;
  unsigned int buf_len;
  char *buf_ptr;
  
  if (first_type == NS_TYPE_NONE)
    return 0;

  va_start (ap, first_type);

  pos = 0;
  cur_type = first_type;

  do {
    switch (cur_type)
      {

      case NS_TYPE_INT32:
	data_pos = va_arg (ap, void *);
	i32_val = ns_msg_read_int32 (msg, &pos);
	*((int32 *) data_pos) = i32_val;
	break;

      case NS_TYPE_UINT8:
	data_pos = va_arg (ap, void *);
	ui8_val = ns_msg_read_uint8 (msg, &pos);
	*((uint8 *) data_pos) = ui8_val;
	break;

      case NS_TYPE_UINT16:
	data_pos = va_arg (ap, void *);
	*((uint16 *) data_pos) = ns_msg_read_uint16 (msg, &pos);	
	break;

      case NS_TYPE_UINT32:
	data_pos = va_arg (ap, void *);
	*((uint32 *) data_pos) = ns_msg_read_uint32 (msg, &pos);
	break;

      case NS_TYPE_DOUBLE:
	data_pos = va_arg (ap, void *);
	*((double *) data_pos) = ns_msg_read_double (msg, &pos);
	break;

      case NS_TYPE_CHAR_ARRAY:
	buf_len = va_arg (ap, unsigned int);
	buf_ptr = va_arg (ap, char *);

	ns_msg_read_string (msg, &pos, buf_ptr, buf_len); /* FIXME: check error */
	break;

      case NS_TYPE_ARRAY:
	data_pos = va_arg (ap, void *); /* to store the uin32 length*/
	buf_ptr = va_arg (ap, char *);
	buf_len = *((uint32 *) data_pos);
	*((uint32 *) data_pos) = ns_msg_read_string (msg, &pos, buf_ptr, buf_len);
	break;

      default:
	fprintf (stderr, "ERROR: Unkown type: %u", cur_type);
      }
    
    
    cur_type = va_arg (ap, uint32);
  } while (cur_type != NS_TYPE_NONE);

  va_end (ap);

  return 0;
}


static void *
ns_msg_body_peek_at (NsMsg *msg, int pos)
{
  size_t body_size;

  if (msg->body == NULL)
    return NULL;

  body_size = ns_msg_get_body_size (msg);

  if (body_size < pos)
    return NULL;


  return (void *) (((unsigned char *) msg->body) + pos);
}

uint8
ns_msg_read_uint8 (NsMsg *msg, int *pos)
{
  void *raw_data;
  uint8 value;

  raw_data = ns_msg_body_peek_at (msg, *pos);

  if (raw_data == NULL)
    {
      *pos = -1;
      return 0;
    }

  value = *(uint8 *) raw_data;
  *pos += sizeof (value);

  return value;
}

uint16
ns_msg_read_uint16 (NsMsg *msg, int *pos)
{
  void *raw_data;
  uint16 value;

  raw_data = ns_msg_body_peek_at (msg, *pos);

  if (raw_data == NULL)
    {
      *pos = -1;
      return 0;
    }

  value = *(uint16 *) raw_data;
  *pos += sizeof (value);

  return value;
}

uint32
ns_msg_read_uint32 (NsMsg *msg, int *pos)
{
  void *raw_data;
  uint32 value;

  raw_data = ns_msg_body_peek_at (msg, *pos);
  
  if (raw_data == NULL)
    {
      *pos = -1;
      return 0;
    }

  value = *(uint32 *) raw_data;
  *pos += sizeof (value);

  return value;
}

int32
ns_msg_read_int32 (NsMsg *msg, int *pos)
{
  void *raw_data;
  int32 value;

  raw_data = ns_msg_body_peek_at (msg, *pos);
  
  if (raw_data == NULL)
    {
      *pos = -1;
      return 0;
    }

  value = *(int32 *) raw_data;
  *pos += sizeof (value);

  return value;
}

double
ns_msg_read_double (NsMsg *msg, int *pos)
{
  void *raw_data;
  double value;

  raw_data = ns_msg_body_peek_at (msg, *pos);

  if (raw_data == NULL)
    {
      *pos = -1;
      return 0;
    }

  value = *(double *) raw_data;
  *pos += sizeof (value);

  return value;
}

ssize_t
ns_msg_read_string (NsMsg *msg, int *pos, char *buf, size_t len)
{

  uint32 msg_str_len;
  size_t max_to_read;
  void * msg_data;
  int    safe_pos;

  safe_pos = *pos;

  msg_str_len = ns_msg_read_uint32 (msg, &safe_pos);

  if (safe_pos < 0)
    {
      fprintf (stderr, "Error reading string: %d\n", safe_pos);
      *pos = safe_pos;
      return -1;
    }

  fprintf (stderr, "ns_msg_read_string: str lengths: %u, %u\n", msg_str_len, len);
  if (msg_str_len > len)
    return -2; /*don't modify pos here */

  *pos = safe_pos;

  max_to_read = MIN (msg_str_len, len);
  msg_data = ns_msg_body_peek_at (msg, *pos);

  if (msg_data == NULL)
    return -1;

  memcpy (buf, msg_data, max_to_read);

  *pos += max_to_read;

  return max_to_read;
}

char *
ns_msg_read_dup_string (NsMsg *msg, int *pos)
{
  uint32   msg_str_len;
  char    *buf;
  ssize_t  str_len;
  int      safe_pos;

  safe_pos = *pos;
  msg_str_len = ns_msg_read_uint32 (msg, &safe_pos);
   
  if (safe_pos == -1)
    {
      *pos = safe_pos;
      return NULL;
    }

  buf = g_malloc (sizeof (char) * msg_str_len);

  str_len = ns_msg_read_string (msg, pos, buf, msg_str_len);

  if (str_len < 0)
    {
      g_free (buf);
      buf = NULL;
    }

  return buf;
}


/* small helper */
int
ns_msg_is_error (NsMsg *msg)
{
  return ns_msg_get_msg_type (msg) == NS_MSG_TYPE_ERROR;
}


void
ns_msg_dump_header (NsMsg *msg)
{

  fprintf (stderr, TEXT("[size: %u |serial: %u |type: %hhu |flags: %hhu |req_id: %hu]\n"), 
	   (uint32) ntohl (NS_MSG_HEADER (msg).size),
	   (uint32) ntohl (NS_MSG_HEADER (msg).serial),
	    NS_MSG_HEADER (msg).type,
	    NS_MSG_HEADER (msg).flags,
	    ntohs (NS_MSG_HEADER (msg).req_id));
}

void
ns_msg_dump (NsMsg *msg)
{
  int i;
  uint32 size;
  char *ptr;
  char buf[17] = {0, };

  fprintf (stderr, "\n   - - - - - - - - - - - - - - \n");
  ns_msg_dump_header (msg);

  size = ns_msg_get_body_size (msg);
  fprintf (stderr, "  Body Size: %u\n", size);
  if (size == 0)
    {
      fprintf (stderr, "  No body\n");
      goto out;
    }

  ptr = ns_msg_body_peek_at (msg, 0);

  for (i = 0; i < size; i++)
    {    
      unsigned char c = ptr[i];

      if (i % 16 == 0)
        fprintf (stderr, " %3d: ", i);

      fprintf (stderr, "%02hhX ", c);

      if (isalnum (c))
	buf[i % 16] = c;
      else
	buf[i % 16] = '.';

      if (i % 16 == 15)
	{
	  fprintf (stderr, " | %s\n ", buf);
	  memset (buf, 0, sizeof (buf));
	}
      else if (i % 4 == 3)
	fprintf (stderr, " ");
    }

  if (buf[0] != '\0')
    fprintf (stderr, "%*s| %s\n ", 34 - strlen (buf), " ", buf);
  
  fprintf (stderr, "\n");
 out:
  fprintf (stderr, "   - - - - - - - - - - - - - -\n");
}

