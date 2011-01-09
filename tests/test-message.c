
#if defined (_WIN32)

# ifndef _WIN32_WINNT            
#  define _WIN32_WINNT 0x0501 //Minimum requirement is: Windows Server 2003, Windows XP
# endif

# ifdef _MSC_VER
#  define _POSIX_
# endif

# define WIN32_LEAN_AND_MEAN 
# include <tchar.h>

# include <winsock2.h>
# include <ws2tcpip.h>

# include <windows.h>

#else
# include <glib.h>
# include <glib/gprintf.h>
# include <arpa/inet.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#include <nsWireProtocol.h>

static int
test_message ()
{
  NsMsg  *msg;
  NsMsg  *reply;
  size_t  len;

  msg = ns_msg_new_sized (NS_MSG_TYPE_CALL, NS_REQ_HANDSHAKE, 0, 0);
  assert (msg);

  assert (NS_MSG_HEADER (msg).type == NS_MSG_TYPE_CALL);
  assert (NS_MSG_HEADER (msg).flags == 0);
  assert (NS_MSG_HEADER (msg).req_id = htons (NS_REQ_HANDSHAKE));

  assert (msg->len == 0);
  assert (msg->sealed == FALSE);

  ns_msg_set_serial (msg, 42);
  assert (ntohl (NS_MSG_HEADER (msg).serial) == 42);
  assert (ns_msg_get_serial (msg) == 42);

  ns_msg_pack_uint32 (msg, 42);
  assert (ns_msg_get_body_size (msg) == sizeof (uint32));

  ns_msg_prepare_for_io (msg, &len);
  assert (ns_msg_get_body_size (msg) == sizeof (uint32));
  assert (ntohl (NS_MSG_HEADER (msg).size) == (sizeof (uint32) + sizeof (NsMsgHeader)));

  reply = ns_msg_new_reply (msg, 0);
  
  assert (ns_msg_get_serial (msg) == ns_msg_get_serial (reply));
  assert (ns_msg_get_req_id (msg) == ns_msg_get_req_id (reply));

  ns_msg_dump (msg);

  ns_msg_free (msg);
  ns_msg_free (reply);
  return 1;
}

static NsMsg *
pack_message_poly (int32   test_int32,
		   uint8   test_uint8,
		   uint16  test_uint16,
		   uint32  test_uint32,
		   double  test_double,
		   const char *buf)
{
  NsMsg  *msg;

  msg = ns_msg_new_sized (NS_MSG_TYPE_CALL, NS_REQ_HANDSHAKE, 0, 0);

  ns_msg_pack_poly (msg,
		    NS_TYPE_INT32, test_int32,
		    NS_TYPE_UINT8, test_uint8,
		    NS_TYPE_UINT16, test_uint16,
		    NS_TYPE_UINT32, test_uint32,
		    NS_TYPE_DOUBLE, test_double,
		    NS_TYPE_CHAR_ARRAY, strlen (buf) + 1, buf,
		    NS_TYPE_NONE);

  //g_fprintf (stderr, "Packing:\n\t uint8: %p| uint16: %p", &test_uint8, &test_uint16);
  g_fprintf (stderr, "Packing (poly):\n\t %d, %hhu, %hu, %u, %lf %s\n", test_int32,
	     test_uint8, test_uint16, test_uint32, test_double, buf);
  return msg;
}

static NsMsg *
pack_message_single (int32   test_int32,
		     uint8   test_uint8,
		     uint16  test_uint16,
		     uint32  test_uint32,
		     double  test_double,
		     const char *buf)
{
  NsMsg  *msg;

  msg = ns_msg_new_sized (NS_MSG_TYPE_CALL, NS_REQ_HANDSHAKE, 0, 0);

  ns_msg_pack_int32 (msg, test_int32);
  ns_msg_pack_uint8 (msg, test_uint8);
  ns_msg_pack_uint16 (msg, test_uint16);
  ns_msg_pack_uint32 (msg, test_uint32);  
  ns_msg_pack_double (msg, test_double);
  ns_msg_pack_string (msg, buf, -1);

  //g_fprintf (stderr, "Packing:\n\t uint8: %p| uint16: %p", &test_uint8, &test_uint16);
  g_fprintf (stderr, "Packing (single):\n\t %d, %hhu, %hu, %u, %lf %s\n", test_int32,
	     test_uint8, test_uint16, test_uint32, test_double, buf);

  return msg;
}

static int
test_marshalling ()
{
  NsMsg  *msg;
  int32   test_int32;
  uint8   test_uint8;
  uint16  test_uint16;
  uint32  test_uint32;
  double  test_double;
  char    buf[32];
  size_t  slen;
  int     pos = 0;
  int     old_pos = 0;

  msg = pack_message_single (-323232, 88, 1616, 323232,  3.14159, "INCF GNode");

  ns_msg_dump (msg);

  test_int32 = ns_msg_read_int32 (msg, &pos);
  assert (pos == sizeof (test_int32));
  old_pos = pos;

  test_uint8 = ns_msg_read_uint8 (msg, &pos);
  assert (pos == old_pos + sizeof (test_uint8));
  old_pos = pos;

  test_uint16 = ns_msg_read_uint16 (msg, &pos);
  assert (pos == old_pos + sizeof (test_uint16));
  old_pos = pos;

  test_uint32 = ns_msg_read_uint32 (msg, &pos);
  assert (pos == old_pos + sizeof (test_uint32));
  old_pos = pos;


  test_double = ns_msg_read_double (msg, &pos);  
  assert (pos == old_pos + sizeof (test_double));
  old_pos = pos;

  slen = ns_msg_read_string (msg, &pos, buf, sizeof (buf));
  assert (slen == strlen ("INCF GNode") + 1); /* FIXME: +1 ? */

  assert (pos == old_pos + slen + sizeof (uint32));

  /* Reading over the message body boundaries should result in pos == -1 */
  ns_msg_read_uint32 (msg, &pos);
  assert (pos == -1);

  g_fprintf (stderr, "Reading (single):\n\t %d, %hhu, %hu, %u, %lf %s\n",
	     test_int32, test_uint8, test_uint16, test_uint32, test_double, buf);
  
  ns_msg_dump (msg);
  
  assert (test_int32 == -323232);
  assert (test_uint8 == 88);
  assert (test_uint16 == 1616);
  assert (test_uint32 == 323232);
  assert (test_double == 3.14159);
  assert (g_str_equal (buf, "INCF GNode"));

  ns_msg_free (msg);

  msg = pack_message_poly (-323232, 88, 1616, 323232,  3.14159, "INCF GNode");

  ns_msg_read_poly (msg,
		    NS_TYPE_INT32, &test_int32,
		    NS_TYPE_UINT8, &test_uint8,
		    NS_TYPE_UINT16, &test_uint16,
		    NS_TYPE_UINT32, &test_uint32,
		    NS_TYPE_DOUBLE, &test_double,
		    NS_TYPE_CHAR_ARRAY, strlen ("INCF GNode") + 1, buf,
		    NS_TYPE_NONE);

  g_fprintf (stderr, "Reading (poly):\n\t %d, %hhu, %hu, %u, %lf %s\n",
	     test_int32, test_uint8, test_uint16, test_uint32, test_double, buf);

  ns_msg_dump (msg);

  assert (test_int32 == -323232);
  assert (test_uint8 == 88);
  assert (test_uint16 == 1616);
  assert (test_uint32 == 323232);
  assert (test_double == 3.14159);
  assert (g_str_equal (buf, "INCF GNode"));

  ns_msg_free (msg);

  return 1;
}

int
main (int argc, char **argv)
{
  int res = 0;

  fprintf (stderr, "Baisc checks.\n");
  res = NS_CHECK_HDR_ALIGNMENT ();
  assert (res);

  fprintf (stderr, "Message checks.\n");
  assert (test_message ());

  fprintf (stderr, "Marshalling tests\n");
  assert (test_marshalling ());

  return 0;
}
