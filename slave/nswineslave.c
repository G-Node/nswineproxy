
#pragma pack(4)

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
#include <stdio.h>
#include <string.h>

#include <direct.h> /* _getcwd() */

#include <stddef.h>

#include <nsAPItypes.h>
#include <nsAPIdllimp.h>
#include <nsWireProtocol.h>


#ifndef MIN
#define MIN(_a, _b) (_a < _b ? _a : _b)
#endif

typedef struct _LibraryHandle {

  HMODULE                 handle;

  NS_GETLIBRARYINFO       ns_GetLibraryInfo;
  NS_OPENFILE             ns_OpenFile;
  NS_GETFILEINFO          ns_GetFileInfo;
  NS_CLOSEFILE            ns_CloseFile;
  NS_GETENTITYINFO        ns_GetEntityInfo;
  NS_GETEVENTINFO         ns_GetEventInfo;
  NS_GETEVENTDATA         ns_GetEventData;
  NS_GETANALOGINFO        ns_GetAnalogInfo;
  NS_GETANALOGDATA        ns_GetAnalogData;
  NS_GETSEGMENTINFO       ns_GetSegmentInfo;
  NS_GETSEGMENTSOURCEINFO ns_GetSegmentSourceInfo;
  NS_GETSEGMENTDATA       ns_GetSegmentData;
  NS_GETNEURALINFO        ns_GetNeuralInfo;
  NS_GETNEURALDATA        ns_GetNeuralData;
  NS_GETINDEXBYTIME       ns_GetIndexByTime;
  NS_GETTIMEBYINDEX       ns_GetTimeByIndex;
  NS_GETLASTERRORMSG      ns_GetLastErrorMsg;

} LibraryHandle;

static LibraryHandle lib_handle = {0, };

static NsByteOrder
check_the_egg (void)
{
  NsByteOrder byteorder;
  union {
    uint16 s;
    char   c[sizeof (short)];
  } egg;

  egg.s = 0x0102;

  
  if (egg.c[0] == 0x01 && egg.c[1] == 0x02)
    byteorder = NS_BIG_ENDIAN;
  else if (egg.c[0] == 0x02 && egg.c[1] == 0x01)
    byteorder = NS_LITTLE_ENDIAN;
  else
    byteorder = NS_UNKOWN_ENDIAN;
  
  return byteorder;
}

/* ********************************** */
/* socket functions */


static int
socket_send_all (SOCKET sock, const void *data, size_t len)
{
  char *bufptr;
  size_t to_send;
  int res;

  to_send = len;
  bufptr = (char *) data;

  while (to_send > 0)
    {
      res = send (sock, bufptr, to_send, 0);
      
      if (res < 0)
	{
	  int w_errno;

	  if (res == 0)
	    break;

	  w_errno = WSAGetLastError ();

	  if (w_errno == WSAEINTR)
	    continue;
	  else
	    return res;
	}
      
      to_send -= res;
      bufptr += res;
    }
  
  return len;
}

static int
socket_recv_all (SOCKET sock, void *buffer, size_t len)
{
  int     res;
  size_t  to_read;
  const char *bufptr;


  bufptr = buffer;
  to_read = len;

  while (to_read > 0)
    {
      res = recv (sock, (void *) bufptr, to_read, 0);

      if (res < 1)
	{
	  int w_errno;

	  if (res == 0)
	    break;

	  w_errno = WSAGetLastError ();

	  if (w_errno == WSAEINTR)
	    continue;
	  else
	    return res;
	}

      bufptr += res;
      to_read -= res;
    }
 
  return len - to_read;
}

static int
socket_send_message (SOCKET sock, NsMsg *msg)
{
  int     res;
  void   *body_data;
  size_t  len;

  body_data = ns_msg_prepare_for_io (msg, &len);
  fprintf (stderr, "<NSWS> [D] Sending msg: \n");
 
  res = socket_send_all (sock, msg, sizeof (NsMsgHeader));

  if (res <= 0 || len == 0) /* NB: error case AND non-error but len == 0 case */
    return res;

  res = socket_send_all (sock, body_data, len);

  if (res <= 0)
    return res;

  fprintf (stderr, "<NSWS> [D] Sending down.\n");
  return res;
}



static NsMsg *
socket_receive_message (SOCKET sock, int *res_out)
{
  int     res;
  NsMsg  *msg;
  size_t  to_read = 0;
  size_t  n_left;

  msg = ns_msg_new_from_wire ();

  res = socket_recv_all (sock, (void *) msg, sizeof (NsMsgHeader));

  if (res < 1)
    {
      *res_out = res;
      ns_msg_free (msg);

      if (res == 0)
	fprintf (stderr, "<NSWS> [I] Socket: EOF\n");
      else
	fprintf (stderr, "<NSWS> [I] Socket: Error during recv of header\n");

      return NULL;
    }

  n_left = ns_msg_get_body_size (msg);

  while (n_left > 0)
    {
      uint8 buf[4096] = {0, };
      
      to_read = MIN (n_left, sizeof (buf));  
      fprintf (stderr, "<NSWS> [D] to_read %d %d\n", to_read, n_left);

      res = recv (sock, (void *) buf, to_read, 0);
      
      if (res < 1)
	{
	  *res_out = res;
	  ns_msg_free (msg);
	  fprintf (stderr, "<NSWS> [E] Error during recv %d\n", WSAGetLastError ());
	  return NULL;
	}
      
      fprintf (stderr, "<NSWS> [D] did read %d\n", res);
      n_left = ns_msg_body_read_from_wire (msg, buf, res);
    }

  return msg;
}


static int
do_handshake (SOCKET sock, const char *cookie)
{
  NsMsg *msg;
  size_t data_size;
  int res;

  fprintf (stderr, "<NSWS> [D] Doing handshake!\n");

  data_size = strlen (cookie) + 1;

  msg = ns_msg_new_sized (NS_MSG_TYPE_CALL, NS_REQ_HANDSHAKE, 0, data_size);
  ns_msg_set_serial (msg, 0); /* Handeshakes have 0 serial */
  ns_msg_pack_string (msg, cookie, -1);

  res = socket_send_message (sock, msg);

  fprintf (stderr, "<NSWS> [D] Message sent: %i!\n", res);
  return res;
}

static int
connect_to_lib (_TCHAR *port, SOCKET *sock_out)
{
  WSADATA wsaData;
  struct addrinfo *result = NULL;
  struct addrinfo *ptr = NULL;
  struct addrinfo hints;
  SOCKET sock;
  int res;

  res = WSAStartup (MAKEWORD (2, 2), &wsaData);

  if (res != 0) {
    printf ("<NSWS> [E] WSAStartup failed: %d\n", res);
    return 1;
  }

  ZeroMemory (&hints, sizeof (hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  res = getaddrinfo (TEXT  ("localhost"), port, &hints, &result);

  if (res != 0) {    
    fprintf (stderr, "<NSWS> [E] Host lookup failed with error: %d\n", res); 
    WSACleanup ();
    return 1;
  }

  for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {

      sock = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
      if (sock == INVALID_SOCKET)
	{
	  continue;
	}
      
      res = connect (sock, ptr->ai_addr, ptr->ai_addrlen);
      if (res == 0)
	break;
      
      close (sock);
    }
  
  freeaddrinfo (result);

  if (ptr == NULL)
    {
      fprintf (stderr, "<NSWS> [E]Could not connect to lib: %d\n", res); 
      WSACleanup ();
      return 1;
    }

  *sock_out = sock;
  
  return 0;
}

#define PROC_ADDR(_handle, _struct, _function, _variable) \
  _struct->_variable = (_function) GetProcAddress (_handle, #_variable); \
  if (_struct->_variable == NULL)					\
    return -1;

static int
load_library_assign_pointers (HMODULE handle, LibraryHandle *lib)
{
  PROC_ADDR (handle, lib, NS_GETLIBRARYINFO, ns_GetLibraryInfo);
  PROC_ADDR (handle, lib, NS_OPENFILE, ns_OpenFile);
  PROC_ADDR (handle, lib, NS_CLOSEFILE, ns_CloseFile);
  PROC_ADDR (handle, lib, NS_GETFILEINFO, ns_GetFileInfo);
  PROC_ADDR (handle, lib, NS_GETENTITYINFO, ns_GetEntityInfo);
  PROC_ADDR (handle, lib, NS_GETEVENTINFO, ns_GetEventInfo);
  PROC_ADDR (handle, lib, NS_GETEVENTDATA, ns_GetEventData);
  PROC_ADDR (handle, lib, NS_GETANALOGINFO, ns_GetAnalogInfo);
  PROC_ADDR (handle, lib, NS_GETANALOGDATA, ns_GetAnalogData);
  PROC_ADDR (handle, lib, NS_GETSEGMENTINFO, ns_GetSegmentInfo);
  PROC_ADDR (handle, lib, NS_GETSEGMENTSOURCEINFO, ns_GetSegmentSourceInfo);
  PROC_ADDR (handle, lib, NS_GETSEGMENTDATA, ns_GetSegmentData);
  PROC_ADDR (handle, lib, NS_GETNEURALINFO, ns_GetNeuralInfo);
  PROC_ADDR (handle, lib, NS_GETNEURALDATA, ns_GetNeuralData);
  PROC_ADDR (handle, lib, NS_GETINDEXBYTIME, ns_GetIndexByTime);
  PROC_ADDR (handle, lib, NS_GETINDEXBYTIME, ns_GetIndexByTime);
  PROC_ADDR (handle, lib, NS_GETTIMEBYINDEX, ns_GetTimeByIndex);
  PROC_ADDR (handle, lib, NS_GETLASTERRORMSG, ns_GetLastErrorMsg);
  
  return 0;
}

static int
load_library (const char *filename)
{
  HMODULE handle;
  int res;

  /* FIXME: set errors */
 
  handle = LoadLibraryEx (filename, 0, 0);
  
  if (handle == NULL)
    return -1;

  lib_handle.handle = handle;

  res = load_library_assign_pointers (handle, &lib_handle);

  if (res == -1)
    {
      FreeLibrary (handle);
      ZeroMemory (&lib_handle, sizeof (LibraryHandle));
    }

  fprintf (stderr, "<NSWS> [I] Library %s loaded\n", filename);
  return res;
}



static NsMsg *
process_load_lib (NsMsg *msg)
{
  NsMsg *reply = NULL;
  char *lib_path;
  int pos;
  int res;

  pos = 0;

  /* FIXME: unicode
     http://msdn.microsoft.com/en-us/library/dd319072(v=vs.85).aspx
     MultiByteToWideChar () & WideCharToMultiByte ()
   */
  
  lib_path = ns_msg_read_dup_string (msg, &pos);

  if (lib_path == NULL || pos == -1)
    {
      reply = ns_msg_new_error (msg, NS_ERROR_BAD_ARGUMENTS, NULL);
      return reply;
    }

  fprintf (stderr, "<NSWS> D: LoadLib Path: %s\n", lib_path);

  res = load_library (lib_path);

  free (lib_path);

  if (res < 0)
    {
      res *= -1;
      reply = ns_msg_new_error (msg, NS_ERROR_FAILED, NULL);
      return reply;
    }

  reply = ns_msg_new_reply (msg, 0);

  return reply;
}

static NsMsg *
generate_error_reply (NsMsg *call_msg, ns_RESULT result)
{
  ns_RESULT  ns_res;
  NsMsg     *reply = NULL;
  char      *errstr = NULL;
  char       errbuf[1024] = {0, };
 
  ns_res = lib_handle.ns_GetLastErrorMsg (errbuf, sizeof (errbuf));

  if (ns_res == ns_OK)
    errstr = errbuf;

  reply = ns_msg_new_error (call_msg, result, errstr);

  return reply;
}

static NsMsg *
process_open_file (NsMsg *msg)
{
  ns_RESULT  ns_res;
  int        pos;
  char      *filename;
  uint32     file_id;
  NsMsg     *reply = NULL;
  
  pos = 0;

  filename = ns_msg_read_dup_string (msg, &pos);

  if (filename == NULL || pos == -1)
    {
      reply = ns_msg_new_error (msg, NS_ERROR_BAD_ARGUMENTS, NULL);
      return reply;
    }

  fprintf (stderr, "<NSWS> D: OpenFile Path: %s\n", filename);
  ns_res = lib_handle.ns_OpenFile (filename, &file_id);
  
  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (uint32));
  ns_msg_pack_uint32 (reply, file_id);
  
  return reply;
}


static NsMsg *
process_get_file_info (NsMsg *msg)
{
  NsMsg       *reply = NULL;
  ns_RESULT    ns_res;
  ns_FILEINFO  FileInfo;
  uint32       the_file_id;

  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetFileInfo (the_file_id,
				      &FileInfo,
				      sizeof (FileInfo));


  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_FILEINFO));

  ns_msg_pack_poly (reply,
		    NS_TYPE_CHAR_ARRAY, 32, FileInfo.szFileType, 
		    NS_TYPE_UINT32, FileInfo.dwEntityCount,
		    NS_TYPE_DOUBLE, FileInfo.dTimeStampResolution,
		    NS_TYPE_DOUBLE, FileInfo.dTimeSpan,
		    NS_TYPE_CHAR_ARRAY, 64, FileInfo.szAppName,
		    NS_TYPE_UINT32, FileInfo.dwTime_Year,
		    NS_TYPE_UINT32, FileInfo.dwTime_Month,
		    NS_TYPE_UINT32, FileInfo.dwTime_DayofWeek,
		    NS_TYPE_UINT32, FileInfo.dwTime_Day,
		    NS_TYPE_UINT32, FileInfo.dwTime_Hour,
		    NS_TYPE_UINT32, FileInfo.dwTime_Min,
		    NS_TYPE_UINT32, FileInfo.dwTime_Sec,
		    NS_TYPE_UINT32, FileInfo.dwTime_MilliSec,
		    NS_TYPE_CHAR_ARRAY, 256, FileInfo.szFileType,
		    NS_TYPE_NONE);

  return reply;
}

static NsMsg *
process_get_entity_info (NsMsg *msg)
{
  ns_ENTITYINFO  EntityInfo;
  ns_RESULT      ns_res;
  uint32         the_file_id;
  uint32         entity_id;
  NsMsg         *reply = NULL;

  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetEntityInfo (the_file_id,
					entity_id,
					&EntityInfo,
					sizeof (EntityInfo));

  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_ENTITYINFO));

  ns_msg_pack_poly (reply,
		    NS_TYPE_CHAR_ARRAY, 32, EntityInfo.szEntityLabel,
		    NS_TYPE_UINT32, EntityInfo.dwEntityType,
		    NS_TYPE_UINT32, EntityInfo.dwItemCount,
		    NS_TYPE_NONE);

  return reply;
}

static NsMsg *
process_get_event_info (NsMsg *msg)
{
  ns_EVENTINFO  EventInfo;
  ns_RESULT     ns_res;
  uint32        the_file_id;
  uint32        entity_id;
  NsMsg        *reply = NULL;

  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetEventInfo (the_file_id,
				       entity_id,
				       &EventInfo,
				       sizeof (EventInfo));

  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_EVENTINFO));

  ns_msg_pack_poly (reply,
		    NS_TYPE_UINT32, EventInfo.dwEventType,
		    NS_TYPE_UINT32, EventInfo.dwMinDataLength,
		    NS_TYPE_UINT32, EventInfo.dwMaxDataLength,
		    NS_TYPE_CHAR_ARRAY, 128, EventInfo.szCSVDesc,
		    NS_TYPE_NONE);

  return reply; 
}


static NsMsg *
process_get_event_data (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     the_file_id;
  uint32     entity_id;
  uint32     index;
  uint32     data_size;
  uint32     data_ret_size;
  double     timestamp;
  NsMsg     *reply = NULL;
  void      *buffer;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_UINT32, &index,
		    NS_TYPE_UINT32, &data_size,
		    NS_TYPE_NONE);

  reply = ns_msg_new_reply (msg, data_size + sizeof (double));

  buffer = ns_msg_pack_raw_start (reply, data_size);

  ns_res = lib_handle.ns_GetEventData (the_file_id,
				       entity_id,
				       index,
				       &timestamp,
				       buffer,
				       data_size,
				       &data_ret_size);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  ns_msg_pack_raw_finish (reply, data_ret_size);
  ns_msg_pack_double (reply, timestamp);
  return reply;
}

static NsMsg *
process_get_analog_info (NsMsg *msg)
{
  ns_ANALOGINFO  AnalogInfo;
  ns_RESULT      ns_res;
  uint32         the_file_id;
  uint32         entity_id;
  NsMsg         *reply = NULL;

  fprintf (stderr, " + process_get_analog_info \n");
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetAnalogInfo (the_file_id,
					entity_id,
					&AnalogInfo,
					sizeof (AnalogInfo));

  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_ANALOGINFO));

  ns_msg_pack_poly (reply,
		    NS_TYPE_DOUBLE, AnalogInfo.dSampleRate,
		    NS_TYPE_DOUBLE, AnalogInfo.dMinVal,
		    NS_TYPE_DOUBLE, AnalogInfo.dMaxVal,
		    NS_TYPE_CHAR_ARRAY, 16, AnalogInfo.szUnits,
		    NS_TYPE_DOUBLE, AnalogInfo.dResolution,
		    NS_TYPE_DOUBLE, AnalogInfo.dLocationX,
		    NS_TYPE_DOUBLE, AnalogInfo.dLocationY,
		    NS_TYPE_DOUBLE, AnalogInfo.dLocationZ,
		    NS_TYPE_DOUBLE, AnalogInfo.dLocationUser,
		    NS_TYPE_DOUBLE, AnalogInfo.dHighFreqCorner,
		    NS_TYPE_UINT32, AnalogInfo.dwHighFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, AnalogInfo.szHighFilterType,
		    NS_TYPE_DOUBLE, AnalogInfo.dLowFreqCorner,
		    NS_TYPE_UINT32, AnalogInfo.dwLowFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, AnalogInfo.szLowFilterType,
		    NS_TYPE_CHAR_ARRAY, 128, AnalogInfo.szProbeInfo,
		    NS_TYPE_NONE);

  return reply; 
}

static NsMsg *
process_get_analog_data (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     the_file_id;
  uint32     entity_id;
  uint32     index_start;
  uint32     index_count;
  uint32     cont_count;
  uint32     data_size;
  NsMsg     *reply = NULL;
  void      *buffer;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_UINT32, &index_start,
		    NS_TYPE_UINT32, &index_count,
		    NS_TYPE_NONE);

  data_size = sizeof (double) * index_count;

  reply = ns_msg_new_reply (msg, data_size + sizeof (double));

  buffer = ns_msg_pack_raw_start (reply, data_size);

  ns_res = lib_handle.ns_GetAnalogData (the_file_id,
					entity_id,
					index_start,
					index_count,
					&cont_count,
					buffer);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  ns_msg_pack_raw_finish (reply, data_size);
  ns_msg_pack_uint32 (reply, cont_count);
  
  return reply;
}

static NsMsg *
process_get_segment_info (NsMsg *msg)
{
  ns_SEGMENTINFO  SegmentInfo;
  ns_RESULT       ns_res;
  uint32          the_file_id;
  uint32          entity_id;
  NsMsg          *reply = NULL;

  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetSegmentInfo (the_file_id,
					 entity_id,
					 &SegmentInfo,
					 sizeof (SegmentInfo));

  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_SEGMENTINFO));

  
  ns_msg_pack_poly (reply,
		    NS_TYPE_UINT32, SegmentInfo.dwSourceCount,
		    NS_TYPE_UINT32, SegmentInfo.dwMinSampleCount,
		    NS_TYPE_UINT32, SegmentInfo.dwMaxSampleCount,
		    NS_TYPE_DOUBLE, SegmentInfo.dSampleRate,
		    NS_TYPE_CHAR_ARRAY, 32, SegmentInfo.szUnits,
		    NS_TYPE_NONE);

  return reply; 
}

static NsMsg *
process_get_segment_source_info (NsMsg *msg)
{
  ns_SEGSOURCEINFO  SourceInfo;
  ns_RESULT         ns_res;
  uint32            the_file_id;
  uint32            entity_id;
  uint32            source_id;
  NsMsg            *reply = NULL;

  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_UINT32, &source_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetSegmentSourceInfo (the_file_id,
					       entity_id,
					       source_id,
					       &SourceInfo,
					       sizeof (SourceInfo));

  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_SEGSOURCEINFO));

  ns_msg_pack_poly (reply,   
		    NS_TYPE_DOUBLE, SourceInfo.dMinVal,
		    NS_TYPE_DOUBLE, SourceInfo.dMaxVal,
		    NS_TYPE_DOUBLE, SourceInfo.dResolution,
		    NS_TYPE_DOUBLE, SourceInfo.dSubSampleShift,
		    NS_TYPE_DOUBLE, SourceInfo.dLocationX,
		    NS_TYPE_DOUBLE, SourceInfo.dLocationY,
		    NS_TYPE_DOUBLE, SourceInfo.dLocationZ,
		    NS_TYPE_DOUBLE, SourceInfo.dLocationUser,
		    NS_TYPE_DOUBLE, SourceInfo.dHighFreqCorner,
		    NS_TYPE_UINT32, SourceInfo.dwHighFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, SourceInfo.szHighFilterType,
		    NS_TYPE_DOUBLE, SourceInfo.dLowFreqCorner,
		    NS_TYPE_UINT32, SourceInfo.dwLowFreqOrder,
		    NS_TYPE_CHAR_ARRAY, 16, SourceInfo.szLowFilterType,
		    NS_TYPE_CHAR_ARRAY, 128, SourceInfo.szProbeInfo,
		    NS_TYPE_NONE);

  return reply; 
}

static NsMsg *
process_get_segment_data (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     the_file_id;
  uint32     entity_id;
  uint32     index;
  uint32     buffer_size;
  uint32     sample_count;
  uint32     unit_id;
  double     timestamp;
  NsMsg     *reply = NULL;
  void      *buffer;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_UINT32, &index,
		    NS_TYPE_UINT32, &buffer_size,
		    NS_TYPE_NONE);

  reply = ns_msg_new_reply (msg, buffer_size + sizeof (double));

  buffer = ns_msg_pack_raw_start (reply, buffer_size);

  ns_res = lib_handle.ns_GetSegmentData (the_file_id,
					 entity_id,
					 index,
					 &timestamp,
					 buffer,
					 buffer_size,
					 &sample_count,
					 &unit_id);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  ns_msg_pack_raw_finish (reply, buffer_size); /* FIXME: can we transfer less data? */
  ns_msg_pack_poly (reply,
		    NS_TYPE_DOUBLE, timestamp,
		    NS_TYPE_UINT32, sample_count,
		    NS_TYPE_UINT32, unit_id,
		    NS_TYPE_NONE);

  return reply;
}


static NsMsg *
process_get_neural_info (NsMsg *msg)
{
  ns_NEURALINFO  NeuralInfo;
  ns_RESULT      ns_res;
  uint32         the_file_id;
  uint32         entity_id;
  NsMsg         *reply = NULL;

  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_NONE);

  ns_res = lib_handle.ns_GetNeuralInfo (the_file_id,
					entity_id,
					&NeuralInfo,
					sizeof (NeuralInfo));

  if (ns_res != ns_OK) 
    {
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  reply = ns_msg_new_reply (msg, sizeof (ns_NEURALINFO));

  ns_msg_pack_poly (reply,
		    NS_TYPE_UINT32, NeuralInfo.dwSourceEntityID,
		    NS_TYPE_UINT32, NeuralInfo.dwSourceUnitID,
		    NS_TYPE_CHAR_ARRAY, 128, NeuralInfo.szProbeInfo,
		    NS_TYPE_NONE);

  return reply; 
}

static NsMsg *
process_get_neural_data (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     the_file_id;
  uint32     entity_id;
  uint32     index_start;
  uint32     index_count;
  uint32     data_size;
  NsMsg     *reply = NULL;
  void      *buffer;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_UINT32, &index_start,
		    NS_TYPE_UINT32, &index_count,
		    NS_TYPE_NONE);

  data_size = sizeof (double) * index_count;

  reply = ns_msg_new_reply (msg, data_size + sizeof (double));

  buffer = ns_msg_pack_raw_start (reply, data_size);

  ns_res = lib_handle.ns_GetNeuralData (the_file_id,
					entity_id,
					index_start,
					index_count,
					buffer);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  ns_msg_pack_raw_finish (reply, data_size);

  return reply;
}


static NsMsg *
process_get_time_by_index (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     the_file_id;
  uint32     entity_id;
  uint32     index;
  double     time;
  NsMsg     *reply = NULL;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_UINT32, &index,
		    NS_TYPE_NONE);

  reply = ns_msg_new_reply (msg, sizeof (double));

  ns_res = lib_handle.ns_GetTimeByIndex (the_file_id,
					 entity_id,
					 index,
					 &time);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  ns_msg_pack_double (reply, time);
  return reply;
}

static NsMsg *
process_get_index_by_time (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     the_file_id;
  uint32     entity_id;
  uint32     index;
  double     time;
  int32      flags;
  NsMsg     *reply = NULL;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &the_file_id,
		    NS_TYPE_UINT32, &entity_id,
		    NS_TYPE_DOUBLE, &time,
		    NS_TYPE_INT32,  &flags,
		    NS_TYPE_NONE);

  reply = ns_msg_new_reply (msg, sizeof (double));

  ns_res = lib_handle.ns_GetIndexByTime (the_file_id,
					 entity_id,
					 time,
					 flags,
					 &index);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = generate_error_reply (msg, ns_res);
      return reply;
    }

  ns_msg_pack_uint32 (reply, index);
  return reply;
}

static NsMsg *
process_get_last_error_msg (NsMsg *msg)
{
  ns_RESULT  ns_res;
  uint32     buffer_size;
  void      *buffer;
  NsMsg     *reply = NULL;
 
  ns_msg_read_poly (msg,
		    NS_TYPE_UINT32, &buffer_size,
		    NS_TYPE_NONE);

  reply = ns_msg_new_reply (msg, buffer_size);

  buffer = ns_msg_pack_raw_start (reply, buffer_size);

  ns_res = lib_handle.ns_GetLastErrorMsg (buffer,
					  buffer_size);

  if (ns_res != ns_OK) 
    {
      ns_msg_free (reply);
      reply = ns_msg_new_error (msg, NS_ERROR_FAILED, NULL);
      return reply;
    }

  ns_msg_pack_raw_finish (msg, strlen (buffer));
  return reply;
}



static NsMsg *
handle_incoming_message (NsMsg *msg)
{
  NsReqId  req_id;
  NsMsg   *reply = NULL;

  req_id = ns_msg_get_req_id (msg);

  switch (req_id) {
    
  case NS_REQ_LOAD_LIB:
    reply = process_load_lib (msg);
    break;

  case NS_REQ_NS_OPEN_FILE:
    reply = process_open_file (msg);
    break;

   case NS_REQ_NS_GET_FILE_INFO:
    reply = process_get_file_info (msg);
   break;

   case NS_REQ_NS_GET_ENTITY_INFO:
    reply = process_get_entity_info (msg);
   break;

  case NS_REQ_NS_GET_EVENT_INFO:
    reply = process_get_event_info (msg);
    break;

  case NS_REQ_NS_GET_EVENT_DATA:
    reply = process_get_event_data (msg);
    break;

  case NS_REQ_NS_GET_ANALOG_INFO:
    reply = process_get_analog_info (msg);
    break;

  case NS_REQ_NS_GET_ANALOG_DATA:
    reply = process_get_analog_data (msg);
    break;

  case NS_REQ_NS_GET_SEGMENT_INFO:
    reply = process_get_segment_info (msg);
    break;

  case NS_REQ_NS_GET_SEGSRC_INFO:
    reply = process_get_segment_source_info (msg);
    break;

  case NS_REQ_NS_GET_SEGMENT_DATA:
    reply = process_get_segment_data (msg);
    break;

  case NS_REQ_NS_GET_NEURAL_INFO:
    reply = process_get_neural_info (msg);
    break;

  case NS_REQ_NS_GET_NEURAL_DATA:
    reply = process_get_neural_data (msg);
    break;

  case NS_REQ_NS_GET_TIME_BY_INDEX:
    reply = process_get_time_by_index (msg);
    break;

  case NS_REQ_NS_GET_INDEX_BY_TIME:
    reply = process_get_index_by_time (msg);
    break;

  case NS_REQ_NS_GET_LAST_ERR_MSG:
    reply = process_get_last_error_msg (msg);
    break;

  default:
    reply = ns_msg_new_error (msg, NS_ERROR_UNKOWN_CALL, NULL);
  }

  return reply;
}



int 
_tmain (int argc, _TCHAR* argv[])
{
  NsByteOrder byteorder;
  SOCKET      sock;
  int         res;
  int         port;
  char       *cookie;
  char        cwd[FILENAME_MAX];
  NsMsg      *msg;
  _TCHAR     *port_str;


  if (argc < 3)
    {
      fprintf (stderr,"<NSWS> [E]: Wrong number of arguments \n");
      return -1;
    }

  port_str = argv[1];
  port = atoi (port_str);
  cookie = argv[2];

  byteorder = check_the_egg ();

  _getcwd (cwd, sizeof (cwd));
  
  fprintf (stderr, "<NSWS> [I] NsWineSlave (c) 2011 G-Node. Starting up. \n");
  fprintf (stderr, "<NSWS> [I] port: %d; cwd: %s; byteorder: %c\n", port, cwd, byteorder);
  fprintf (stderr, "<NSWS> [I] Checking alignment... %s! \n",
	   NS_CHECK_HDR_ALIGNMENT() == 1 ? "pass" : "FAILDED");
 
  res = connect_to_lib (port_str, &sock);

  if (res != 0)
      return -1;

  res = do_handshake (sock, cookie);

  fprintf (stderr, "<NSWS> [I] READY; waiting for commandos \n");

  while (res > 0 && (msg = socket_receive_message (sock, &res)))
    {
      NsMsg *reply = NULL;

      fprintf (stderr, "<NSWS> [D] Received new message.");
      ns_msg_dump (msg);

      reply = handle_incoming_message (msg);
      
      ns_msg_free (msg);
      
      if (reply == NULL)
	{
	  res = -1;
	  break;
	}

      res = socket_send_message (sock, reply);
 
      ns_msg_free (reply);
    }

  fprintf (stderr, "<NSWS> [I] Shutting down (%d)\n", res);
  close (sock);
  WSACleanup ();

  return res;

}
