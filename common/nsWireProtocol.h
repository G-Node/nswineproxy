
#ifndef _NS_WIRE_PROTOCOL_H_
#define _NS_WIRE_PROTOCOL_H_

#include <stdlib.h>
#include <unistd.h>

#include <nsAPItypes.h>

#ifdef __cplusplus
extern "C" 
{
#endif

  typedef enum {

    NS_TYPE_NONE         = 0,
    NS_TYPE_ARRAY        = 1,
    NS_TYPE_INT32        = 2,
    NS_TYPE_UINT8        = 3,
    NS_TYPE_UINT16       = 4,
    NS_TYPE_UINT32       = 5,
    NS_TYPE_DOUBLE       = 6,
    NS_TYPE_STRING       = 7,
    NS_TYPE_CHAR_ARRAY   = 8,
    NS_TYPE_CHAR_2D      = 9,
    NS_TYPE_DOUBLE_ARRAY = 10

  } NsTypeId;

  typedef enum {

    NS_UNKOWN_ENDIAN = 0,
    NS_BIG_ENDIAN    = 'B',
    NS_LITTLE_ENDIAN = 'l'

  } NsByteOrder;


  typedef enum {

    NS_MSG_TYPE_UNKOWN = 0,
    NS_MSG_TYPE_ERROR  = 1,
    NS_MSG_TYPE_CALL   = 2,
    NS_MSG_TYPE_REPLY  = 3

  } NsMsgType;


  typedef enum {

    NS_MSG_FLAGS_NONE = 0

  } NsMsgFlags;

  typedef enum {

    NS_REQ_INTERNAL             = (1 << 15), /* MSB of uint16 */

    NS_REQ_UNKNOWN              = 0,

    NS_REQ_HANDSHAKE            = NS_REQ_INTERNAL | 1,
    NS_REQ_LOAD_LIB             = NS_REQ_INTERNAL | 2,
    NS_REQ_UNLOAD_LIB           = NS_REQ_INTERNAL | 3,

    NS_REQ_NS_OPEN_FILE         = 1,
    NS_REQ_NS_GET_FILE_INFO     = 2,
    NS_REQ_NS_GET_ENTITY_INFO   = 3,
    NS_REQ_NS_GET_EVENT_INFO    = 4,
    NS_REQ_NS_GET_EVENT_DATA    = 5,
    NS_REQ_NS_GET_ANALOG_INFO   = 6,
    NS_REQ_NS_GET_ANALOG_DATA   = 7,
    NS_REQ_NS_GET_SEGMENT_INFO  = 8,
    NS_REQ_NS_GET_SEGSRC_INFO   = 9,
    NS_REQ_NS_GET_SEGMENT_DATA  = 10,
    NS_REQ_NS_GET_NEURAL_INFO   = 11,
    NS_REQ_NS_GET_NEURAL_DATA   = 12,
    NS_REQ_NS_GET_INDEX_BY_TIME = 13,
    NS_REQ_NS_GET_TIME_BY_INDEX = 14,
    NS_REQ_NS_GET_LAST_ERR_MSG  = 15

  } NsReqId;

  typedef enum {
    
    NS_ERROR_TYPE          = -2, // ns_TYPEERROR
    NS_ERRRO_LIB           = -1, // ns_LIBERROR,

    NS_ERROR_FAILED        = 1,
    NS_ERROR_UNKOWN_CALL   = 2,
    NS_ERROR_BAD_ARGUMENTS = 3

  } NsErrorId;

  typedef struct _NsMsgHeader NsMsgHeader;
  struct _NsMsgHeader {
    uint32 size;
    uint32 serial;
    uint8  type;
    uint8  flags;
    uint16 req_id;
  };
  

  typedef struct _NsMsg NsMsg;
  struct _NsMsg {

    NsMsgHeader header;

    /* internal buffer handling */
    void   *body;
    size_t  len;
    size_t  allocated;
    
    size_t  pos;
    int     sealed;

  };

#define NS_MSG_HEADER(_msg) (*((NsMsgHeader *) _msg))

#define NS_CHECK_HDR_ALIGNMENT() (((sizeof (NsMsgHeader) == 12) &&	\
				   offsetof (NsMsgHeader, size)   == 0 && \
				   offsetof (NsMsgHeader, serial) == 4 && \
				   offsetof (NsMsgHeader, type)   == 8 && \
				   offsetof (NsMsgHeader, flags)  == 9 && \
				   offsetof (NsMsgHeader, req_id) == 10) ? 1 : 0)


  NsMsg *       ns_msg_new_sized            (NsMsgType type, NsReqId req_id, NsMsgFlags flags, size_t data_size);
  NsMsg *       ns_msg_new_call             (NsReqId req_id, size_t body_size_est);
  NsMsg *       ns_msg_new_reply            (NsMsg *msg, size_t body_size_est);
  NsMsg *       ns_msg_new_error            (NsMsg *msg, int32 error_id, const char *error_str);

  NsMsg *       ns_msg_new_from_wire        (void);
  void          ns_msg_free                 (NsMsg *msg);

  void          ns_msg_set_serial           (NsMsg *msg, uint32 serial);
  uint32        ns_msg_get_serial           (NsMsg *msg);

  NsReqId       ns_msg_get_req_id           (NsMsg *msg);
  void          ns_msg_set_req_id           (NsMsg *msg, NsReqId);

  NsMsgType     ns_msg_get_msg_type         (NsMsg *msg);

  uint32        ns_msg_get_body_size        (NsMsg *size);

  void *        ns_msg_prepare_for_io       (NsMsg *msg, size_t *len);

  size_t        ns_msg_body_read_from_wire  (NsMsg *msg, const void *buffer, size_t len);
  int           ns_msg_body_pack_raw        (NsMsg *msg, void *data, size_t len);

  /* data pack and reading functions */
  int           ns_msg_pack_int32           (NsMsg *msg, int32  value);
  int           ns_msg_pack_uint8           (NsMsg *msg, uint8  value);
  int           ns_msg_pack_uint16          (NsMsg *msg, uint16 value);
  int           ns_msg_pack_uint32          (NsMsg *msg, uint32 value);
  int           ns_msg_pack_double          (NsMsg *msg, double value);
  void          ns_msg_pack_string          (NsMsg *msg, const char  *string, int len);
  int           ns_msg_pack_string_array    (NsMsg *msg, const char **strv, int len);
  int           ns_msg_pack_double_array    (NsMsg *msg, double *dv, int len);

  void *        ns_msg_pack_raw_start       (NsMsg *msg, uint32 max_size_req);
  int           ns_msg_pack_raw_finish      (NsMsg *msg, uint32 actual_size_req);

  int           ns_msg_pack_poly            (NsMsg *msg, NsTypeId first_type, ...);

  int32         ns_msg_read_int32           (NsMsg *msg, int *pos);
  uint8         ns_msg_read_uint8           (NsMsg *msg, int *pos);
  uint16        ns_msg_read_uint16          (NsMsg *msg, int *pos);
  uint32        ns_msg_read_uint32          (NsMsg *msg, int *pos);
  double        ns_msg_read_double          (NsMsg *msg, int *pos);
  char *        ns_msg_read_dup_string      (NsMsg *msg, int *pos);
  ssize_t       ns_msg_read_string          (NsMsg *msg, int *pos, char *buf, size_t len);

  const char ** ns_msg_read_string_array    (NsMsg *msg, int *pos);
  double *      ns_msg_read_double_array    (NsMsg *msg, int *pos);

  int           ns_msg_read_poly            (NsMsg *msg, NsTypeId first_type, ...);


  /* small helper */
  int           ns_msg_is_error             (NsMsg *msg);

  /* debugging */
  void          ns_msg_dump_header          (NsMsg *msg);
  void          ns_msg_dump                 (NsMsg *msg);

#ifdef __cplusplus
}
#endif

#endif /* #pragma once */

