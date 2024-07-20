// temp name

#include "lauxlib.h"
#include "lnodemcu.h"
#include "module.h"
#include "stdlib.h" // sdk-overrides/include/stdlib.h
#include "lwip/mem.h"
#include "lwip/ip_addr.h"
#include "espconn.h"
#include "os_type.h"
#include "user_interface.h"

#define CAPTURE_ERR_OUT_OF_MEMORY          1
#define CAPTURE_ERR_CONNECTION_NOT_FOUND   2
#define CAPTURE_ERR_UNKOWN_ERROR           3
#define CAPTURE_ERR_SOCKET_ALREADY_OPEN    4
#define CAPTURE_ERR_MAX_NUMBER             5
#define CAPTURE_ERR_ALREADY_INITIALIZED    6


typedef struct
{
  struct espconn *espconn_dns_udp;
  struct tcp_pcb *http_pcb;
  // char *http_payload_data;
  // uint32_t http_payload_len;
  // char *ap_ssid;
  // os_timer_t check_station_timer;
  // os_timer_t shutdown_timer;
  int lua_connected_cb_ref;
  // int lua_err_cb_ref;`
  // int lua_dbg_cb_ref;
  // scan_listener_t *scan_listeners;
  // uint8_t softAPchannel;
  // uint8_t success;
  // uint8_t callbackDone;
  // uint8_t lastStationStatus;
  // uint8_t connecting;
} capture_state_t;

static capture_state_t *state;


/**
 * DNS Response Packet:
 *
 * |DNS ID - 16 bits|
 * |dns_header|
 * |QNAME|
 * |dns_body|
 * |ip - 32 bits|
 *
 *        DNS Header Part          |  FLAGS | | Q COUNT |  | A CNT  |  |AUTH CNT|  | ADD CNT| */
static const char dns_header[] = { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
/*        DNS Query Part           | Q TYPE |  | Q CLASS| */
static const char dns_body[]   = { 0x00, 0x01, 0x00, 0x01,
/*        DNS Answer Part          |LBL OFFS|  |  TYPE  |  |  CLASS |  |         TTL        |  | RD LEN | */
                                   0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04 };


// static void on_initial_scan_done (void *arg, STATUS status)
// {
//   // ENDUSER_SETUP_DEBUG("on_initial_scan_done");

//   if (state == NULL)
//   {
//     return;
//   }

//   int8_t rssi = -100;

//   if (status == OK)
//   {
//     /* Find the strongest signal and use the same wi-fi channel for the SoftAP. This is based on an assumption that end-user
//      * will likely be choosing that AP to connect to. Since ESP only has one radio, STA and AP must share same channel. This
//      * algorithm tries to minimize the SoftAP unavailability when the STA is connecting to verify. If the STA must switch to
//      * another wi-fi channel, then the SoftAP will follow it, but the end-user's device will not know that the SoftAP is no
//      * longer there until it times out. To mitigate, we try to prevent the need to switch channels, and if a switch does occur,
//      * be quick about returning to this channel so that status info can be delivered to the end-user's device before shutting
//      * down EUS.
//      */
//     for (struct bss_info *wn = arg; wn; wn = wn->next.stqe_next)
//     {
//       if (wn->rssi > rssi)
//       {
//         state->softAPchannel = wn->channel;
//         rssi = wn->rssi;
//       }
//     }
//   }

//   enduser_setup_ap_start();
//   enduser_setup_check_station_start();
// }


static void capture_dns_recv_callback(void *arg, char *recv_data, unsigned short recv_len)
{
  struct espconn *callback_espconn = arg;
  struct ip_info ip_info;

  uint32_t qname_len = strlen(&(recv_data[12])) + 1; /* \0=1byte */
  uint32_t dns_reply_static_len = (uint32_t) sizeof(dns_header) + (uint32_t) sizeof(dns_body) + 2 + 4; /* dns_id=2bytes, ip=4bytes */
  uint32_t dns_reply_len = dns_reply_static_len + qname_len;


  uint8_t if_mode = wifi_get_opmode();
  if ((if_mode & SOFTAP_MODE) == 0)
  {
    return;
    //ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Interface mode not supported.", ENDUSER_SETUP_ERR_UNKOWN_ERROR, ENDUSER_SETUP_ERR_FATAL);
  }

  uint8_t if_index = (if_mode == STATION_MODE ? STATION_IF : SOFTAP_IF);
  if (wifi_get_ip_info(if_index , &ip_info) == false)
  {
    return;
    //ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Unable to get interface IP.", ENDUSER_SETUP_ERR_UNKOWN_ERROR, ENDUSER_SETUP_ERR_FATAL);
  }

  char *dns_reply = (char *) malloc(dns_reply_len);
  if (dns_reply == NULL)
  {
    //
    //ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Failed to allocate memory.", ENDUSER_SETUP_ERR_OUT_OF_MEMORY, ENDUSER_SETUP_ERR_NONFATAL);
  }

  uint32_t insert_byte = 0;
  memcpy(&(dns_reply[insert_byte]), recv_data, 2);
  insert_byte += 2;
  memcpy(&(dns_reply[insert_byte]), dns_header, sizeof(dns_header));
  insert_byte += (uint32_t) sizeof(dns_header);
  memcpy(&(dns_reply[insert_byte]), &(recv_data[12]), qname_len);
  insert_byte += qname_len;
  memcpy(&(dns_reply[insert_byte]), dns_body, sizeof(dns_body));
  insert_byte += (uint32_t) sizeof(dns_body);
  memcpy(&(dns_reply[insert_byte]), &(ip_info.ip), 4);

  /* SDK 1.4.0 changed behaviour, for UDP server need to look up remote ip/port */
  remot_info *pr = 0;
  if (espconn_get_connection_info(callback_espconn, &pr, 0) != ESPCONN_OK)
  {
    return;
    //ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Unable to get IP of UDP sender.", ENDUSER_SETUP_ERR_CONNECTION_NOT_FOUND, ENDUSER_SETUP_ERR_FATAL);
  }
  callback_espconn->proto.udp->remote_port = pr->remote_port;
  os_memmove(callback_espconn->proto.udp->remote_ip, pr->remote_ip, 4);

  int8_t err;
  err = espconn_send(callback_espconn, dns_reply, dns_reply_len);
  free(dns_reply);
  if (err == ESPCONN_MEM)
  {
    return;
    // ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Failed to allocate memory for send.", ENDUSER_SETUP_ERR_OUT_OF_MEMORY, ENDUSER_SETUP_ERR_FATAL);
  }
  else if (err == ESPCONN_ARG)
  {
    return;
    // ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Can't execute transmission.", ENDUSER_SETUP_ERR_CONNECTION_NOT_FOUND, ENDUSER_SETUP_ERR_FATAL);
  }
  else if (err == ESPCONN_MAXNUM)
  {
    return;
    // ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Buffer full. Discarding...", ENDUSER_SETUP_ERR_MAX_NUMBER, ENDUSER_SETUP_ERR_NONFATAL);
  }
  else if (err == ESPCONN_IF)
  {
    return;
    // ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. Send UDP data failed", ENDUSER_SETUP_ERR_UNKOWN_ERROR, ENDUSER_SETUP_ERR_NONFATAL);
  }
  else if (err != 0)
  {
    return;
    // ENDUSER_SETUP_ERROR_VOID("dns_recv_callback failed. espconn_send failed", ENDUSER_SETUP_ERR_UNKOWN_ERROR, ENDUSER_SETUP_ERR_FATAL);
  }
}


static int capture_dns_start(void)
{
  if (state->espconn_dns_udp != NULL)
  {
  	return CAPTURE_ERR_ALREADY_INITIALIZED;
  }

  state->espconn_dns_udp = (struct espconn *) malloc(sizeof(struct espconn));
  if (state->espconn_dns_udp == NULL)
  {
  	return CAPTURE_ERR_OUT_OF_MEMORY;
  }

  esp_udp *esp_udp_data = (esp_udp *) malloc(sizeof(esp_udp));
  if (esp_udp_data == NULL)
  {
  	return CAPTURE_ERR_OUT_OF_MEMORY;
  }

  memset(state->espconn_dns_udp, 0, sizeof(struct espconn));
  memset(esp_udp_data, 0, sizeof(esp_udp));
  state->espconn_dns_udp->proto.udp = esp_udp_data;
  state->espconn_dns_udp->type = ESPCONN_UDP;
  state->espconn_dns_udp->state = ESPCONN_NONE;
  esp_udp_data->local_port = 53;

  int8_t err;
  err = espconn_regist_recvcb(state->espconn_dns_udp, capture_dns_recv_callback);
  if (err != 0)
  {
  	return CAPTURE_ERR_UNKOWN_ERROR;
  }

  err = espconn_create(state->espconn_dns_udp);
  if (err == ESPCONN_ISCONN)
  {
  	return CAPTURE_ERR_SOCKET_ALREADY_OPEN;
  }
  else if (err == ESPCONN_MEM)
  {
  	return CAPTURE_ERR_OUT_OF_MEMORY;
  }
  else if (err != 0)
  {
  	return CAPTURE_ERR_UNKOWN_ERROR;
  }

  return 0;
}

static void enduser_setup_dns_stop(void)
{
  if (state != NULL && state->espconn_dns_udp != NULL)
  {
    espconn_delete(state->espconn_dns_udp);
  }
}

static void enduser_setup_free(void)
{
  if (state == NULL)
  {
    return;
  }

  if (state->espconn_dns_udp != NULL)
  {
    if (state->espconn_dns_udp->proto.udp != NULL)
    {
      free(state->espconn_dns_udp->proto.udp);
    }
    free(state->espconn_dns_udp);
  }

  free(state);
  state = NULL;
}


static int capture_init(lua_State *L)
{
  /* Defer errors until the bottom, so that callbacks can be set, if applicable, to handle debug and error messages */
  int ret = 0;

  if (state != NULL)
  {
    ret = CAPTURE_ERR_ALREADY_INITIALIZED;
  }
  else
  {
    state = (capture_state_t *) calloc(1, sizeof(capture_state_t));

    if (state == NULL)
    {
      ret = CAPTURE_ERR_OUT_OF_MEMORY;
    }
    else
    {
      memset(state, 0, sizeof(capture_state_t));

      state->lua_connected_cb_ref = LUA_NOREF;

      // state->lua_err_cb_ref = LUA_NOREF;
      // state->lua_dbg_cb_ref = LUA_NOREF;

      // todo
      // state->softAPchannel = 1;
      // state->success = 0;
      // state->callbackDone = 0;
      // state->lastStationStatus = 0;
      // state->connecting = 0;
    }
  }

  // lua user gives a callback...
  int argno = 1;

  if (!lua_isnoneornil(L, argno))
  {
    lua_pushvalue(L, argno);
    state->lua_connected_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }

  //
  if (ret == CAPTURE_ERR_ALREADY_INITIALIZED)
  {
  	return CAPTURE_ERR_ALREADY_INITIALIZED;
  }
  else if (ret == CAPTURE_ERR_OUT_OF_MEMORY)
  {
  	return CAPTURE_ERR_OUT_OF_MEMORY;
  }

  return ret;
}


// capture.stop()
static int capture_stop(lua_State* L)
{
  enduser_setup_dns_stop();
  enduser_setup_free();

  return 0;
}

// capture.start()
static int capture_start(lua_State* L)
{
  if (capture_init(L))
  {
    capture_stop(L);
  }

  if (capture_dns_start()) 
  {
    capture_stop(L);
  }

 	return 0;
}




LROT_BEGIN(capture, NULL, 0)
	LROT_FUNCENTRY(start, capture_start)
  LROT_FUNCENTRY(stop, capture_stop)
LROT_END(capture, NULL, 0)


NODEMCU_MODULE(CAPTURE, "capture", capture, NULL);