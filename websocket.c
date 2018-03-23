
#include "websocket.h"
#include "lwip/tcp.h" // for the netconn structure
#include "esp_system.h" // for esp_random
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include <string.h>

ws_client_t ws_connect_client(struct netconn* conn,
                              char* url,
                              void (*ccallback)(WEBSOCKET_TYPE_t type,char* msg,uint64_t len),
                              void (*scallback)(uint8_t num,WEBSOCKET_TYPE_t type,char* msg,uint64_t len)
                            ) {
  ws_client_t client;
  client.conn = conn;
  client.url  = url;
  client.ping = 0;
  client.last_opcode = 0;
  client.contin = NULL;
  client.len = 0;
  client.ccallback = ccallback;
  client.scallback = scallback;
  return client;
}

void ws_disconnect_client(ws_client_t* client) {
  ws_send(client,WEBSOCKET_OPCODE_CLOSE,NULL,0,1); // tell the client to close
  if(client->conn) {
    client->conn->callback = NULL; // shut off the callback
    netconn_close(client->conn);
    netconn_delete(client->conn);
    client->conn = NULL;
  }
  client->url = NULL;
  client->last_opcode = 0;
  if(client->len) {
    if(client->contin)
      free(client->contin);
    client->len = 0;
  }
  client->ccallback = NULL;
  client->scallback = NULL;
}

bool ws_is_connected(ws_client_t client) {
  if((client.conn) && (client.conn->pcb.tcp->state == ESTABLISHED))
    return 1;
  return 0;
}

static void ws_generate_mask(ws_header_t* header) {
  header->param.bit.MASK = 1;
  header->key.full = esp_random(); // generate a random 32 bit number
}

static void ws_encrypt_decrypt(char* msg,ws_header_t header) {
  if(header.param.bit.MASK) {
    for(uint64_t i=0; i<header.length; i++) {
      msg[i] ^= header.key.part[i%4];
    }
  }
}

void ws_send(ws_client_t* client,WEBSOCKET_OPCODES_t opcode,char* msg,uint64_t len,bool mask) {
  char* out;
  char* encrypt;
  uint64_t pos;
  uint64_t true_len;
  ws_header_t header;

  header.param.pos.ZERO = 0; // reset the whole header
  header.param.pos.ONE  = 0;

  header.param.bit.FIN = 1; // all pieces are done (you don't need a huge message anyway...)
  header.param.bit.OPCODE = opcode;
  // populate LEN field
  pos = 2;
  header.length = len;
  if(len<125) {
    header.param.bit.LEN = len;
  }
  else if(len<65536) {
    header.param.bit.LEN = 126;
    pos += 2;
  }
  else {
    header.param.bit.LEN = 127;
    pos += 8;
  }

  if(mask) {
    ws_generate_mask(&header); // get a key
    encrypt = malloc(len); // allocate memory for the encryption
    memcpy(encrypt,msg,len);
    ws_encrypt_decrypt(encrypt,header); // encrypt it!
    pos += 4; // add the position
  }

  true_len = pos+len; // get the length of the entire message
  pos = 2;
  out = malloc(true_len); // allocate dat memory

  out[0] = header.param.pos.ZERO; // save header
  out[1] = header.param.pos.ONE;

  // put in the length, if necessary
  if(header.param.bit.LEN == 126) {
    out[2] = (len >> 8) & 0xFF;
    out[3] = (len     ) & 0xFF;
    pos = 4;
  }
  if(header.param.bit.LEN == 127) {
    memcpy(&out[2],&len,8);
    pos = 10;
  }

  if(mask) {
    out[pos] = header.key.part[0]; pos++;
    out[pos] = header.key.part[1]; pos++;
    out[pos] = header.key.part[2]; pos++;
    out[pos] = header.key.part[3]; pos++;
    memcpy(&out[pos],encrypt,len); // put in the encrypted message
    free(encrypt);
  }
  else {
    memcpy(&out[pos],msg,len);
  }

  netconn_write(client->conn,out,true_len,NETCONN_COPY); // finally! send it.
  free(out); // free the entire message
}

char* ws_read(ws_client_t* client,ws_header_t* header) {
  char* ret;
  char* append;
  err_t err;
  struct netbuf* inbuf;
  char* buf;
  uint16_t len;
  uint64_t pos;
  uint64_t cont_len;

  err = netconn_recv(client->conn,&inbuf);
  if(err != ERR_OK) return NULL;
  netbuf_data(inbuf,(void**)&buf, &len);
  if(!buf) return NULL;

  // get the header
  header->param.pos.ZERO = buf[0];
  header->param.pos.ONE  = buf[1];

  // get the message length
  pos = 2;
  if(header->param.bit.LEN < 125) {
    header->length = header->param.bit.LEN;
  }
  else if(header->param.bit.LEN == 126) {
    memcpy(&(header->length),&buf[2],2);
    pos = 4;
  }
  else { // LEN = 127
    memcpy(&(header->length),&buf[2],8);
    pos = 10;
  }

  if(header->param.bit.MASK) {
    memcpy(&(header->key.full),&buf[pos],4); // extract the key
    pos += 4;
  }

  // don't read the whole message if there's an issue
  if(header->length > (len-pos)) {
    netbuf_delete(inbuf);
    free(buf);
    return NULL;
  }

  ret = malloc(header->length+1); // allocate memory, plus a bit
  if(!ret) {
    netbuf_delete(inbuf);
    free(buf);
    return NULL;
  }
  memcpy(ret,&buf[pos],header->length+1); // copy the message
  ret[header->length] = '\0'; // end string
  ws_encrypt_decrypt(ret,*header); // unencrypt, if necessary

  if(header->param.bit.FIN == 0) { // if the message isn't done
    if((header->param.bit.OPCODE == WEBSOCKET_OPCODE_CONT) &&
       ((client->last_opcode==WEBSOCKET_OPCODE_BIN) || (client->last_opcode==WEBSOCKET_OPCODE_TEXT))) {
         cont_len = header->length + client->len;
         append = malloc(cont_len);
         memcpy(append,client->contin,client->len);
         memcpy(&append[client->len],ret,header->length);
         free(client->contin);
         client->contin = malloc(cont_len);
         client->len = cont_len;

         free(append);
         free(ret);
         netbuf_delete(inbuf);
         free(buf);
         return NULL;
    }
    else if((header->param.bit.OPCODE==WEBSOCKET_OPCODE_BIN) || (header->param.bit.OPCODE==WEBSOCKET_OPCODE_TEXT)) {
      if(client->len) {
        free(client->contin);
      }
      client->contin = malloc(header->length);
      memcpy(client->contin,ret,header->length);
      client->len = header->length;
      client->last_opcode = header->param.bit.OPCODE;

      free(ret);
      netbuf_delete(inbuf);
      free(buf);
      return NULL;
    }
    else { // there shouldn't be another FIN code....
      free(ret);
      netbuf_delete(inbuf);
      free(buf);
      return NULL;
    }
  }
  client->last_opcode = header->param.bit.OPCODE;
  netbuf_delete(inbuf);
  header->received = 1;
  return ret;
}

char* ws_hash_handshake(char* handshake,uint8_t len) {
  const char hash[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const uint8_t hash_len = sizeof(hash);
  char* ret;
  char key[64];
  unsigned char sha1sum[20];
  unsigned int ret_len;

  if(!len) return NULL;
  ret = malloc(32);

  memcpy(key,handshake,len);
  strlcpy(&key[len],hash,sizeof(key));
  mbedtls_sha1((unsigned char*)key,len+hash_len-1,sha1sum);
  mbedtls_base64_encode(NULL, 0, &ret_len, sha1sum, 20);
  if(!mbedtls_base64_encode((unsigned char*)ret,32,&ret_len,sha1sum,20)) {
    ret[ret_len] = '\0';
    return ret;
  }
  free(ret);
  return NULL;
}
