#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

#include <errno.h>
#include <sys/stat.h>

/* Per-frame send ledger (2026-11-16, GLM53 plan section 2.1): machine-readable
 * JSONL written when LOOPFUZZ_REPLAY_LEDGER names a writable path. A frame is
 * recorded as send_complete ONLY when net_send returns the full frame length;
 * the "Size of the current packet" banner prints BEFORE the send attempt and
 * is not send evidence. stop_reason distinguishes client receive failures,
 * short sends, end-of-file, and clean completion. The ledger binds to its
 * input via the basename/size header; the replay verifier cross-checks both
 * against the framed input bytes and the replay plan's input hash. */
static FILE *g_ledger = NULL;
static const char *g_stop_reason = "eof";
static int g_peer_closed = 0;

/* net_recv is shared with the fuzzer and treats orderly EOF as an empty
 * successful read. Replay must distinguish it before sending another frame.
 * Peeking after its drain detects FIN without consuming any response bytes. */
static int replay_recv(int fd, struct timeval timeout, int poll_timeout,
                       char **response, unsigned int *response_size, int stream)
{
  int result = net_recv(fd, timeout, poll_timeout, response, response_size);
  if (result || !stream) return result;
  char byte;
  ssize_t peek;
  do { peek = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT); }
  while (peek < 0 && errno == EINTR);
  if (peek == 0) { g_peer_closed = 1; errno = 0; return 2; }
  if (peek < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 1;
  errno = 0;
  return 0;
}

static void finish_ledger(unsigned int frames)
{
  if (!g_ledger) return;
  fprintf(g_ledger,
          "{\"event\":\"session_end\",\"frames_total\":%u,\"stop_reason\":\"%s\","
          "\"peer_closed\":%s}\n", frames, g_stop_reason,
          g_peer_closed ? "true" : "false");
  fclose(g_ledger);
  g_ledger = NULL;
}

/* Reject malformed framing before any network traffic. In particular fread
 * of one integer hides 1-3 trailing bytes, and ck_alloc zeroes a short payload. */
static int validate_input(FILE *fp)
{
  unsigned int length;
  unsigned char chunk[4096];
  for (;;) {
    size_t header = fread(&length, 1, sizeof(length), fp);
    if (header == 0) {
      if (ferror(fp)) { g_stop_reason = "input-read-failed"; return 0; }
      rewind(fp);
      return 1;
    }
    if (header != sizeof(length)) {
      g_stop_reason = "truncated-frame-header";
      return 0;
    }
    unsigned int remaining = length;
    while (remaining) {
      size_t wanted = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
      size_t got = fread(chunk, 1, wanted, fp);
      if (got != wanted) {
        g_stop_reason = ferror(fp) ? "input-read-failed" : "truncated-frame-payload";
        return 0;
      }
      remaining -= got;
    }
  }
}

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

int main(int argc, char* argv[])
{
  FILE *fp;
  int portno, n, local_port = 0;
  struct sockaddr_in serv_addr;
  struct sockaddr_in local_serv_addr;

  char* buf = NULL, *response_buf = NULL;
  int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;


  if (argc < 5) {
    PFATAL("Usage: ./aflnet-client packet_file protocol port local_port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
  }

  fp = fopen(argv[1],"rb");
  if (!fp) {
    fprintf(stderr, "[AFLNet-replay] Cannot open input %s: %s\n", argv[1], strerror(errno));
    return 1;
  }

  {
    const char *ledger_path = getenv("LOOPFUZZ_REPLAY_LEDGER");
    if (ledger_path) {
      g_ledger = fopen(ledger_path, "w");
      if (g_ledger) {
        setvbuf(g_ledger, NULL, _IOLBF, 0);
        struct stat st;
        off_t input_size = (stat(argv[1], &st) == 0) ? st.st_size : -1;
        const char *base = strrchr(argv[1], '/');
        base = base ? base + 1 : argv[1];
        fprintf(g_ledger,
                "{\"event\":\"session_begin\",\"schema\":\"loopfuzz-replay-frame-ledger-v1\","
                "\"input_file\":\"%s\",\"input_size\":%lld,\"protocol\":\"%s\"}\n",
                base, (long long)input_size, argv[2]);
      }
    }
  }

  if (!validate_input(fp)) {
    fprintf(stderr, "[AFLNet-replay] Invalid framed input: %s\n", g_stop_reason);
    fclose(fp);
    finish_ledger(0);
    return 2;
  }

  if (!strcmp(argv[2], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(argv[2], "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(argv[2], "MQTT")) extract_response_codes = &extract_response_codes_mqtt;
  else if (!strcmp(argv[2], "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(argv[2], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(argv[2], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(argv[2], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(argv[2], "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(argv[2], "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(argv[2], "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(argv[2], "HTTP")) extract_response_codes = &extract_response_codes_http;
  else if (!strcmp(argv[2], "IPP")) extract_response_codes = &extract_response_codes_ipp;
  else {fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]); exit(1);}

  portno = atoi(argv[3]);
  local_port = atoi(argv[4]);

  if (argc > 5) {
    poll_timeout = atoi(argv[5]);
    if (argc > 6) {
      socket_timeout = atoi(argv[6]);
    }
  }

  //Wait for the server to initialize
  usleep(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  int sockfd;
  int stream = 1;
  if ((!strcmp(argv[2], "DTLS12")) || (!strcmp(argv[2], "DNS")) || (!strcmp(argv[2], "SIP"))) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    stream = 0;
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  //if the server is still alive after processing all the requests
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (local_port > 0)
  {
    local_serv_addr.sin_family = AF_INET;
    local_serv_addr.sin_addr.s_addr = INADDR_ANY;
    local_serv_addr.sin_port = htons(local_port);

    local_serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sockfd, (struct sockaddr *)&local_serv_addr, sizeof(struct sockaddr_in)))
    {
      FATAL("Unable to bind socket on local source port");
    }
  }

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //If it cannot connect to the server under test
    //try it again as the server initial startup time is varied
    for (n=0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n== 1000) {
      close(sockfd);
      return 1;
    }
  }

  //Send requests one by one
  //And save all the server responses
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    size_t header = fread(&size, 1, sizeof(size), fp);
    if (header && header != sizeof(size)) {
      g_stop_reason = "truncated-frame-header";
      break;
    }
    if (!header && ferror(fp)) { g_stop_reason = "input-read-failed"; break; }
    if (header == sizeof(size)) {
      packet_count++;
    	fprintf(stderr,"\nSize of the current packet %d is  %d\n", packet_count, size);

      buf = (char *)ck_alloc(size);
      size_t rd = fread(buf, 1, size, fp);
      if (rd != size) {
        g_stop_reason = "truncated-frame-payload";
        break;
      }

      errno = 0;
      int pre_recv = replay_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size, stream);
      int pre_recv_errno = pre_recv ? errno : 0;
      int sent = -2; /* -2 = not attempted */
      int send_errno = 0;
      if (pre_recv) {
        g_stop_reason = pre_recv == 2 ? "peer-closed-before-frame" : "client-recv-pre-send-failed";
      } else {
        sent = net_send(sockfd, timeout, buf, size);
        if (sent == -1) send_errno = errno;
        if (sent != (int)size) g_stop_reason = "send-short-or-error";
      }
      int post_recv = 0;
      int post_recv_errno = 0;
      if (sent == (int)size) {
        errno = 0;
        post_recv = replay_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size, stream);
        post_recv_errno = post_recv ? errno : 0;
        if (post_recv == 1) g_stop_reason = "client-recv-post-send-failed";
        if (post_recv == 2) {
          int next = fgetc(fp);
          if (next != EOF) {
            ungetc(next, fp);
            g_stop_reason = "peer-closed-before-input-end";
          } else if (ferror(fp)) g_stop_reason = "input-read-failed";
          /* A FIN after the final complete frame is normal protocol shutdown. */
        }
      }
      if (g_ledger) {
        fprintf(g_ledger,
                "{\"event\":\"frame\",\"frame\":%u,\"len\":%u,\"read_complete\":%s,"
                "\"pre_recv_ok\":%s,\"send_attempt\":%s,\"sent_bytes\":%d,"
                "\"send_errno\":%d,\"post_recv_ok\":%s,"
                "\"pre_recv_errno\":%d,\"post_recv_errno\":%d,\"peer_closed\":%s}\n",
                packet_count, size, rd == size ? "true" : "false",
                pre_recv ? "false" : "true",
                sent == -2 ? "false" : "true", sent, send_errno,
                (sent == (int)size) ? (post_recv == 1 ? "false" : "true") : "false",
                pre_recv_errno, post_recv_errno, g_peer_closed ? "true" : "false");
      }
      if (pre_recv) break;
      if (sent != (int)size) break;
      if (post_recv) break;
    }
  }


  fclose(fp);
  close(sockfd);

  //Extract response codes
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    fprintf(stderr,"%c",response_buf[i]);
  }
  fprintf(stderr,"\n--------------------------------");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);

  finish_ledger(packet_count);

  /* A clean process exit is not evidence that replay finished. Preserve the
   * frame/session ledger above, then expose receive/send failures to callers
   * instead of silently returning success for an incomplete conversation. */
  return strcmp(g_stop_reason, "eof") == 0 ? 0 : 2;
}

