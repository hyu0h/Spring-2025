/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

 #include "backend.h"

 #include <poll.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdbool.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <errno.h>

 #include "ut_packet.h"
 #include "ut_tcp.h"

 #define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
 #define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

 void send_empty(ut_socket_t *sock, int s_flags, bool fin_ack, bool send_fin)
 {
   size_t conn_len = sizeof(sock->conn);
   int sockfd = sock->socket;

   uint16_t src = sock->my_port;
   uint16_t dst = ntohs(sock->conn.sin_port);

   uint32_t seq = sock->send_win.last_sent + 1;
   if (send_fin)
   {
     seq = sock->send_fin_seq;
   }
   uint32_t ack = sock->recv_win.next_expect;
   if (fin_ack)
   {
     ack++;
   }

   uint16_t hlen = sizeof(ut_tcp_header_t);
   uint8_t flags = s_flags;
   uint16_t adv_window = MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len);

   uint16_t payload_len = 0;
   uint8_t *payload = &flags;
   uint16_t plen = hlen + payload_len;

   uint8_t *msg = create_packet(
       src, dst, seq, ack, hlen, plen, flags, adv_window, payload, payload_len);

   sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
   free(msg);
 }

 bool check_dying(ut_socket_t *sock)
 {
   while (pthread_mutex_lock(&(sock->death_lock)) != 0)
   {
   }
   bool dying = sock->dying;
   if (dying)
   {
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     if (sock->sending_len == 0)
     {
       sock->send_fin_seq = sock->send_win.last_write + 1;
     }
     else
     {
       dying = false;
     }
     pthread_mutex_unlock(&(sock->send_lock));
   }
   pthread_mutex_unlock(&(sock->death_lock));
   return dying;
 }

 void handle_pkt_handshake(ut_socket_t *sock, ut_tcp_header_t *hdr)
 {
   /*
   TODOs:
   * The `handle_pkt_handshake` function processes TCP handshake packets for a given socket.
   * It first extracts the flags from the TCP header and determines whether the socket is an initiator or a listener.
   * If the socket is an initiator, it verifies the SYN-ACK response and updates the send and receive windows accordingly.
   * If the socket is a listener, it handles incoming SYN packets and ACK responses, updating the socket’s state and windows as needed.
   */
   // Extract flags, seq, and ack from the TCP header
   uint8_t flags = get_flags(hdr);

   if (sock->type == TCP_INITIATOR)
   {
     if ((flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) == (SYN_FLAG_MASK | ACK_FLAG_MASK))
     {
       sock->recv_win.next_expect = get_seq(hdr) + 1;
       sock->recv_win.last_read = get_seq(hdr);
       sock->send_win.last_ack = get_ack(hdr) - 1;
       sock->send_win.last_sent = get_ack(hdr) - 1;
       send_empty(sock, ACK_FLAG_MASK, false, false);
       sock->complete_init = true;
     }
   }
   else if (sock->type == TCP_LISTENER)
   {
     if (flags & SYN_FLAG_MASK)
     {
       sock->recv_win.next_expect = get_seq(hdr) + 1;
       sock->recv_win.last_read = get_seq(hdr);
       sock->send_syn = true;
     }
     if (flags & ACK_FLAG_MASK)
     {
       sock->send_win.last_ack = get_ack(hdr) - 1;
       sock->send_win.last_sent = get_ack(hdr) - 1;
       sock->complete_init = true;
     }
   }
 }

 
 void handle_ack(ut_socket_t *sock, ut_tcp_header_t *hdr)
 {
  uint32_t ack = get_ack(hdr);
   if (after(get_ack(hdr) - 1, sock->send_win.last_ack))
   {
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     /*
     TODOs:
     * Reset duplicated ACK count to zero.
     * Update the congestion window.
     * Update the sender window based on the ACK field.
       * Update `last_ack`, re-allocate the sending buffer, and update the `sending_len` field.
     */
     sock->dup_ack_count = 0;

      if (sock->cong_win < sock->slow_start_thresh) {
          sock->cong_win += MSS;
      } else {
          sock->cong_win += MSS * (MSS / sock->cong_win);
      }

        
      uint32_t old_last_ack = sock->send_win.last_ack;
      sock->send_win.last_ack = ack - 1;

      
      uint32_t acked_bytes = sock->send_win.last_ack - old_last_ack;
      if (acked_bytes > 0 && acked_bytes <= sock->sending_len) {
          memmove(sock->sending_buf, sock->sending_buf + acked_bytes, sock->sending_len - acked_bytes);
          sock->sending_len -= acked_bytes;


          if (sock->sending_len > 0) {
            sock->sending_buf = realloc(sock->sending_buf, sock->sending_len);
        } else {
            free(sock->sending_buf);
            sock->sending_buf = NULL;
        }
      }
     pthread_mutex_unlock(&(sock->send_lock));
   }
   // Handle Duplicated ACK.
   else if (get_ack(hdr) - 1 == sock->send_win.last_ack)
   {
     if (sock->dup_ack_count == 3)  // `Fast recovery` state
     {
       sock->cong_win += MSS;
     }
     else // `Slow start` or `Congestion avoidance` state
     {
       /*
       TODOs:
       * Increment the duplicated ACK count (Up to 3).
       * If the duplicated ACK count reaches 3, adjust the congestion window and slow start threshold.
       * Retransmit missing segments using Go-back-N (i.e., update the `last_sent` to `last_ack`).
       */

       sock->dup_ack_count++;

       if (sock->dup_ack_count == 3) {
        sock->slow_start_thresh = sock->cong_win / 2;
        sock->cong_win = sock->slow_start_thresh + 3 * MSS;
        // Retransmit lost segment
        sock->send_win.last_sent = sock->send_win.last_ack;
        sock->dup_ack_count = 0;

    } else if (sock->dup_ack_count > 3) {
        sock->cong_win += MSS;
    } else {
        sock->cong_win += MSS;
    }
     }
   }
 }

 void update_received_buf(ut_socket_t *sock, uint8_t *pkt)
 {
 

   /*
   - This function processes an incoming TCP packet by updating the receive buffer based on the packet's sequence number and payload length.
   - If the new data extends beyond the last received sequence, it reallocates the receive buffer and copies the payload into the correct position.

   TODOs:
   * Extract the TCP header and sequence number from the packet.
   * Determine the end of the data segment and update the receive window if needed.
   * Copy the payload into the receive buffer based on the sequence number:
     * Ensure that the required buffer space does not exceed `MAX_NETWORK_BUFFER` before proceeding.
     * Use `memcpy` to copy the payload:
       memcpy(void *to, const void *from, size_t numBytes);
   * Send an acknowledgment if the packet arrives in order:
     * Use the `send_empty` function to send the acknowledgment.
   */
   ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;
   uint32_t plen = get_plen(hdr);
   uint32_t hlen = get_hlen(hdr);

   if (plen < hlen) {
       return;
   }

   uint32_t payload_len = plen - hlen;
   uint32_t seq = get_seq(hdr);

   if (payload_len == 0) {
       return;
   }

   if (seq <= sock->recv_win.last_read) {
       return;
   }

   uint32_t offset = seq - sock->recv_win.last_read - 1;

   if (offset + payload_len > MAX_NETWORK_BUFFER) {
       return;
   }

   if (sock->received_len < offset + payload_len) {
       uint32_t new_size = offset + payload_len;
       uint8_t *new_buf = realloc(sock->received_buf, new_size);
       if (new_buf == NULL) {
           return;
       }
       sock->received_buf = new_buf;
       sock->received_len = new_size;
   }

   uint8_t *payload = pkt + hlen;

   
   memcpy(sock->received_buf + offset, payload, payload_len);

   uint32_t packet_last_byte = seq + payload_len - 1;
   if (packet_last_byte > sock->recv_win.last_recv) {
       sock->recv_win.last_recv = packet_last_byte;
   }

   if (seq == sock->recv_win.next_expect) {
       sock->recv_win.next_expect = seq + payload_len;
       sock->send_adv_win = MAX_NETWORK_BUFFER - (sock->recv_win.last_recv - sock->recv_win.last_read);
       send_empty(sock, ACK_FLAG_MASK, false, false);
   }

 }

 void handle_pkt(ut_socket_t *sock, uint8_t *pkt)
 {
   ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;
   uint8_t flags = get_flags(hdr);
   uint32_t ack = get_ack(hdr);
   uint32_t seq = get_seq(hdr);

   if (!sock->complete_init)
   {
     handle_pkt_handshake(sock, hdr);
     if (!sock->complete_init)
            return;
   }
     /*
     TODOs:
     * Handle the FIN flag.
       * Mark the socket as having received a FIN, store the sequence number, and send an ACK response.

     * Update the advertised window.
     * Handle the ACK flag. You will have to handle the following cases:
       1) ACK after sending FIN.
         * If the ACK is for the FIN sequence, mark the socket as FIN-ACKed.
       2) ACK after sending data.
         * If the ACK is for a new sequence, update the send window and congestion control (call `handle_ack`).
     * Update the receive buffer (call `update_received_buf`).
     */

    sock->send_adv_win = get_advertised_window(hdr);

     if (flags & FIN_FLAG_MASK) {
      sock->recv_fin = true;
      sock->recv_fin_seq = seq;
      send_empty(sock, ACK_FLAG_MASK, true, false);
    }
  
    if (flags & ACK_FLAG_MASK) {
      if (ack == sock->send_fin_seq + 1) {
        sock->fin_acked = true;
      } else {
        handle_ack(sock, hdr);
      }
    }

  /*
   * Update the advertised window based on the current receive buffer.
   * (This is also used when constructing outgoing packets in send_empty().)
   * Here, we update the receive buffer with the newly received data.
   */
   update_received_buf(sock, pkt);

 }

 void recv_pkts(ut_socket_t *sock)
 {
   ut_tcp_header_t hdr;
   uint8_t *pkt;
   socklen_t conn_len = sizeof(sock->conn);
   ssize_t len = 0, n = 0;
   uint32_t plen = 0, buf_size = 0;

   struct pollfd ack_fd;
   ack_fd.fd = sock->socket;
   ack_fd.events = POLLIN;
   if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) > 0)
   {
     len = recvfrom(sock->socket, &hdr, sizeof(ut_tcp_header_t),
                    MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                    &conn_len);
   }
   else  // TIMEOUT
   {
     /*
     TODOs:
     * Reset duplicated ACK count to zero.
     * Implement the rest of timeout handling
       * Congestion control window and slow start threshold adjustment
       * Adjust the send window for retransmission of lost packets (Go-back-N)
     */
     sock->dup_ack_count = 0;  // Reset duplicate ACK counter

      // Enter Slow Start
      sock->slow_start_thresh = sock->cong_win / 2;
      sock->cong_win = MSS;

      // Go-back-N retransmit
      sock->send_win.last_sent = sock->send_win.last_ack;
      return;
   }

   if (len >= (ssize_t)sizeof(ut_tcp_header_t))
   {
     plen = get_plen(&hdr);
     pkt = malloc(plen);
     while (buf_size < plen)
     {
       n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                    (struct sockaddr *)&(sock->conn), &conn_len);
       buf_size = buf_size + n;
     }
     while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
     {
     }
     handle_pkt(sock, pkt);
     pthread_mutex_unlock(&(sock->recv_lock));
     free(pkt);
   }
 }

 void send_pkts_handshake(ut_socket_t *sock)
 {
   /*
   TODOs:
   * Implement the handshake initialization logic.
   * We provide an example of sending a SYN packet by the initiator below:
   */
  if (sock->type == TCP_INITIATOR)
  {
    if (sock->send_syn)
    {
      send_empty(sock, SYN_FLAG_MASK, false, false);
      sock->send_syn = false;
    }
  }
  else if (sock->type == TCP_LISTENER)
  {
    if (sock->send_syn)
    {
      send_empty(sock, SYN_FLAG_MASK | ACK_FLAG_MASK, false, false);
      sock->send_syn = false;
    }
  }
 }

 void send_pkts_data(ut_socket_t *sock)
 {
   /*
   * Sends packets of data over a TCP connection.
   * This function handles the transmission of data packets over a TCP connection
     using the provided socket. It ensures that the data is sent within the constraints
     of the congestion window, advertised window, and maximum segment size (MSS).

   TODOs:
   * Calculate the available window size for sending data based on the congestion window,
     advertised window, and the amount of data already sent.
   * Iterate the following steps until the available window size is consumed in the sending buffer:
     * Create and send packets with appropriate sequence and acknowledgment numbers,
       ensuring the payload length does not exceed the available window or MSS.
       * Refer to the send_empty function for guidance on creating and sending packets.
     * Update the last sent sequence number after each packet is sent.
   */

   //Calculate window size
   if (sock->sending_buf == NULL) {
      return;
    }
   uint32_t base_window = MIN(sock->cong_win, sock->send_adv_win);
   uint32_t available_window = base_window - (sock->send_win.last_sent - sock->send_win.last_ack);
   while (available_window > 0 && sock->send_win.last_sent < sock->send_win.last_write) {
    uint32_t to_send = MIN(available_window, sock->send_win.last_write - sock->send_win.last_sent);
    uint32_t payload_len = MIN(to_send, MSS);

    uint8_t *payload_ptr = sock->sending_buf + (sock->send_win.last_sent - sock->send_win.last_ack);

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t seq = sock->send_win.last_sent + 1;
    uint32_t ack = sock->recv_win.next_expect;
    uint8_t flags = 0;

    uint16_t hlen = sizeof(ut_tcp_header_t);
    uint16_t plen = hlen + payload_len;

    uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, plen, flags, sock->send_adv_win, payload_ptr, payload_len);

    sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn), sizeof(sock->conn));

    sock->send_win.last_sent += payload_len;
    available_window -= payload_len;

    free(pkt);
  }
 }
 
 
 void send_pkts(ut_socket_t *sock)
 {
   if (!sock->complete_init)
   {
     send_pkts_handshake(sock);
   }
   else
   {
     // Stop sending when duplicated ACKs are received and not in fast recovery state.
     if (sock->dup_ack_count < 3 && sock->dup_ack_count > 0)
       return;
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     send_pkts_data(sock);
     pthread_mutex_unlock(&(sock->send_lock));
   }
 }

 void *begin_backend(void *in)
 {
   ut_socket_t *sock = (ut_socket_t *)in;
   int death, buf_len, send_signal;
   uint8_t *data;

   while (1)
   {
     if (check_dying(sock))
     {
       if (!sock->fin_acked)
       {
         send_empty(sock, FIN_FLAG_MASK, false, true);
       }
     }

     if (sock->fin_acked && sock->recv_fin)
     {
       // Finish the connection after timeout
       sleep(DEFAULT_TIMEOUT / 1000);
       break;
     }
     send_pkts(sock);
     recv_pkts(sock);
     while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
     {
     }
     uint32_t avail = sock->recv_win.next_expect - sock->recv_win.last_read - 1;
     send_signal = avail > 0;
     pthread_mutex_unlock(&(sock->recv_lock));

     if (send_signal)
     {
       pthread_cond_signal(&(sock->wait_cond));
     }
   }
   pthread_exit(NULL);
   return NULL;
 }