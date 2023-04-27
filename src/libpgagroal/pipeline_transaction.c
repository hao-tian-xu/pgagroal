/*
 * Copyright (C) 2023 Red Hat
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgagroal */
#include <pgagroal.h>
#include <logging.h>
#include <management.h>
#include <message.h>
#include <network.h>
#include <pipeline.h>
#include <pool.h>
#include <prometheus.h>
#include <server.h>
#include <shmem.h>
#include <tracker.h>
#include <worker.h>
#include <utils.h>

/* system */
#include <errno.h>
#include <ev.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

static int  transaction_initialize(void*, void**, size_t*);
static void transaction_start(struct ev_loop* loop, struct worker_io*);
static void transaction_client(struct ev_loop* loop, struct ev_io* watcher, int revents);
static void transaction_server(struct ev_loop* loop, struct ev_io* watcher, int revents);
static void transaction_stop(struct ev_loop* loop, struct worker_io*);
static void transaction_destroy(void*, size_t);
static void transaction_periodic(void);

static void start_mgt(struct ev_loop* loop);
static void shutdown_mgt(struct ev_loop* loop);
static void accept_cb(struct ev_loop* loop, struct ev_io* watcher, int revents);

static int slot;
static char username[MAX_USERNAME_LENGTH];
static char database[MAX_DATABASE_LENGTH];
static char appname[MAX_APPLICATION_NAME];
static bool in_tx;
static int next_client_message;
static int next_server_message;
static int unix_socket = -1;
static int deallocate;
static bool fatal;
static int fds[MAX_NUMBER_OF_CONNECTIONS];
static bool saw_x = false;
static struct ev_io io_mgt;
static struct worker_io server_io;

struct pipeline
transaction_pipeline(void)
{
   struct pipeline pipeline;

   pipeline.initialize = &transaction_initialize;
   pipeline.start = &transaction_start;
   pipeline.client = &transaction_client;
   pipeline.server = &transaction_server;
   pipeline.stop = &transaction_stop;
   pipeline.destroy = &transaction_destroy;
   pipeline.periodic = &transaction_periodic;

   return pipeline;
}

static int
transaction_initialize(void* shmem, void** pipeline_shmem, size_t* pipeline_shmem_size)
{
   return 0;
}

static void
transaction_start(struct ev_loop* loop, struct worker_io* w)
{
   // Declare local variables
   char p[MISC_LENGTH];
   bool is_new;
   struct configuration* config = NULL;

   config = (struct configuration*)shmem;

   // Initialize local variables
   slot = -1;
   memcpy(&username[0], config->connections[w->slot].username, MAX_USERNAME_LENGTH);
   memcpy(&database[0], config->connections[w->slot].database, MAX_DATABASE_LENGTH);
   memcpy(&appname[0], config->connections[w->slot].appname, MAX_APPLICATION_NAME);
   in_tx = false;
   next_client_message = 0;
   next_server_message = 0;
   deallocate = false;

   // Prepare the UNIX socket path
   memset(&p, 0, sizeof(p));
   snprintf(&p[0], sizeof(p), ".s.%d", getpid());

   // Bind to the UNIX socket
   if (pgagroal_bind_unix_socket(config->unix_socket_dir, &p[0], &unix_socket))
   {
      pgagroal_log_fatal("pgagroal: Could not bind to %s/%s", config->unix_socket_dir, &p[0]);
      goto error;
   }

   // Copy file descriptors from the shared configuration into a local array
   for (int i = 0; i < config->max_connections; i++)
   {
      fds[i] = config->connections[i].fd;
   }

   // Start the management event loop
   start_mgt(loop);

   // Log a tracking event for the start of the transaction
   pgagroal_tracking_event_slot(TRACKER_TX_RETURN_CONNECTION_START, w->slot);

   // Store whether the connection in the slot is new
   is_new = config->connections[w->slot].new;
   // Return the connection to the connection pool
   pgagroal_return_connection(w->slot, w->server_ssl, true);

   // Reset worker_io structure fields
   w->server_fd = -1;
   w->slot = -1;

   // If the connection is new, sleep for 5ms to allow the connection to stabilize
   if (is_new)
   {
      /* Sleep for 5ms */
      SLEEP(5000000L)
   }

   return;

error:

   // In case of an error, set the exit_code, stop the loop and return
   exit_code = WORKER_FAILURE;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;
}

static void
transaction_stop(struct ev_loop* loop, struct worker_io* w)
{
   if (slot != -1)
   {
      struct configuration* config = NULL;

      config = (struct configuration*)shmem;

      /* We are either in 'X' or the client terminated (consider cancel query) */
      if (in_tx)
      {
         /* ROLLBACK */
         pgagroal_write_rollback(NULL, config->connections[slot].fd);
      }

      ev_io_stop(loop, (struct ev_io*)&server_io);
      pgagroal_tracking_event_slot(TRACKER_TX_RETURN_CONNECTION_STOP, w->slot);
      pgagroal_return_connection(slot, w->server_ssl, true);
      slot = -1;
   }

   shutdown_mgt(loop);
}

static void
transaction_destroy(void* pipeline_shmem, size_t pipeline_shmem_size)
{
}

static void
transaction_periodic(void)
{
}

static void
transaction_client(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   int status = MESSAGE_STATUS_ERROR;
   SSL* s_ssl = NULL;
   struct worker_io* wi = NULL;
   struct message* msg = NULL;
   struct configuration* config = NULL;

   // Retrieve the worker_io object from the watcher
   wi = (struct worker_io*)watcher;
   // Retrieve the configuration from shared memory
   config = (struct configuration*)shmem;

   // Check if the slot is not yet set
   /* We can't use the information from wi except from client_fd/client_ssl */
   if (slot == -1)
   {
      // Try to get a connection
      pgagroal_tracking_event_basic(TRACKER_TX_GET_CONNECTION, &username[0], &database[0]);
      if (pgagroal_get_connection(&username[0], &database[0], true, true, &slot, &s_ssl))
      {
         // Write a "pool full" message if getting the connection fails
         pgagroal_write_pool_full(wi->client_ssl, wi->client_fd);
         goto get_error;
      }

      // Set the server file descriptor, SSL object, and slot in the worker_io object
      wi->server_fd = config->connections[slot].fd;
      wi->server_ssl = s_ssl;
      wi->slot = slot;

      // Copy the application name to the connection
      memcpy(&config->connections[slot].appname[0], &appname[0], MAX_APPLICATION_NAME);

      // Initialize the server_io event watcher for the transaction_server function
      ev_io_init((struct ev_io*)&server_io, transaction_server, config->connections[slot].fd, EV_READ);
      server_io.client_fd = wi->client_fd;
      server_io.server_fd = config->connections[slot].fd;
      server_io.slot = slot;
      server_io.client_ssl = wi->client_ssl;
      server_io.server_ssl = wi->server_ssl;

      fatal = false;

      // Start the server_io event watcher
      ev_io_start(loop, (struct ev_io*)&server_io);
   }

   // Read a message from the client
   if (wi->client_ssl == NULL)
   {
      status = pgagroal_read_socket_message(wi->client_fd, &msg);
   }
   else
   {
      status = pgagroal_read_ssl_message(wi->client_ssl, &msg);
   }
   // Check if the message read was successful
   if (likely(status == MESSAGE_STATUS_OK))
   {
      pgagroal_prometheus_network_sent_add(msg->length);

      // If the message is not a termination message
      if (likely(msg->kind != 'X'))
      {
         int offset = 0;

         // Process the client message
         while (offset < msg->length)
         {
            if (next_client_message == 0)
            {
               char kind = pgagroal_read_byte(msg->data + offset);
               int length = pgagroal_read_int32(msg->data + offset + 1);

               // Check if the configuration is set to track prepared statements
               if (config->track_prepared_statements)
               {
                  // Check if the message is a prepared statement message
                  /* The P message tell us the prepared statement */
                  if (kind == 'P')
                  {
                     char* ps = pgagroal_read_string(msg->data + offset + 5);
                     if (strcmp(ps, ""))
                     {
                        deallocate = true;
                     }
                  }
               }

               /* The Q and E message tell us the execute of the simple query and the prepared statement */
               if (kind == 'Q' || kind == 'E')
               {
                  // Update the Prometheus metric for query count and slot-specific query count
                  pgagroal_prometheus_query_count_add();
                  pgagroal_prometheus_query_count_specified_add(wi->slot);
               }

               /* Calculate the offset to the next message */
               if (offset + length + 1 <= msg->length)
               {
                  next_client_message = 0;
                  offset += length + 1;
               }
               else
               {
                  // Update the offset based on the remaining next_client_message value
                  next_client_message = length + 1 - (msg->length - offset);
                  offset = msg->length;
               }
            }
            else
            {
               offset = MIN(next_client_message, msg->length);
               next_client_message -= offset;
            }
         }

         // Write the message to the server
         if (wi->server_ssl == NULL)
         {
            status = pgagroal_write_socket_message(wi->server_fd, msg);
         }
         else
         {
            status = pgagroal_write_ssl_message(wi->server_ssl, msg);
         }
         // Check if the message writing to the server was unsuccessful
         if (unlikely(status == MESSAGE_STATUS_ERROR))
         {
            if (config->failover)
            {
               // Perform failover if the configuration allows it
               pgagroal_server_failover(slot);
               pgagroal_write_client_failover(wi->client_ssl, wi->client_fd);
               pgagroal_prometheus_failed_servers();

               goto failover;
            }
            else
            {
               goto server_error;
            }
         }
      }
      // If the message is a termination message
      else if (msg->kind == 'X')
      {
         saw_x = true;
         running = 0;
      }
   }
   // Handle the case where the message read status is zero
   else if (status == MESSAGE_STATUS_ZERO)
   {
      goto client_done;
   }
   // Handle client errors
   else
   {
      goto client_error;
   }

   // Break the loop and stop processing events after a single iteration
   ev_break(loop, EVBREAK_ONE);
   return;

client_done:
   pgagroal_log_debug("[C] Client done (slot %d database %s user %s): %s (socket %d status %d)",
                      wi->slot, config->connections[wi->slot].database, config->connections[wi->slot].username,
                      strerror(errno), wi->client_fd, status);
   errno = 0;

   // Set the exit code based on whether the termination message was received
   if (saw_x)
   {
      exit_code = WORKER_SUCCESS;
   }
   else
   {
      exit_code = WORKER_SERVER_FAILURE;
   }

   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

client_error:
   pgagroal_log_warn("[C] Client error (slot %d database %s user %s): %s (socket %d status %d)",
                     wi->slot, config->connections[wi->slot].database, config->connections[wi->slot].username,
                     strerror(errno), wi->client_fd, status);
   pgagroal_log_message(msg);
   errno = 0;

   exit_code = WORKER_CLIENT_FAILURE;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

server_error:
   pgagroal_log_warn("[C] Server error (slot %d database %s user %s): %s (socket %d status %d)",
                     wi->slot, config->connections[wi->slot].database, config->connections[wi->slot].username,
                     strerror(errno), wi->server_fd, status);
   pgagroal_log_message(msg);
   errno = 0;

   exit_code = WORKER_SERVER_FAILURE;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

failover:

   exit_code = WORKER_FAILOVER;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

get_error:
   pgagroal_log_warn("Failure during obtaining connection");

   exit_code = WORKER_SERVER_FAILURE;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;
}

static void
transaction_server(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   int status = MESSAGE_STATUS_ERROR;
   bool has_z = false;
   struct worker_io* wi = NULL;
   struct message* msg = NULL;
   struct configuration* config = NULL;

   wi = (struct worker_io*)watcher;
   config = (struct configuration*)shmem;

   // Set server_fd and slot from the configuration
   /* We can't use the information from wi except from client_fd/client_ssl */
   wi->server_fd = config->connections[slot].fd;
   wi->slot = slot;

   // Check if the client socket is valid
   if (!pgagroal_socket_isvalid(wi->client_fd))
   {
      goto client_error;
   }

   // Read a message from the server, either via a socket or SSL
   if (wi->server_ssl == NULL)
   {
      status = pgagroal_read_socket_message(wi->server_fd, &msg);
   }
   else
   {
      status = pgagroal_read_ssl_message(wi->server_ssl, &msg);
   }
   // If the message was read successfully
   if (likely(status == MESSAGE_STATUS_OK))
   {
      // Update Prometheus network received metric
      pgagroal_prometheus_network_received_add(msg->length);

      int offset = 0;

      // Iterate through the message
      while (offset < msg->length)
      {
         if (next_server_message == 0)
         {
            // Read message kind and length
            char kind = pgagroal_read_byte(msg->data + offset);
            int length = pgagroal_read_int32(msg->data + offset + 1);

            // Check if the message is a transaction state message
            /* The Z message tell us the transaction state */
            if (kind == 'Z')
            {
               char tx_state = pgagroal_read_byte(msg->data + offset + 5);

               has_z = true;

               // If the transaction state is not idle and not currently in a transaction
               if (tx_state != 'I' && !in_tx)
               {
                  // Update Prometheus transaction count metric
                  pgagroal_prometheus_tx_count_add();
               }

               // Update in_tx to reflect the current transaction state
               in_tx = tx_state != 'I';
            }

            /* Calculate the offset to the next message */
            if (offset + length + 1 <= msg->length)
            {
               next_server_message = 0;
               offset += length + 1;
            }
            else
            {
               next_server_message = length + 1 - (msg->length - offset);
               offset = msg->length;
            }
         }
         else
         {
            // Move to the next server message
            offset = MIN(next_server_message, msg->length);
            next_server_message -= offset;
         }
      }

      // Write the message to the client, either via a socket or SSL
      if (wi->client_ssl == NULL)
      {
         status = pgagroal_write_socket_message(wi->client_fd, msg);
      }
      else
      {
         status = pgagroal_write_ssl_message(wi->client_ssl, msg);
      }
      // If the message writing failed, go to the client_error label
      if (unlikely(status != MESSAGE_STATUS_OK))
      {
         goto client_error;
      }

      // Check if the message is an error message and if it is fatal or panic
      if (unlikely(msg->kind == 'E'))
      {
         if (!strncmp(msg->data + 6, "FATAL", 5) || !strncmp(msg->data + 6, "PANIC", 5))
         {
            fatal = true;
         }
      }

      // If not fatal
      if (!fatal)
      {
         // If there is a transaction state message indicating not in a transaction, and the slot is valid
         if (has_z && !in_tx && slot != -1)
         {
            // Stop the server_io event watcher
            ev_io_stop(loop, (struct ev_io*)&server_io);

            // If deallocate flag is set, send deallocate all message to the server
            if (deallocate)
            {
               pgagroal_write_deallocate_all(wi->server_ssl, wi->server_fd);
               deallocate = false;
            }

            // Send a tracking event for returning the connection to the pool
            pgagroal_tracking_event_slot(TRACKER_TX_RETURN_CONNECTION, slot);
            // Return the connection to the pool
            if (pgagroal_return_connection(slot, wi->server_ssl, true))
            {
               goto return_error;
            }

            slot = -1;
         }
      }
      // If the error is fatal
      else
      {
         // If there is a transaction state message indicating not in a transaction, and the slot is valid
         if (has_z && !in_tx && slot != -1)
         {
            // Stop the server_io event watcher
            ev_io_stop(loop, (struct ev_io*)&server_io);

            // Set the exit code and stop the loop
            exit_code = WORKER_SERVER_FATAL;
            running = 0;
         }
      }
   }
   // If the message status is zero, go to the server_done label
   else if (status == MESSAGE_STATUS_ZERO)
   {
      goto server_done;
   }
   // If the message status is an error, go to the server_error label
   else
   {
      goto server_error;
   }

   // Break the event loop
   ev_break(loop, EVBREAK_ONE);
   return;

client_error:
   pgagroal_log_warn("[S] Client error (slot %d database %s user %s): %s (socket %d status %d)",
                     wi->slot, config->connections[wi->slot].database, config->connections[wi->slot].username,
                     strerror(errno), wi->client_fd, status);
   pgagroal_log_message(msg);
   errno = 0;

   exit_code = WORKER_CLIENT_FAILURE;
   // set the running flag to 0 to stop the loop
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

server_done:
   pgagroal_log_debug("[S] Server done (slot %d database %s user %s): %s (socket %d status %d)",
                      wi->slot, config->connections[wi->slot].database, config->connections[wi->slot].username,
                      strerror(errno), wi->server_fd, status);
   errno = 0;

   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

server_error:
   pgagroal_log_warn("[S] Server error (slot %d database %s user %s): %s (socket %d status %d)",
                     wi->slot, config->connections[wi->slot].database, config->connections[wi->slot].username,
                     strerror(errno), wi->server_fd, status);
   pgagroal_log_message(msg);
   errno = 0;

   exit_code = WORKER_SERVER_FAILURE;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;

return_error:
   pgagroal_log_warn("Failure during connection return");

   exit_code = WORKER_SERVER_FAILURE;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
   return;
}

static void
start_mgt(struct ev_loop* loop)
{
   memset(&io_mgt, 0, sizeof(struct ev_io));
   ev_io_init(&io_mgt, accept_cb, unix_socket, EV_READ);
   ev_io_start(loop, &io_mgt);
}

static void
shutdown_mgt(struct ev_loop* loop)
{
   char p[MISC_LENGTH];
   struct configuration* config = NULL;

   config = (struct configuration*)shmem;

   memset(&p, 0, sizeof(p));
   snprintf(&p[0], sizeof(p), ".s.%d", getpid());

   ev_io_stop(loop, &io_mgt);
   pgagroal_disconnect(unix_socket);
   errno = 0;
   pgagroal_remove_unix_socket(config->unix_socket_dir, &p[0]);
   errno = 0;
}

static void
accept_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   // Declare local variables
   struct sockaddr_in client_addr;
   socklen_t client_addr_length;
   int client_fd;
   signed char id;
   int32_t payload_slot;
   int payload_i;
   char* payload_s = NULL;
   struct configuration* config = NULL;

   config = (struct configuration*)shmem;

   // Check for invalid events
   if (EV_ERROR & revents)
   {
      pgagroal_log_debug("accept_cb: invalid event: %s", strerror(errno));
      errno = 0;
      return;
   }

   // Process the management request
   // Accept the incoming connection
   client_addr_length = sizeof(client_addr);
   client_fd = accept(watcher->fd, (struct sockaddr*)&client_addr, &client_addr_length);
   if (client_fd == -1)
   {
      pgagroal_log_debug("accept: %s (%d)", strerror(errno), watcher->fd);
      errno = 0;
      return;
   }

   /* Process management request */
   pgagroal_management_read_header(client_fd, &id, &payload_slot);
   pgagroal_management_read_payload(client_fd, id, &payload_i, &payload_s);

   // Switch statement to handle different management request types
   switch (id)
   {
      case MANAGEMENT_CLIENT_FD:
         pgagroal_log_debug("pgagroal: Management client file descriptor: Slot %d FD %d", payload_slot, payload_i);
         fds[payload_slot] = payload_i;
         break;
      case MANAGEMENT_REMOVE_FD:
         pgagroal_log_debug("pgagroal: Management remove file descriptor: Slot %d FD %d", payload_slot, payload_i);
         if (fds[payload_slot] == payload_i && !config->connections[payload_slot].new && config->connections[payload_slot].fd > 0)
         {
            pgagroal_disconnect(payload_i);
            fds[payload_slot] = 0;
         }
         break;
      default:
         pgagroal_log_debug("pgagroal: Unsupported management id: %d", id);
         break;
   }

   // Close the client connection
   pgagroal_disconnect(client_fd);
}
