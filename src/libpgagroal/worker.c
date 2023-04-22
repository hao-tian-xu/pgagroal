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
#include <memory.h>
#include <message.h>
#include <network.h>
#include <pipeline.h>
#include <pool.h>
#include <prometheus.h>
#include <security.h>
#include <tracker.h>
#include <worker.h>
#include <utils.h>

/* system */
#include <ev.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <openssl/ssl.h>

volatile int running = 1;
volatile int exit_code = WORKER_FAILURE;

static void signal_cb(struct ev_loop* loop, ev_signal* w, int revents);

// The pgagroal_worker function is responsible for processing client connections
// after successful authentication, managing the event loop and handling I/O
void
pgagroal_worker(int client_fd, char* address, char** argv)
{
   // Declare necessary variables
   struct ev_loop* loop = NULL;        // Event loop for this worker
   struct signal_info signal_watcher;  // Signal watcher for the worker
   struct worker_io client_io;         // Worker I/O structure for the client
   struct worker_io server_io;         // Worker I/O structure for the server
   time_t start_time;                  // Time when the worker started processing
   bool started = false;               // Flag to indicate whether the worker has started
   int auth_status;                    // Authentication status
   struct configuration* config;       // Pointer to the configuration structure in shared memory
   struct pipeline p;                  // Pipeline structure
   bool tx_pool = false;               // Flag to indicate if the connection is part of a transaction pool
   int32_t slot = -1;                  // Slot index in the connection pool
   SSL* client_ssl = NULL;             // SSL object for the client connection
   SSL* server_ssl = NULL;             // SSL object for the server connection

   // Initialize logging and memory management
   pgagroal_start_logging();
   pgagroal_memory_init();

   // Get the configuration from shared memory
   config = (struct configuration*)shmem;

   // Initialize client_io and server_io structures
   memset(&client_io, 0, sizeof(struct worker_io));
   memset(&server_io, 0, sizeof(struct worker_io));

   client_io.slot = -1;
   server_io.slot = -1;

   // Get the start time of the worker
   start_time = time(NULL);

   // Log the start of the worker in the tracking system
   pgagroal_tracking_event_basic(TRACKER_CLIENT_START, NULL, NULL);
   pgagroal_tracking_event_socket(TRACKER_SOCKET_ASSOCIATE_CLIENT, client_fd);
   // Set the process title to indicate the worker is authenticating the client
   pgagroal_set_proc_title(1, argv, "authenticating", NULL);

   // Update Prometheus metrics: increment the number of waiting clients
   pgagroal_prometheus_client_wait_add();
   // Authenticate the client and get the corresponding slot in the connection pool
   /* Authentication */
   auth_status = pgagroal_authenticate(client_fd, address, &slot, &client_ssl, &server_ssl);
   // If authentication is successful
   if (auth_status == AUTH_SUCCESS)
   {
      // Log the slot assignment for debugging
      pgagroal_log_debug("pgagroal_worker: Slot %d (%d -> %d)", slot, client_fd, config->connections[slot].fd);

      // Associate the server socket with the tracker
      pgagroal_tracking_event_socket(TRACKER_SOCKET_ASSOCIATE_SERVER, config->connections[slot].fd);

      // Log the connection details if enabled in the configuration
      if (config->log_connections)
      {
         pgagroal_log_info("connect: user=%s database=%s address=%s", config->connections[slot].username,
                           config->connections[slot].database, address);
      }

      // Update Prometheus metrics: decrement waiting clients, increment active clients
      pgagroal_prometheus_client_wait_sub();
      pgagroal_prometheus_client_active_add();

      // Log the connection pool status
      pgagroal_pool_status();

      // Update the process title based on the configuration setting
      // do we have to update the process title?
      switch (config->update_process_title)
      {
         case UPDATE_PROCESS_TITLE_MINIMAL:
         case UPDATE_PROCESS_TITLE_STRICT:
            // pgagroal_set_proc_title will check the policy
            pgagroal_set_proc_title(1, argv, config->connections[slot].username, config->connections[slot].database);
            break;
         case UPDATE_PROCESS_TITLE_VERBOSE:
            pgagroal_set_connection_proc_title(1, argv, &config->connections[slot]);
            break;
      }

      // Set the pipeline to be used based on the configuration
      if (config->pipeline == PIPELINE_PERFORMANCE)
      {
         p = performance_pipeline();
      }
      else if (config->pipeline == PIPELINE_SESSION)
      {
         p = session_pipeline();
      }
      else if (config->pipeline == PIPELINE_TRANSACTION)
      {
         p = transaction_pipeline();
         tx_pool = true;
      }
      else
      {
         pgagroal_log_error("pgagroal_worker: Unknown pipeline %d", config->pipeline);
         p = session_pipeline();
      }

      // Initialize the client I/O watcher and set its associated data
      ev_io_init((struct ev_io*)&client_io, p.client, client_fd, EV_READ);
      client_io.client_fd = client_fd;
      client_io.server_fd = config->connections[slot].fd;
      client_io.slot = slot;
      client_io.client_ssl = client_ssl;
      client_io.server_ssl = server_ssl;

      // Initialize the server I/O watcher and set its associated data (if not using a transaction pipeline)
      if (config->pipeline != PIPELINE_TRANSACTION)
      {
         ev_io_init((struct ev_io*)&server_io, p.server, config->connections[slot].fd, EV_READ);
         server_io.client_fd = client_fd;
         server_io.server_fd = config->connections[slot].fd;
         server_io.slot = slot;
         server_io.client_ssl = client_ssl;
         server_io.server_ssl = server_ssl;
      }

      // Create a new event loop
      loop = ev_loop_new(pgagroal_libev(config->libev));

      // Initialize and start the signal watcher
      ev_signal_init((struct ev_signal*)&signal_watcher, signal_cb, SIGQUIT);
      signal_watcher.slot = slot;
      ev_signal_start(loop, (struct ev_signal*)&signal_watcher);

      // Start the pipeline processing
      p.start(loop, &client_io);
      started = true;

      // Start the client I/O watcher
      ev_io_start(loop, (struct ev_io*)&client_io);
      // Start the server I/O watcher (if not using a transaction pipeline)
      if (config->pipeline != PIPELINE_TRANSACTION)
      {
         ev_io_start(loop, (struct ev_io*)&server_io);
      }

      // Main event loop
      while (running)
      {
         ev_loop(loop, 0);
      }

      // If using a transaction pipeline, update the slot as it may have changed
      if (config->pipeline == PIPELINE_TRANSACTION)
      {
         /* The slot may have been updated */
         slot = client_io.slot;
      }

      // Update Prometheus metrics: decrement the number of active clients
      pgagroal_prometheus_client_active_sub();
   }
   // Authentication fails
   else
   {
      if (config->log_connections)
      {
         pgagroal_log_info("connect: address=%s", address);
      }
      pgagroal_prometheus_client_wait_sub();
   }

   // Log disconnections if enabled in the configuration
   if (config->log_disconnections)
   {
      if (auth_status == AUTH_SUCCESS)
      {
         pgagroal_log_info("disconnect: user=%s database=%s address=%s", config->connections[slot].username,
                           config->connections[slot].database, address);
      }
      else
      {
         pgagroal_log_info("disconnect: address=%s", address);
      }
   }

   // Return connection to the pool or kill it based on the exit_code
   /* Return to pool */
   if (slot != -1)
   {
      // If the pipeline processing started, stop it
      if (started)
      {
         p.stop(loop, &client_io);

         pgagroal_prometheus_session_time(difftime(time(NULL), start_time));
      }

      // Check the conditions for returning the connection to the pool
      if ((auth_status == AUTH_SUCCESS || auth_status == AUTH_BAD_PASSWORD) &&
          (exit_code == WORKER_SUCCESS || exit_code == WORKER_CLIENT_FAILURE ||
           (exit_code == WORKER_FAILURE && config->connections[slot].has_security != SECURITY_INVALID)))
      {
         if (config->pipeline != PIPELINE_TRANSACTION)
         {
            pgagroal_tracking_event_socket(TRACKER_SOCKET_DISASSOCIATE_SERVER, config->connections[slot].fd);
            pgagroal_tracking_event_slot(TRACKER_WORKER_RETURN1, slot);
            pgagroal_return_connection(slot, server_ssl, tx_pool);
         }
      }
      // Check the conditions for killing the connection
      else if (exit_code == WORKER_SERVER_FAILURE || exit_code == WORKER_SERVER_FATAL || exit_code == WORKER_SHUTDOWN || exit_code == WORKER_FAILOVER ||
               (exit_code == WORKER_FAILURE && config->connections[slot].has_security == SECURITY_INVALID))
      {
         pgagroal_tracking_event_socket(TRACKER_SOCKET_DISASSOCIATE_SERVER, config->connections[slot].fd);
         pgagroal_tracking_event_slot(TRACKER_WORKER_KILL1, slot);
         pgagroal_kill_connection(slot, server_ssl);
      }
      // Check the conditions for returning or killing the connection
      else
      {
         if (pgagroal_socket_isvalid(config->connections[slot].fd) &&
             pgagroal_connection_isvalid(config->connections[slot].fd) &&
             config->connections[slot].has_security != SECURITY_INVALID)
         {
            pgagroal_tracking_event_socket(TRACKER_SOCKET_DISASSOCIATE_SERVER, config->connections[slot].fd);
            pgagroal_tracking_event_slot(TRACKER_WORKER_RETURN2, slot);
            pgagroal_return_connection(slot, server_ssl, tx_pool);
         }
         else
         {
            pgagroal_tracking_event_socket(TRACKER_SOCKET_DISASSOCIATE_SERVER, config->connections[slot].fd);
            pgagroal_tracking_event_slot(TRACKER_WORKER_KILL2, slot);
            pgagroal_kill_connection(slot, server_ssl);
         }
      }
   }

   // Notify management that the client processing is done
   pgagroal_management_client_done(getpid());

   // Clean up the client SSL resources, if used
   if (client_ssl != NULL)
   {
      int res;
      SSL_CTX* ctx = SSL_get_SSL_CTX(client_ssl);
      res = SSL_shutdown(client_ssl);
      if (res == 0)
      {
         SSL_shutdown(client_ssl);
      }
      SSL_free(client_ssl);
      SSL_CTX_free(ctx);
   }

   // Log the client disconnection and disassociate the client socket
   pgagroal_log_debug("client disconnect: %d", client_fd);
   pgagroal_tracking_event_socket(TRACKER_SOCKET_DISASSOCIATE_CLIENT, client_fd);
   pgagroal_disconnect(client_fd);

   // Update Prometheus metrics for client sockets and reset query count for the slot
   pgagroal_prometheus_client_sockets_sub();
   pgagroal_prometheus_query_count_specified_reset(slot);

   // Display the pool status and log debug information
   pgagroal_pool_status();
   pgagroal_log_debug("After client: PID %d Slot %d (%d)", getpid(), slot, exit_code);

   // Clean up libev resources, if a loop was created
   if (loop)
   {
      ev_io_stop(loop, (struct ev_io*)&client_io);
      if (config->pipeline != PIPELINE_TRANSACTION)
      {
         ev_io_stop(loop, (struct ev_io*)&server_io);
      }

      ev_signal_stop(loop, (struct ev_signal*)&signal_watcher);

      ev_loop_destroy(loop);
   }

   // Free the allocated memory for the address
   free(address);

   // Log the client stop event
   pgagroal_tracking_event_basic(TRACKER_CLIENT_STOP, NULL, NULL);

   // Clean up memory resources and stop logging
   pgagroal_memory_destroy();
   pgagroal_stop_logging();

   // Exit the worker process with the exit code
   exit(exit_code);
}

static void
signal_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
   struct signal_info* si;

   si = (struct signal_info*)w;

   pgagroal_log_debug("pgagroal: signal %d for slot %d", si->signal.signum, si->slot);

   exit_code = WORKER_SHUTDOWN;
   running = 0;
   ev_break(loop, EVBREAK_ALL);
}
