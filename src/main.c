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
#include <configuration.h>
#include <logging.h>
#include <management.h>
#include <network.h>
#include <pipeline.h>
#include <pool.h>
#include <prometheus.h>
#include <remote.h>
#include <security.h>
#include <server.h>
#include <shmem.h>
#include <utils.h>
#include <worker.h>

/* system */
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <err.h>

#include <openssl/crypto.h>
#ifdef HAVE_LINUX
#include <systemd/sd-daemon.h>
#endif

#define MAX_FDS 64

static void accept_main_cb(struct ev_loop* loop, struct ev_io* watcher, int revents);
static void accept_mgt_cb(struct ev_loop* loop, struct ev_io* watcher, int revents);
static void accept_metrics_cb(struct ev_loop* loop, struct ev_io* watcher, int revents);
static void accept_management_cb(struct ev_loop* loop, struct ev_io* watcher, int revents);
static void shutdown_cb(struct ev_loop* loop, ev_signal* w, int revents);
static void reload_cb(struct ev_loop* loop, ev_signal* w, int revents);
static void graceful_cb(struct ev_loop* loop, ev_signal* w, int revents);
static void coredump_cb(struct ev_loop* loop, ev_signal* w, int revents);
static void idle_timeout_cb(struct ev_loop* loop, ev_periodic* w, int revents);
static void max_connection_age_cb(struct ev_loop* loop, ev_periodic* w, int revents);
static void validation_cb(struct ev_loop* loop, ev_periodic* w, int revents);
static void disconnect_client_cb(struct ev_loop* loop, ev_periodic* w, int revents);
static bool accept_fatal(int error);
static void add_client(pid_t pid);
static void remove_client(pid_t pid);
static void reload_configuration(void);
static void create_pidfile_or_exit(void);
static void remove_pidfile(void);
static void shutdown_ports(void);

struct accept_io
{
   struct ev_io io;
   int socket;
   char** argv;
};

struct client
{
   pid_t pid;
   struct client* next;
};

static volatile int keep_running = 1;              // a volatile integer flag that controls the main loop's execution. // memo: The volatile keyword in C is a type qualifier that informs the compiler not to optimize the object it is applied to, ensuring that the object's value is always read from memory and not cached in a CPU register. This is particularly useful when the value of the variable may change due to external factors, such as signal handlers or concurrent threads, outside the normal flow of the program.
static char** argv_ptr;                            // a pointer to the command-line arguments passed to the main function.
static struct ev_loop* main_loop = NULL;           // a pointer to the main event loop used by the libev library.
static struct accept_io io_main[MAX_FDS];          // an array of accept_io structures, storing information related to the main file descriptors (sockets).
static struct accept_io io_mgt;                    // an accept_io structure that stores information related to the management file descriptor (socket). // Research: difference from io_management
static struct accept_io io_uds;                    // an accept_io structure that stores information related to the Unix domain socket file descriptor.
static int* main_fds = NULL;                       // an array of integers that holds the main file descriptors (sockets) for incoming connections.
static int main_fds_length = -1;                   // an integer that holds the length of the 'main_fds' array.
static int unix_management_socket = -1;            // an integer that holds the file descriptor for the Unix management socket.
static int unix_pgsql_socket = -1;                 // an integer that holds the file descriptor for the Unix PostgreSQL socket. // Research: tbd
static struct accept_io io_metrics[MAX_FDS];       // an array of accept_io structures, storing information related to the metrics file descriptors (sockets).
static int* metrics_fds = NULL;                    // an array of integers that holds the metrics file descriptors (sockets) for incoming connections. // Research: tbd
static int metrics_fds_length = -1;                // an integer that holds the length of the 'metrics_fds' array.
static struct accept_io io_management[MAX_FDS];    // an array of accept_io structures, storing information related to the management file descriptors (sockets).
static int* management_fds = NULL;                 // an array of integers that holds the management file descriptors (sockets) for incoming connections.
static int management_fds_length = -1;             // an integer that holds the length of the 'management_fds' array.
static struct pipeline main_pipeline;              // a pipeline structure that represents the main pipeline for handling incoming connections and processing requests.
static int known_fds[MAX_NUMBER_OF_CONNECTIONS];   // an array of integers that holds the file descriptors of known connections.
static struct client* clients = NULL;              // a pointer to an array of client structures, representing all connected clients.

static void
start_mgt(void)
{
   memset(&io_mgt, 0, sizeof(struct accept_io));
   ev_io_init((struct ev_io*)&io_mgt, accept_mgt_cb, unix_management_socket, EV_READ);
   io_mgt.socket = unix_management_socket;
   io_mgt.argv = argv_ptr;
   ev_io_start(main_loop, (struct ev_io*)&io_mgt);
}

static void
shutdown_mgt(void)
{
   struct configuration* config;

   config = (struct configuration*)shmem;

   ev_io_stop(main_loop, (struct ev_io*)&io_mgt);
   pgagroal_disconnect(unix_management_socket);
   errno = 0;
   pgagroal_remove_unix_socket(config->unix_socket_dir, MAIN_UDS);
   errno = 0;
}

static void
start_uds(void)
{
   memset(&io_uds, 0, sizeof(struct accept_io));
   ev_io_init((struct ev_io*)&io_uds, accept_main_cb, unix_pgsql_socket, EV_READ);
   io_uds.socket = unix_pgsql_socket;
   io_uds.argv = argv_ptr;
   ev_io_start(main_loop, (struct ev_io*)&io_uds);
}

static void
shutdown_uds(void)
{
   char pgsql[MISC_LENGTH];
   struct configuration* config;

   config = (struct configuration*)shmem;

   memset(&pgsql, 0, sizeof(pgsql));
   snprintf(&pgsql[0], sizeof(pgsql), ".s.PGSQL.%d", config->port);

   ev_io_stop(main_loop, (struct ev_io*)&io_uds);
   pgagroal_disconnect(unix_pgsql_socket);
   errno = 0;
   pgagroal_remove_unix_socket(config->unix_socket_dir, &pgsql[0]);
   errno = 0;
}

static void
start_io(void)
{
   for (int i = 0; i < main_fds_length; i++)
   {
      int sockfd = *(main_fds + i);

      memset(&io_main[i], 0, sizeof(struct accept_io));
      ev_io_init((struct ev_io*)&io_main[i], accept_main_cb, sockfd, EV_READ);
      io_main[i].socket = sockfd;
      io_main[i].argv = argv_ptr;
      ev_io_start(main_loop, (struct ev_io*)&io_main[i]);
   }
}

static void
shutdown_io(void)
{
   for (int i = 0; i < main_fds_length; i++)
   {
      ev_io_stop(main_loop, (struct ev_io*)&io_main[i]);
      pgagroal_disconnect(io_main[i].socket);
      errno = 0;
   }
}

static void
start_metrics(void)
{
   for (int i = 0; i < metrics_fds_length; i++)
   {
      int sockfd = *(metrics_fds + i);

      memset(&io_metrics[i], 0, sizeof(struct accept_io));
      ev_io_init((struct ev_io*)&io_metrics[i], accept_metrics_cb, sockfd, EV_READ);
      io_metrics[i].socket = sockfd;
      io_metrics[i].argv = argv_ptr;
      ev_io_start(main_loop, (struct ev_io*)&io_metrics[i]);
   }
}

static void
shutdown_metrics(void)
{
   for (int i = 0; i < metrics_fds_length; i++)
   {
      ev_io_stop(main_loop, (struct ev_io*)&io_metrics[i]);
      pgagroal_disconnect(io_metrics[i].socket);
      errno = 0;
   }
}

static void
start_management(void)
{
   for (int i = 0; i < management_fds_length; i++)
   {
      int sockfd = *(management_fds + i);

      memset(&io_management[i], 0, sizeof(struct accept_io));
      ev_io_init((struct ev_io*)&io_management[i], accept_management_cb, sockfd, EV_READ);
      io_management[i].socket = sockfd;
      io_management[i].argv = argv_ptr;
      ev_io_start(main_loop, (struct ev_io*)&io_management[i]);
   }
}

static void
shutdown_management(void)
{
   for (int i = 0; i < management_fds_length; i++)
   {
      ev_io_stop(main_loop, (struct ev_io*)&io_management[i]);
      pgagroal_disconnect(io_management[i].socket);
      errno = 0;
   }
}

static void
version(void)
{
   printf("pgagroal %s\n", PGAGROAL_VERSION);
   exit(1);
}

static void
usage(void)
{
   printf("pgagroal %s\n", PGAGROAL_VERSION);
   printf("  High-performance connection pool for PostgreSQL\n");
   printf("\n");

   printf("Usage:\n");
   printf("  pgagroal [ -c CONFIG_FILE ] [ -a HBA_FILE ] [ -d ]\n");
   printf("\n");
   printf("Options:\n");
   printf("  -c, --config CONFIG_FILE           Set the path to the pgagroal.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_CONF_FILE);
   printf("  -a, --hba HBA_FILE                 Set the path to the pgagroal_hba.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_HBA_FILE);
   printf("  -l, --limit LIMIT_FILE             Set the path to the pgagroal_databases.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_LIMIT_FILE);
   printf("  -u, --users USERS_FILE             Set the path to the pgagroal_users.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_USERS_FILE);
   printf("  -F, --frontend FRONTEND_USERS_FILE Set the path to the pgagroal_frontend_users.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_FRONTEND_USERS_FILE);
   printf("  -A, --admins ADMINS_FILE           Set the path to the pgagroal_admins.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_ADMINS_FILE);
   printf("  -S, --superuser SUPERUSER_FILE     Set the path to the pgagroal_superuser.conf file\n");
   printf("                                     Default: %s\n", PGAGROAL_DEFAULT_SUPERUSER_FILE);
   printf("  -d, --daemon                       Run as a daemon\n");
   printf("  -V, --version                      Display version information\n");
   printf("  -?, --help                         Display help\n");
   printf("\n");
   printf("pgagroal: %s\n", PGAGROAL_HOMEPAGE);
   printf("Report bugs: %s\n", PGAGROAL_ISSUES);
}

int
main(int argc, char** argv)
{
   /* Declare variables */

   // Path variables for various configuration files.
   char* configuration_path = NULL;
   char* hba_path = NULL;
   char* limit_path = NULL;
   char* users_path = NULL;
   char* frontend_users_path = NULL;
   char* admins_path = NULL;
   char* superuser_path = NULL;
   // Daemon flag and process id variables.
   // memo: When set to true, the process will detach itself from the terminal and run in the background, providing its services without user interaction.
   bool daemon = false;
   pid_t pid, sid;
#ifdef HAVE_LINUX
   // Systemd socket activation variable for Linux only.
   int sds;
#endif
   // Socket-related flags.
   // memo: A Unix Domain Socket, also known as IPC (Inter-Process Communication) socket or local socket, is a communication mechanism that enables processes running on the same host (machine) to exchange data. Unlike network sockets (e.g., TCP/IP sockets), which facilitate communication between processes across different hosts using a network protocol, Unix Domain Sockets use the file system for addressing and don't involve any network overhead.
   //    Unix Domain Sockets provide a way for bidirectional communication between processes on the same host, and they can be more efficient than network sockets in this context since they bypass the network stack. They are typically represented as special files within the file system, with a specific path used as the socket's address.
   bool has_unix_socket = false;
   // memo: The term "main sockets" refers to the primary sockets the application uses for accepting incoming connections. These sockets are typically network sockets (e.g., TCP/IP sockets) that listen for incoming connections from clients on a specific IP address and port number.
   //    The application binds to the main sockets to serve incoming client requests. For example, a database proxy application might listen for incoming client connections on a particular IP address and port. When clients connect to these main sockets, the application can then manage, process, and forward the requests to the appropriate backend server.
   bool has_main_sockets = false;
   // Event loop and signal handling variables.
   // memo: The signal_watcher structures in the provided context are instances of the signal_info struct, which is used to store information about various signals the program needs to handle. These structures are typically used with an event-driven framework, such as libev, to watch for specific signals and execute a callback function when they are triggered.
   struct signal_info signal_watcher[6];
   struct ev_periodic idle_timeout;
   struct ev_periodic max_connection_age;
   struct ev_periodic validation;
   struct ev_periodic disconnect_client;
   // Resource limit variable.
   // memo: rlimit is a structure defined in the sys/resource.h header file on Unix-like systems. It is used to represent the resource limits that can be applied to a process. Each resource limit consists of a soft limit and a hard limit. The soft limit is the value that the kernel enforces for the corresponding resource, while the hard limit represents an absolute maximum value that cannot be exceeded.
   //    the flimit variable of type struct rlimit is used to store the resource limits related to file descriptors for the process. Specifically, it is used to change the maximum number of open file descriptors that the process is allowed to have.
   //    In a connection pooling application like pgagroal, there can be a large number of open file descriptors due to client connections, backend connections, and other resources. By adjusting the rlimit for file descriptors, you can ensure that the process can handle the required number of connections without running into issues caused by reaching the default file descriptor limit.
   //    The flimit variable is typically used in conjunction with the getrlimit() and setrlimit() system calls to read the current limits and modify them as needed before the main part of the application starts.
   struct rlimit flimit;
   // Shared memory-related variables.
   void* tmp_shmem = NULL;
   size_t shmem_size;
   size_t pipeline_shmem_size = 0;
   size_t prometheus_shmem_size = 0;
   size_t prometheus_cache_shmem_size = 0;
   size_t tmp_size;
   // Configuration structure and return value variable.
   struct configuration* config = NULL;
   int ret;
   // Other variables
   int c;                     // variable to hold getopt_long return value.
   bool conf_file_mandatory;  // flag to determine if a configuration file is mandatory.
   char message[MISC_LENGTH]; // a generic message used for errors

   argv_ptr = argv;

   /* Main loop to process command line arguments */

   while (1)
   {
      // Define long options for command line arguments.
      static struct option long_options[] =
      {
         {"config", required_argument, 0, 'c'},
         {"hba", required_argument, 0, 'a'},
         {"limit", required_argument, 0, 'l'},
         {"users", required_argument, 0, 'u'},
         {"frontend", required_argument, 0, 'F'},
         {"admins", required_argument, 0, 'A'},
         {"superuser", required_argument, 0, 'S'},
         {"daemon", no_argument, 0, 'd'},
         {"version", no_argument, 0, 'V'},
         {"help", no_argument, 0, '?'}
      };
      int option_index = 0;

      // Get next option from command line arguments.
      c = getopt_long (argc, argv, "dV?a:c:l:u:F:A:S:",
                       long_options, &option_index);

      // Break the loop if there are no more options to process.
      if (c == -1)
      {
         break;
      }

      // Process the current option.
      switch (c)
      {
         // Store the configuration file paths or set the corresponding flags
         case 'a':
            hba_path = optarg;
            break;
         case 'c':
            configuration_path = optarg;
            break;
         case 'l':
            limit_path = optarg;
            break;
         case 'u':
            users_path = optarg;
            break;
         case 'F':
            frontend_users_path = optarg;
            break;
         case 'A':
            admins_path = optarg;
            break;
         case 'S':
            superuser_path = optarg;
            break;
         case 'd':
            daemon = true;
            break;

         // Print version information and exit
         case 'V':
            version();
            break;
         // Print usage information and exit
         case '?':
            usage();
            exit(1);
            break;
         default:
            break;
      }
   }

   // Check if the process is running as root, which is not allowed.
   if (getuid() == 0)
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Using the root account is not allowed");
#endif
      errx(1, "Using the root account is not allowed");
   }

   // Calculate the shared memory size and create shared memory for the configuration.
   shmem_size = sizeof(struct configuration);
   if (pgagroal_create_shared_memory(shmem_size, HUGEPAGE_OFF, &shmem))
   {
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Error in creating shared memory");
#endif
      errx(1, "Error in creating shared memory");
   }

   // Initialize the configuration in shared memory and set the config pointer.
   pgagroal_init_configuration(shmem);
   config = (struct configuration*)shmem;

   // Clear known_fds and message buffers.
   memset(&known_fds, 0, sizeof(known_fds));
   memset(message, 0, MISC_LENGTH);

   /* Configuration files */

   // the main configuration file is mandatory! Use default path if not provided.
   configuration_path = configuration_path != NULL ? configuration_path : PGAGROAL_DEFAULT_CONF_FILE;
   // Read the main configuration from the provided path.
   if ((ret = pgagroal_read_configuration(shmem, configuration_path, true)) != PGAGROAL_CONFIGURATION_STATUS_OK)
   {
      // the configuration has some problem, build up a descriptive message
      if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND)
      {
         snprintf(message, MISC_LENGTH, "Configuration file not found");
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
      {
         snprintf(message, MISC_LENGTH, "Too many sections");
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_KO)
      {
         snprintf(message, MISC_LENGTH, "Invalid configuration file");
      }
      else if (ret > 0)
      {
         snprintf(message, MISC_LENGTH, "%d problematic or duplicated section%c",
                  ret,
                  ret > 1 ? 's' : ' ');
      }

#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=%s: %s", message, configuration_path);
#endif
      errx(1, "%s (file <%s>)", message, configuration_path);
   }

   // Copy the configuration path into the config structure.
   memcpy(&config->configuration_path[0], configuration_path, MIN(strlen(configuration_path), MAX_PATH - 1));

   // the HBA file is mandatory! Use default path if not provided.
   hba_path = hba_path != NULL ? hba_path : PGAGROAL_DEFAULT_HBA_FILE;
   memset(message, 0, MISC_LENGTH);
   ret = pgagroal_read_hba_configuration(shmem, hba_path);
   if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND)
   {
      snprintf(message, MISC_LENGTH, "HBA configuration file not found");
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=%s: %s", message, hba_path);
#endif
      errx(1, "%s (file <%s>)", message, hba_path);
   }
   else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
   {
      snprintf(message, MISC_LENGTH, "HBA too many entries (max %d)", NUMBER_OF_HBAS);
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=%s: %s", message, hba_path);
#endif

      errx(1, "%s (file <%s>)", message, hba_path);
   }

   // Copy the HBA path into the config structure.
   memcpy(&config->hba_path[0], hba_path, MIN(strlen(hba_path), MAX_PATH - 1));

   // Read the limit configuration file.
   conf_file_mandatory = true;
read_limit_path:
   if (limit_path != NULL)
   {
      // Read the limit configuration from the provided path.
      memset(message, 0, MISC_LENGTH);
      ret = pgagroal_read_limit_configuration(shmem, limit_path);

      // Check the status of the configuration file and handle errors.
      if (ret == PGAGROAL_CONFIGURATION_STATUS_OK)
      {
         // Copy the limit path into the config structure.
         memcpy(&config->limit_path[0], limit_path, MIN(strlen(limit_path), MAX_PATH - 1));
      }
      else if (conf_file_mandatory && ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND)
      {

         snprintf(message, MISC_LENGTH, "LIMIT configuration file not found");
         printf("pgagroal: %s (file <%s>)\n", message, limit_path);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, limit_path);
#endif
         exit(1);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
      {

         snprintf(message, MISC_LENGTH, "Too many limit entries");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, limit_path);
#endif
         errx(1, "%s (file <%s>)", message, limit_path);
      }

   }
   else
   {
      // the user did not specify a file on the command line
      // so try the default one and allow it to be missing
      limit_path = PGAGROAL_DEFAULT_LIMIT_FILE;
      conf_file_mandatory = false;
      goto read_limit_path;
   }

   // Read the users configuration file.
   conf_file_mandatory = true;
read_users_path:
   if (users_path != NULL)
   {
      memset(message, 0, MISC_LENGTH);
      ret = pgagroal_read_users_configuration(shmem, users_path);
      if (ret == PGAGROAL_CONFIGURATION_STATUS_OK)
      {
         memcpy(&config->users_path[0], users_path, MIN(strlen(users_path), MAX_PATH - 1));
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND && conf_file_mandatory)
      {

         snprintf(message, MISC_LENGTH, "USERS configuration file not found");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s : %s", message, users_path);
#endif
         errx(1, "%s  (file <%s>)", message, users_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_KO
               || ret == PGAGROAL_CONFIGURATION_STATUS_CANNOT_DECRYPT)
      {

         snprintf(message, MISC_LENGTH, "Invalid master key file");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, users_path);
#endif
         errx(1, "%s (file <%s>)", message, users_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
      {

         snprintf(message, MISC_LENGTH, "USERS: too many users defined (%d, max %d)", config->number_of_users, NUMBER_OF_USERS);

#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, users_path);
#endif
         errx(1, "%s (file <%s>)", message, users_path);
      }
   }
   else
   {
      // the user did not specify a file on the command line
      // so try the default one and allow it to be missing
      users_path = PGAGROAL_DEFAULT_USERS_FILE;
      conf_file_mandatory = false;
      goto read_users_path;
   }

   // Read the frontend users configuration file.
   conf_file_mandatory = true;
read_frontend_users_path:
   if (frontend_users_path != NULL)
   {
      ret = pgagroal_read_frontend_users_configuration(shmem, frontend_users_path);
      if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND && conf_file_mandatory)
      {
         memset(message, 0, MISC_LENGTH);
         snprintf(message, MISC_LENGTH, "FRONTEND USERS configuration file not found");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, frontend_users_path);
#endif
         errx(1, "%s (file <%s>)", message, frontend_users_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_CANNOT_DECRYPT
               || ret == PGAGROAL_CONFIGURATION_STATUS_KO)
      {
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Invalid master key file");
#endif
         errx(1, "Invalid master key file");
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
      {
         memset(message, 0, MISC_LENGTH);
         snprintf(message, MISC_LENGTH, "FRONTEND USERS: Too many users defined %d (max %d)",
                  config->number_of_frontend_users, NUMBER_OF_USERS);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, frontend_users_path);
#endif
         errx(1, "%s (file <%s>)", message, frontend_users_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_OK)
      {
         // Copy the frontend users path into the config structure.
         memcpy(&config->frontend_users_path[0], frontend_users_path, MIN(strlen(frontend_users_path), MAX_PATH - 1));
      }
   }
   else
   {
      // the user did not specify a file on the command line
      // so try the default one and allow it to be missing
      frontend_users_path = PGAGROAL_DEFAULT_FRONTEND_USERS_FILE;
      conf_file_mandatory = false;
      goto read_frontend_users_path;
   }

   // Read the admins configuration file.
   conf_file_mandatory = true;
read_admins_path:
   if (admins_path != NULL)
   {
      memset(message, 0, MISC_LENGTH);
      ret = pgagroal_read_admins_configuration(shmem, admins_path);
      if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND && conf_file_mandatory)
      {

         snprintf(message, MISC_LENGTH, "ADMINS configuration file not found");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, admins_path);
#endif
         errx(1, "%s (file <%s>)", message, admins_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_CANNOT_DECRYPT
               || ret == PGAGROAL_CONFIGURATION_STATUS_KO)
      {
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Invalid master key file");
#endif
         errx(1, "Invalid master key file");
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
      {
         snprintf(message, MISC_LENGTH, "Too many admins defined %d (max %d)", config->number_of_admins, NUMBER_OF_ADMINS);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s %s", message, admins_path);
#endif
         errx(1, "%s (file <%s>)", message, admins_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_OK)
      {
         memcpy(&config->admins_path[0], admins_path, MIN(strlen(admins_path), MAX_PATH - 1));
      }
   }
   else
   {
      // the user did not specify a file on the command line
      // so try the default one and allow it to be missing
      admins_path = PGAGROAL_DEFAULT_ADMINS_FILE;
      conf_file_mandatory = false;
      goto read_admins_path;
   }

   // Read the superuser configuration file.
   conf_file_mandatory = true;
read_superuser_path:
   if (superuser_path != NULL)
   {
      ret = pgagroal_read_superuser_configuration(shmem, superuser_path);
      memset(message, 0, MISC_LENGTH);
      if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND && conf_file_mandatory)
      {
         snprintf(message, MISC_LENGTH, "SUPERUSER configuration file not found");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, superuser_path);
#endif
         errx(1, "%s (file <%s>)", message, superuser_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_CANNOT_DECRYPT || ret == PGAGROAL_CONFIGURATION_STATUS_KO)
      {
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Invalid master key file");
#endif
         errx(1, "Invalid master key file");
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG)
      {
         snprintf(message, MISC_LENGTH, "SUPERUSER: Too many superusers defined (max 1)");
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=%s: %s", message, superuser_path);
#endif
         errx(1, "%s (file <%s>)", message, superuser_path);
      }
      else if (ret == PGAGROAL_CONFIGURATION_STATUS_OK)
      {
         memcpy(&config->superuser_path[0], superuser_path, MIN(strlen(superuser_path), MAX_PATH - 1));
      }
   }
   else
   {
      // the user did not specify a file on the command line
      // so try the default one and allow it to be missing
      superuser_path = PGAGROAL_DEFAULT_SUPERUSER_FILE;
      conf_file_mandatory = false;
      goto read_superuser_path;
   }

   /* systemd sockets */

   // memo: A systemd socket is a feature provided by the systemd system and service manager. Systemd is an init system and service manager for Linux operating systems. It is responsible for starting and managing processes, services, and other system resources.
   //    Systemd sockets enable a service to listen on one or more sockets before the actual service process is started. This is useful for services that need to start listening for incoming connections as early as possible during the boot process, even before the service itself is fully initialized. This approach can help reduce the downtime of a service during system startup or restarts.
   //    When a systemd service is configured with a socket file, systemd creates the socket and listens for incoming connections on behalf of the service. Once a connection is received, systemd starts the service (if it is not already running) and passes the connected socket to it. This allows the service to start processing the connection immediately, without the need to initialize the listening socket itself.
#ifdef HAVE_LINUX
   // Get the number of systemd sockets.
   sds = sd_listen_fds(0);
   if (sds > 0)
   {
      int m = 0;

      main_fds_length = 0;

      // Count the number of main file descriptors (AF_INET and AF_INET6).
      for (int i = 0; i < sds; i++)
      {
         int fd = SD_LISTEN_FDS_START + i;

         if (sd_is_socket(fd, AF_INET, 0, -1) || sd_is_socket(fd, AF_INET6, 0, -1))
         {
            main_fds_length++;
         }
      }

      // Allocate memory for the main file descriptors if necessary.
      if (main_fds_length > 0)
      {
         main_fds = malloc(main_fds_length * sizeof(int));
      }

      // Iterate through the systemd sockets, setting the file descriptors and flags accordingly.
      for (int i = 0; i < sds; i++)
      {
         int fd = SD_LISTEN_FDS_START + i;

         if (sd_is_socket(fd, AF_UNIX, 0, -1))
         {
            unix_pgsql_socket = fd;
            has_unix_socket = true;
         }
         else if (sd_is_socket(fd, AF_INET, 0, -1) || sd_is_socket(fd, AF_INET6, 0, -1))
         {
            *(main_fds + (m * sizeof(int))) = fd;
            has_main_sockets = true;
            m++;
         }
      }
   }
#endif

   // Initialize the logging system
   if (pgagroal_init_logging())
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Failed to init logging");
#endif
      exit(1);
   }

   // Start the logging system
   if (pgagroal_start_logging())
   {
#ifdef HAVE_LINUX
      // Notify the systemd about the failure
      sd_notify(0, "STATUS=Failed to start logging");
#endif
      errx(1, "Failed to start logging");
   }

   /* Configuration validation */

   // Validate the main configuration
   if (pgagroal_validate_configuration(shmem, has_unix_socket, has_main_sockets))
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Invalid configuration");
#endif
      errx(1, "Invalid configuration");
   }
   // Validate the HBA configuration
   if (pgagroal_validate_hba_configuration(shmem))
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Invalid HBA configuration");
#endif
      errx(1, "Invalid HBA configuration");
   }
   // Validate the limit configuration
   if (pgagroal_validate_limit_configuration(shmem))
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Invalid LIMIT configuration");
#endif
      errx(1, "Invalid LIMIT configuration");
   }
   // Validate the users configuration
   if (pgagroal_validate_users_configuration(shmem))
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Invalid USERS configuration");
#endif
      errx(1, "Invalid USERS configuration");
   }
   // Validate the frontend users configuration
   if (pgagroal_validate_frontend_users_configuration(shmem))
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Invalid FRONTEND USERS configuration");
#endif
      errx(1, "Invalid FRONTEND USERS configuration");
   }
   // Validate the admins configuration
   if (pgagroal_validate_admins_configuration(shmem))
   {
#ifdef HAVE_LINUX
      sd_notify(0, "STATUS=Invalid ADMINS configuration");
#endif
      errx(1, "Invalid ADMINS configuration");
   }

   /* Shared memory */

   // Resize the shared memory segment
   if (pgagroal_resize_shared_memory(shmem_size, shmem, &tmp_size, &tmp_shmem))
   {
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Error in creating shared memory");
#endif
      errx(1, "Error in creating shared memory");
   }
   // Destroy the old shared memory segment
   if (pgagroal_destroy_shared_memory(shmem, shmem_size) == -1)
   {
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Error in destroying shared memory");
#endif
      errx(1, "Error in destroying shared memory");
   }
   // Update the shared memory size and pointer with the new values
   shmem_size = tmp_size;
   shmem = tmp_shmem;
   config = (struct configuration*)shmem;

   // Initialize the prometheus shared memory
   if (pgagroal_init_prometheus(&prometheus_shmem_size, &prometheus_shmem))
   {
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Error in creating and initializing prometheus shared memory");
#endif
      errx(1, "Error in creating and initializing prometheus shared memory");
   }

   // Initialize the prometheus cache shared memory
   if (pgagroal_init_prometheus_cache(&prometheus_cache_shmem_size, &prometheus_cache_shmem))
   {
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Error in creating and initializing prometheus cache shared memory");
#endif
      errx(1, "Error in creating and initializing prometheus cache shared memory");
   }

   // Get the file descriptor limit
   if (getrlimit(RLIMIT_NOFILE, &flimit) == -1)
   {
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Unable to find limit due to %s", strerror(errno));
#endif
      err(1, "Unable to find limit");
   }

   /* We are "reserving" 30 file descriptors for pgagroal main */
   if (config->max_connections > (flimit.rlim_cur - 30))
   {
#ifdef HAVE_LINUX
      sd_notifyf(0,
                 "STATUS=max_connections is larger than the file descriptor limit (%ld available)",
                 (long)(flimit.rlim_cur - 30));
#endif
      errx(1, "max_connections is larger than the file descriptor limit (%ld available)", (long)(flimit.rlim_cur - 30));
   }

   // Check if the daemon mode is enabled
   if (daemon)
   {
      if (config->log_type == PGAGROAL_LOGGING_TYPE_CONSOLE)
      {
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Daemon mode can't be used with console logging");
#endif
         errx(1, "Daemon mode can't be used with console logging");
      }

      // Fork the process to create a child process (daemon)
      pid = fork();

      if (pid < 0)
      {
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Daemon mode failed");
#endif
         errx(1, "Daemon mode failed");
      }

      if (pid > 0)
      {
         exit(0);
      }

      /* We are a daemon now */
      umask(0);
      sid = setsid();

      if (sid < 0)
      {
         exit(1);
      }
   }

   // Create a PID file or exit if it cannot be created
   create_pidfile_or_exit();

   // Initialize the connection pool
   pgagroal_pool_init();

   // Set the process title to "main"
   pgagroal_set_proc_title(argc, argv, "main", NULL);

   /* Bind Unix Domain Socket for file descriptor transfers */ // TODO: what file descriptors are being transferred
   if (pgagroal_bind_unix_socket(config->unix_socket_dir, MAIN_UDS, &unix_management_socket))
   {
      pgagroal_log_fatal("pgagroal: Could not bind to %s/%s", config->unix_socket_dir, MAIN_UDS);
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Could not bind to %s/%s", config->unix_socket_dir, MAIN_UDS);
#endif
      goto error;
   }

   // If there is no Unix socket already, bind the PostgreSQL Unix Domain Socket
   // memo: PostgreSQL can listen for client connections on both TCP/IP and Unix Domain Sockets. By default, PostgreSQL creates a Unix Domain Socket in the /tmp or /var/run/postgresql directory, depending on the system and PostgreSQL version. The socket's name follows the ".s.PGSQL.<port>" pattern, where "<port>" is the port number on which PostgreSQL listens for connections.
   //    When a client (e.g., pgagroal) wants to connect to a PostgreSQL server using a Unix Domain Socket, it has to specify the socket's directory and name. The client then creates its own socket and connects it to the server's socket. Once connected, the client and server can communicate with each other by exchanging data through the sockets.
   if (!has_unix_socket)
   {
      char pgsql[MISC_LENGTH];

      memset(&pgsql, 0, sizeof(pgsql));
      snprintf(&pgsql[0], sizeof(pgsql), ".s.PGSQL.%d", config->port);

      if (pgagroal_bind_unix_socket(config->unix_socket_dir, &pgsql[0], &unix_pgsql_socket))
      {
         pgagroal_log_fatal("pgagroal: Could not bind to %s/%s", config->unix_socket_dir, &pgsql[0]);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=Could not bind to %s/%s", config->unix_socket_dir, &pgsql[0]);
#endif
         goto error;
      }
   }

   /* Bind main socket */
   if (!has_main_sockets)
   {
      if (pgagroal_bind(config->host, config->port, &main_fds, &main_fds_length))
      {
         pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->port); // memo: bind to main host:port
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=Could not bind to %s:%d", config->host, config->port);
#endif
         goto error;
      }
   }

   // Check if the number of file descriptors exceeds the maximum allowed
   if (main_fds_length > MAX_FDS)
   {
      pgagroal_log_fatal("pgagroal: Too many descriptors %d", main_fds_length);
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Too many descriptors %d", main_fds_length);
#endif
      goto error;
   }

   /* Event loop */

   // Initialize the libev event loop
   // memo: libev is a high-performance, lightweight event library for C programming language. It provides an event loop, which is an abstraction that monitors and manages input/output (I/O) events, timers, signals, and other events for your application. libev is designed to be fast and efficient, making it suitable for use in high-performance networking and server applications.
   /* libev */
   main_loop = ev_default_loop(pgagroal_libev(config->libev));
   if (!main_loop)
   {
      pgagroal_log_fatal("pgagroal: No loop implementation (%x) (%x)",
                         pgagroal_libev(config->libev), ev_supported_backends());
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=No loop implementation (%x) (%x)", pgagroal_libev(config->libev), ev_supported_backends());
#endif
      goto error;
   }

   // Initialize signal watchers for various signals
   ev_signal_init((struct ev_signal*)&signal_watcher[0], shutdown_cb, SIGTERM);  // memo: SIGTERM: This signal is used to request a process to terminate. It can be sent by other processes or system services, such as a process manager, to ask the process to shut down gracefully. Programs can handle this signal to perform cleanup tasks before exiting.
   ev_signal_init((struct ev_signal*)&signal_watcher[1], reload_cb, SIGHUP);     // memo: SIGHUP: This signal is typically used to inform a process that its controlling terminal has been closed or that the user has requested a configuration reload. Programs can handle this signal to perform tasks such as re-reading configuration files or re-initializing resources.
   ev_signal_init((struct ev_signal*)&signal_watcher[2], shutdown_cb, SIGINT);   // memo: SIGINT: This signal is sent to a process when the user requests an interrupt, typically by pressing Ctrl+C in the terminal. Programs can handle this signal to perform a graceful shutdown, freeing resources and closing open connections before terminating.
   ev_signal_init((struct ev_signal*)&signal_watcher[3], graceful_cb, SIGTRAP);  // memo: SIGTRAP: This signal is typically used by debuggers and other debugging tools to interrupt a program's execution at a specific point, such as when a breakpoint is reached or when a specific condition is met. It is primarily intended for internal use by debuggers and is not generally used by applications themselves.
   ev_signal_init((struct ev_signal*)&signal_watcher[4], coredump_cb, SIGABRT);  // memo: SIGABRT: This signal is sent to a process when it calls the abort() function, indicating that the process has detected an abnormal condition and cannot continue to execute. When a program receives a SIGABRT, it typically terminates immediately and generates a core dump if the process is configured to do so. This can be helpful for post-mortem analysis and debugging.
   ev_signal_init((struct ev_signal*)&signal_watcher[5], shutdown_cb, SIGALRM);  // memo: SIGALRM: This signal is used to notify a process that a timer set by the alarm() system call has expired. Programs can use the alarm() function to request a SIGALRM signal to be sent to them after a specified interval. When a program receives a SIGALRM, it can perform specific actions, such as executing periodic tasks or implementing a timeout mechanism for certain operations.

   // Start signal watchers
   for (int i = 0; i < 6; i++)
   {
      signal_watcher[i].slot = -1;
      ev_signal_start(main_loop, (struct ev_signal*)&signal_watcher[i]);
   }

   // Initialize the main pipeline based on the configuration
   if (config->pipeline == PIPELINE_PERFORMANCE)
   {
      main_pipeline = performance_pipeline();
   }
   else if (config->pipeline == PIPELINE_SESSION)
   {
      // Session pipeline checks if a Transport Layer Security (TLS) transport should be used.
      if (pgagroal_tls_valid())
      {
         pgagroal_log_fatal("pgagroal: Invalid TLS configuration");
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Invalid TLS configuration");
#endif
         goto error;
      }

      main_pipeline = session_pipeline();
   }
   else if (config->pipeline == PIPELINE_TRANSACTION)
   {
      if (pgagroal_tls_valid())
      {
         pgagroal_log_fatal("pgagroal: Invalid TLS configuration");
#ifdef HAVE_LINUX
         sd_notify(0, "STATUS=Invalid TLS configuration");
#endif
         goto error;
      }

      main_pipeline = transaction_pipeline();
   }
   else
   {
      pgagroal_log_fatal("pgagroal: Unknown pipeline identifier (%d)", config->pipeline);
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Unknown pipeline identifier (%d)", config->pipeline);
#endif
      goto error;
   }

   // Initialize the main pipeline
   if (main_pipeline.initialize(shmem, &pipeline_shmem, &pipeline_shmem_size))
   {
      pgagroal_log_fatal("pgagroal: Pipeline initialize error (%d)", config->pipeline);
#ifdef HAVE_LINUX
      sd_notifyf(0, "STATUS=Pipeline initialize error (%d)", config->pipeline);
#endif
      goto error;
   }

   // Start management, Unix Domain Socket, and I/O services
   start_mgt();
   start_uds();
   start_io();

   // Initialize and start idle_timeout background check, if configured
   if (config->idle_timeout > 0)
   {
      ev_periodic_init (&idle_timeout, idle_timeout_cb, 0.,
                        MAX(1. * config->idle_timeout / 2., 5.), 0);
      ev_periodic_start (main_loop, &idle_timeout);
   }

   // Initialize and start max_connection_age background check, if configured
   if (config->max_connection_age > 0)
   {
      ev_periodic_init (&max_connection_age, max_connection_age_cb, 0.,
                        MAX(1. * config->max_connection_age / 2., 5.), 0);
      ev_periodic_start (main_loop, &max_connection_age);
   }

   // Initialize and start background validation, if configured
   if (config->validation == VALIDATION_BACKGROUND)
   {
      ev_periodic_init (&validation, validation_cb, 0.,
                        MAX(1. * config->background_interval, 5.), 0);
      ev_periodic_start (main_loop, &validation);
   }

   // Initialize and start disconnect_client background check, if configured
   if (config->disconnect_client > 0)
   {
      ev_periodic_init (&disconnect_client, disconnect_client_cb, 0.,
                        MIN(300., MAX(1. * config->disconnect_client / 2., 1.)), 0);
      ev_periodic_start (main_loop, &disconnect_client);
   }

   // Initialize and start metrics service, if configured
   if (config->metrics > 0)
   {
      /* Bind metrics socket */
      if (pgagroal_bind(config->host, config->metrics, &metrics_fds, &metrics_fds_length))
      {
         pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->metrics);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=Could not bind to %s:%d", config->host, config->metrics);
#endif
         goto error;
      }

      if (metrics_fds_length > MAX_FDS)
      {
         pgagroal_log_fatal("pgagroal: Too many descriptors %d", metrics_fds_length);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=Too many descriptors %d", metrics_fds_length);
#endif
         goto error;
      }

      start_metrics();
   }

   // Research: tbd
   // Initialize and start management service, if configured
   if (config->management > 0)
   {
      /* Bind management socket */
      if (pgagroal_bind(config->host, config->management, &management_fds, &management_fds_length))
      {
         pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->management);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=Could not bind to %s:%d", config->host, config->management);
#endif
         goto error;
      }

      if (management_fds_length > MAX_FDS)
      {
         pgagroal_log_fatal("pgagroal: Too many descriptors %d", management_fds_length);
#ifdef HAVE_LINUX
         sd_notifyf(0, "STATUS=Too many descriptors %d", management_fds_length);
#endif
         goto error;
      }

      start_management();
   }

   /* Log the starting information */

   // Log the version and starting information of pgagroal
   pgagroal_log_info("pgagroal: %s started on %s:%d",
                     PGAGROAL_VERSION,
                     config->host,
                     config->port);
   // Log debug information for sockets
   for (int i = 0; i < main_fds_length; i++)
   {
      pgagroal_log_debug("Socket: %d", *(main_fds + i));
   }
   pgagroal_log_debug("Unix Domain Socket: %d", unix_pgsql_socket);
   pgagroal_log_debug("Management: %d", unix_management_socket);
   for (int i = 0; i < metrics_fds_length; i++)
   {
      pgagroal_log_debug("Metrics: %d", *(metrics_fds + i));
   }
   for (int i = 0; i < management_fds_length; i++)
   {
      pgagroal_log_debug("Remote management: %d", *(management_fds + i));
   }
   // Research: tbd
   // Log libev engines information
   pgagroal_libev_engines();
   pgagroal_log_debug("libev engine: %s", pgagroal_libev_engine(ev_backend(main_loop)));
   // Log pipeline and related information
   pgagroal_log_debug("Pipeline: %d", config->pipeline);
   pgagroal_log_debug("Pipeline size: %lu", pipeline_shmem_size);
   // Log the OpenSSL version
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
   pgagroal_log_debug("%s", SSLeay_version(SSLEAY_VERSION));
#else
   pgagroal_log_debug("%s", OpenSSL_version(OPENSSL_VERSION));
#endif
   // Log configuration and connection related information
   pgagroal_log_debug("Configuration size: %lu", shmem_size);
   pgagroal_log_debug("Max connections: %d", config->max_connections);
   pgagroal_log_debug("Known users: %d", config->number_of_users);
   pgagroal_log_debug("Known frontend users: %d", config->number_of_frontend_users);
   pgagroal_log_debug("Known admins: %d", config->number_of_admins);
   pgagroal_log_debug("Known superuser: %s", strlen(config->superuser.username) > 0 ? "Yes" : "No");

   // Log a warning if no users are allowed
   if (!config->allow_unknown_users && config->number_of_users == 0)
   {
      pgagroal_log_warn("No users allowed");
   }

   /* Prefill */

   // Check if prefilling is possible and spawn a child process to do the prefill
   if (pgagroal_can_prefill())
   {
      if (!fork())
      {
         shutdown_ports();
         pgagroal_prefill_if_can(false, true);
      }
   }

#ifdef HAVE_LINUX
   // Notify systemd that pgagroal is ready and running
   sd_notifyf(0,
              "READY=1\n"
              "STATUS=Running\n"
              "MAINPID=%lu", (unsigned long)getpid());
#endif

   /* Main event loop */

   // Run the main event loop while keep_running
   while (keep_running)
   {
      ev_loop(main_loop, 0);
   }

   /* Stopping */

   pgagroal_log_info("pgagroal: shutdown");
#ifdef HAVE_LINUX
   // Notify systemd that pgagroal is stopping
   sd_notify(0, "STOPPING=1");
#endif
   // Shutdown the connection pool
   pgagroal_pool_shutdown();

   // Send a signal to terminate all connected clients
   if (clients != NULL)
   {
      struct client* c = clients;
      while (c != NULL)
      {
         kill(c->pid, SIGQUIT);
         c = c->next;
      }
   }

   // Shutdown various components of pgagroal
   shutdown_management();
   shutdown_metrics();
   shutdown_mgt();
   shutdown_io();
   shutdown_uds();

   // Stop signal watchers
   for (int i = 0; i < 6; i++)
   {
      ev_signal_stop(main_loop, (struct ev_signal*)&signal_watcher[i]);
   }

   // Destroy the main event loop
   ev_loop_destroy(main_loop);

   // Free file descriptor arrays
   free(main_fds);
   free(metrics_fds);
   free(management_fds);

   // Destroy the main pipeline
   main_pipeline.destroy(pipeline_shmem, pipeline_shmem_size);

   // Remove the PID file
   remove_pidfile();

   // Stop logging and destroy shared memory segments
   pgagroal_stop_logging();
   pgagroal_destroy_shared_memory(prometheus_shmem, prometheus_shmem_size);
   pgagroal_destroy_shared_memory(prometheus_cache_shmem, prometheus_cache_shmem_size);
   pgagroal_destroy_shared_memory(shmem, shmem_size);

   return 0;

error:
   // In case of an error, remove the PID file and exit with an error code
   remove_pidfile();
   exit(1);
}

/* Callback function for the main event loop when a new connection is ready to be accepted */
static void
accept_main_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   // Declare necessary variables
   struct sockaddr_in6 client_addr; // IPv6 client address structure
   socklen_t client_addr_length; // Length of the client address
   int client_fd; // File descriptor of the accepted client connection
   char address[INET6_ADDRSTRLEN]; // Buffer to store client's address as a string
   pid_t pid; // Process ID of the forked child process
   struct accept_io* ai; // Pointer to an accept_io structure (contains watcher info)
   struct configuration* config; // Pointer to the configuration structure in shared memory

   // If the received event is an invalid event
   if (EV_ERROR & revents)
   {
      pgagroal_log_debug("accept_main_cb: invalid event: %s", strerror(errno));
      errno = 0;
      return;
   }

   // Cast the watcher to an accept_io structure and get the configuration from shared memory
   ai = (struct accept_io*)watcher;
   config = (struct configuration*)shmem;

   // Clear the memory of the address buffer
   memset(&address, 0, sizeof(address));

   // Accept the new client connection and store the client's address information in client_addr
   client_addr_length = sizeof(client_addr);
   client_fd = accept(watcher->fd, (struct sockaddr*)&client_addr, &client_addr_length);
   // Check if the accept() call failed
   if (client_fd == -1)
   {
      // Handle the error accordingly (e.g., restart the listening port or log the error)
      if (accept_fatal(errno) && keep_running)
      {
         char pgsql[MISC_LENGTH];

         pgagroal_log_warn("Restarting listening port due to: %s (%d)", strerror(errno), watcher->fd);

         shutdown_io();
         shutdown_uds();

         memset(&pgsql, 0, sizeof(pgsql));
         snprintf(&pgsql[0], sizeof(pgsql), ".s.PGSQL.%d", config->port);

         if (pgagroal_bind_unix_socket(config->unix_socket_dir, &pgsql[0], &unix_pgsql_socket))
         {
            pgagroal_log_fatal("pgagroal: Could not bind to %s/%s", config->unix_socket_dir, &pgsql[0]);
            exit(1);
         }

         free(main_fds);
         main_fds = NULL;
         main_fds_length = 0;

         if (pgagroal_bind(config->host, config->port, &main_fds, &main_fds_length))
         {
            pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->port);
            exit(1);
         }

         if (main_fds_length > MAX_FDS)
         {
            pgagroal_log_fatal("pgagroal: Too many descriptors %d", main_fds_length);
            exit(1);
         }

         if (!fork())
         {
            shutdown_ports();
            pgagroal_flush(FLUSH_GRACEFULLY, "*");
         }

         start_io();
         start_uds();

         for (int i = 0; i < main_fds_length; i++)
         {
            pgagroal_log_debug("Socket: %d", *(main_fds + i));
         }
         pgagroal_log_debug("Unix Domain Socket: %d", unix_pgsql_socket);
      }
      else
      {
         pgagroal_log_debug("accept: %s (%d)", strerror(errno), watcher->fd);
      }
      errno = 0;
      return;
   }

   // Update Prometheus metrics by incrementing the number of client sockets
   pgagroal_prometheus_client_sockets_add();

   // Convert the client address to a human-readable string format
   pgagroal_get_address((struct sockaddr*)&client_addr, (char*)&address, sizeof(address));

   // Log the client's address as a trace message
   pgagroal_log_trace("accept_main_cb: client address: %s", address);

   // Fork a new process to handle the client connection
   pid = fork();
   // If the fork failed
   if (pid == -1)
   {
      /* No process */
      pgagroal_log_error("Cannot create process");
   }
   // Parent process
   else if (pid > 0)
   {
      // Add the child process to the client list
      add_client(pid);
   }
   // Child process
   else
   {
      // Allocate memory for the client address string
      char* addr = calloc(1, strlen(address) + 1);
      if (addr == NULL)
      {
         pgagroal_log_fatal("Cannot allocate memory for client address");
         return;
      }
      memcpy(addr, address, strlen(address));

      // Fork the event loop
      ev_loop_fork(loop);
      // Close unnecessary file descriptors
      shutdown_ports();
      // Start processing the client request in the child process
      /* We are leaving the socket descriptor valid such that the client won't reuse it */
      pgagroal_worker(client_fd, addr, ai->argv);
   }

   // Close the client connection
   pgagroal_disconnect(client_fd);
}

static void
accept_mgt_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   struct sockaddr_in6 client_addr;
   socklen_t client_addr_length;
   int client_fd;
   signed char id;
   int32_t slot;
   int payload_i, secondary_payload_i;
   char* payload_s = NULL;
   char* secondary_payload_s = NULL;
   struct configuration* config;

   if (EV_ERROR & revents)
   {
      pgagroal_log_trace("accept_mgt_cb: got invalid event: %s", strerror(errno));
      return;
   }

   config = (struct configuration*)shmem;

   client_addr_length = sizeof(client_addr);
   client_fd = accept(watcher->fd, (struct sockaddr*)&client_addr, &client_addr_length);

   pgagroal_prometheus_self_sockets_add();

   if (client_fd == -1)
   {
      if (accept_fatal(errno) && keep_running)
      {
         pgagroal_log_warn("Restarting management due to: %s (%d)", strerror(errno), watcher->fd);

         shutdown_mgt();

         if (pgagroal_bind_unix_socket(config->unix_socket_dir, MAIN_UDS, &unix_management_socket))
         {
            pgagroal_log_fatal("pgagroal: Could not bind to %s", config->unix_socket_dir);
            exit(1);
         }

         start_mgt();

         pgagroal_log_debug("Management: %d", unix_management_socket);
      }
      else
      {
         pgagroal_log_debug("accept: %s (%d)", strerror(errno), watcher->fd);
      }
      errno = 0;
      return;
   }

   /* Process internal management request -- f.ex. returning a file descriptor to the pool */
   pgagroal_management_read_header(client_fd, &id, &slot);
   pgagroal_management_read_payload(client_fd, id, &payload_i, &payload_s);

   switch (id)
   {
      case MANAGEMENT_TRANSFER_CONNECTION:
         pgagroal_log_debug("pgagroal: Management transfer connection: Slot %d FD %d", slot, payload_i);
         config->connections[slot].fd = payload_i;
         known_fds[slot] = config->connections[slot].fd;

         if (config->pipeline == PIPELINE_TRANSACTION)
         {
            struct client* c = clients;
            while (c != NULL)
            {
               pgagroal_management_client_fd(slot, c->pid);
               c = c->next;
            }
         }

         break;
      case MANAGEMENT_RETURN_CONNECTION:
         pgagroal_log_debug("pgagroal: Management return connection: Slot %d", slot);
         break;
      case MANAGEMENT_KILL_CONNECTION:
         pgagroal_log_debug("pgagroal: Management kill connection: Slot %d", slot);
         if (known_fds[slot] == payload_i)
         {
            struct client* c = clients;

            while (c != NULL)
            {
               pgagroal_management_remove_fd(slot, payload_i, c->pid);
               c = c->next;
            }

            pgagroal_disconnect(payload_i);
            known_fds[slot] = 0;
         }
         break;
      case MANAGEMENT_FLUSH:
         pgagroal_log_debug("pgagroal: Management flush (%d/%s)", payload_i, payload_s);
         if (!fork())
         {
            shutdown_ports();
            pgagroal_flush(payload_i, payload_s);
         }
         break;
      case MANAGEMENT_ENABLEDB:
         pgagroal_log_debug("pgagroal: Management enabledb: %s", payload_s);
         pgagroal_pool_status();

         for (int i = 0; i < NUMBER_OF_DISABLED; i++)
         {
            if (!strcmp("*", payload_s))
            {
               memset(&config->disabled[i], 0, MAX_DATABASE_LENGTH);
            }
            else if (!strcmp(config->disabled[i], payload_s))
            {
               memset(&config->disabled[i], 0, MAX_DATABASE_LENGTH);
            }
         }

         free(payload_s);
         break;
      case MANAGEMENT_DISABLEDB:
         pgagroal_log_debug("pgagroal: Management disabledb: %s", payload_s);
         pgagroal_pool_status();

         if (!strcmp("*", payload_s))
         {
            for (int i = 0; i < NUMBER_OF_DISABLED; i++)
            {
               memset(&config->disabled[i], 0, MAX_DATABASE_LENGTH);
            }

            memcpy(&config->disabled[0], payload_s, 1);
         }
         else
         {
            for (int i = 0; i < NUMBER_OF_DISABLED; i++)
            {
               if (!strcmp(config->disabled[i], ""))
               {
                  memcpy(&config->disabled[i], payload_s, strlen(payload_s));
                  break;
               }
            }
         }

         free(payload_s);
         break;
      case MANAGEMENT_GRACEFULLY:
         pgagroal_log_debug("pgagroal: Management gracefully");
         pgagroal_pool_status();
         config->gracefully = true;
         break;
      case MANAGEMENT_STOP:
         pgagroal_log_debug("pgagroal: Management stop");
         pgagroal_pool_status();
         ev_break(loop, EVBREAK_ALL);
         keep_running = 0;
         break;
      case MANAGEMENT_CANCEL_SHUTDOWN:
         pgagroal_log_debug("pgagroal: Management cancel shutdown");
         pgagroal_pool_status();
         config->gracefully = false;
         break;
      case MANAGEMENT_STATUS:
         pgagroal_log_debug("pgagroal: Management status");
         pgagroal_pool_status();
         pgagroal_management_write_status(client_fd, config->gracefully);
         break;
      case MANAGEMENT_DETAILS:
         pgagroal_log_debug("pgagroal: Management details");
         pgagroal_pool_status();
         pgagroal_management_write_status(client_fd, config->gracefully);
         pgagroal_management_write_details(client_fd);
         break;
      case MANAGEMENT_ISALIVE:
         pgagroal_log_debug("pgagroal: Management isalive");
         pgagroal_management_write_isalive(client_fd, config->gracefully);
         break;
      case MANAGEMENT_RESET:
         pgagroal_log_debug("pgagroal: Management reset");
         pgagroal_prometheus_reset();
         break;
      case MANAGEMENT_RESET_SERVER:
         pgagroal_log_debug("pgagroal: Management reset server");
         pgagroal_server_reset(payload_s);
         pgagroal_prometheus_failed_servers();
         break;
      case MANAGEMENT_CLIENT_DONE:
         pgagroal_log_debug("pgagroal: Management client done");
         pid_t p = (pid_t)payload_i;
         remove_client(p);
         break;
      case MANAGEMENT_SWITCH_TO:
         pgagroal_log_debug("pgagroal: Management switch to");
         int old_primary = -1;
         signed char server_state;
         for (int i = 0; old_primary == -1 && i < config->number_of_servers; i++)
         {
            server_state = atomic_load(&config->servers[i].state);
            if (server_state == SERVER_PRIMARY)
            {
               old_primary = i;
            }
         }

         if (!pgagroal_server_switch(payload_s))
         {
            if (!fork())
            {
               shutdown_ports();
               if (old_primary != -1)
               {
                  pgagroal_flush_server(old_primary);
               }
               else
               {
                  pgagroal_flush(FLUSH_GRACEFULLY, "*");
               }
            }
            pgagroal_prometheus_failed_servers();
         }
         break;
      case MANAGEMENT_RELOAD:
         pgagroal_log_debug("pgagroal: Management reload");
         reload_configuration();
         break;
      case MANAGEMENT_CONFIG_GET:
         pgagroal_log_debug("pgagroal: Management config-get for key <%s>", payload_s);
         pgagroal_management_write_config_get(client_fd, payload_s);
         break;
      case MANAGEMENT_CONFIG_SET:
         // This command has a secondary payload to extract, that is the configuration value
         pgagroal_management_read_payload(client_fd, id, &secondary_payload_i, &secondary_payload_s);
         pgagroal_log_debug("pgagroal: Management config-set for key <%s> setting value to <%s>", payload_s, secondary_payload_s);
         pgagroal_management_write_config_set(client_fd, payload_s, secondary_payload_s);
         break;
      default:
         pgagroal_log_debug("pgagroal: Unknown management id: %d", id);
         break;
   }

   if (keep_running && config->gracefully)
   {
      if (atomic_load(&config->active_connections) == 0)
      {
         pgagroal_pool_status();
         keep_running = 0;
         ev_break(loop, EVBREAK_ALL);
      }
   }

   pgagroal_disconnect(client_fd);

   pgagroal_prometheus_self_sockets_sub();
}

static void
accept_metrics_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   struct sockaddr_in6 client_addr;
   socklen_t client_addr_length;
   int client_fd;
   struct configuration* config;

   if (EV_ERROR & revents)
   {
      pgagroal_log_debug("accept_metrics_cb: invalid event: %s", strerror(errno));
      errno = 0;
      return;
   }

   config = (struct configuration*)shmem;

   client_addr_length = sizeof(client_addr);
   client_fd = accept(watcher->fd, (struct sockaddr*)&client_addr, &client_addr_length);

   pgagroal_prometheus_self_sockets_add();

   if (client_fd == -1)
   {
      if (accept_fatal(errno) && keep_running)
      {
         pgagroal_log_warn("Restarting listening port due to: %s (%d)", strerror(errno), watcher->fd);

         shutdown_metrics();

         free(metrics_fds);
         metrics_fds = NULL;
         metrics_fds_length = 0;

         if (pgagroal_bind(config->host, config->metrics, &metrics_fds, &metrics_fds_length))
         {
            pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->metrics);
            exit(1);
         }

         if (metrics_fds_length > MAX_FDS)
         {
            pgagroal_log_fatal("pgagroal: Too many descriptors %d", metrics_fds_length);
            exit(1);
         }

         start_metrics();

         for (int i = 0; i < metrics_fds_length; i++)
         {
            pgagroal_log_debug("Metrics: %d", *(metrics_fds + i));
         }
      }
      else
      {
         pgagroal_log_debug("accept: %s (%d)", strerror(errno), watcher->fd);
      }
      errno = 0;
      return;
   }

   if (!fork())
   {
      ev_loop_fork(loop);
      shutdown_ports();
      /* We are leaving the socket descriptor valid such that the client won't reuse it */
      pgagroal_prometheus(client_fd);
   }

   pgagroal_disconnect(client_fd);
   pgagroal_prometheus_self_sockets_sub();
}

static void
accept_management_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
   struct sockaddr_in6 client_addr;
   socklen_t client_addr_length;
   int client_fd;
   char address[INET6_ADDRSTRLEN];
   struct configuration* config;

   if (EV_ERROR & revents)
   {
      pgagroal_log_debug("accept_management_cb: invalid event: %s", strerror(errno));
      errno = 0;
      return;
   }

   memset(&address, 0, sizeof(address));

   config = (struct configuration*)shmem;

   client_addr_length = sizeof(client_addr);
   client_fd = accept(watcher->fd, (struct sockaddr*)&client_addr, &client_addr_length);

   pgagroal_prometheus_self_sockets_add();

   if (client_fd == -1)
   {
      if (accept_fatal(errno) && keep_running)
      {
         pgagroal_log_warn("Restarting listening port due to: %s (%d)", strerror(errno), watcher->fd);

         shutdown_management();

         free(management_fds);
         management_fds = NULL;
         management_fds_length = 0;

         if (pgagroal_bind(config->host, config->management, &management_fds, &management_fds_length))
         {
            pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->management);
            exit(1);
         }

         if (management_fds_length > MAX_FDS)
         {
            pgagroal_log_fatal("pgagroal: Too many descriptors %d", management_fds_length);
            exit(1);
         }

         start_management();

         for (int i = 0; i < management_fds_length; i++)
         {
            pgagroal_log_debug("Remote management: %d", *(management_fds + i));
         }
      }
      else
      {
         pgagroal_log_debug("accept: %s (%d)", strerror(errno), watcher->fd);
      }
      errno = 0;
      return;
   }

   pgagroal_get_address((struct sockaddr*)&client_addr, (char*)&address, sizeof(address));

   if (!fork())
   {
      char* addr = calloc(1, strlen(address) + 1);
      if (addr == NULL)
      {
         pgagroal_log_fatal("Couldn't allocate address");
         return;
      }
      memcpy(addr, address, strlen(address));

      ev_loop_fork(loop);
      shutdown_ports();
      /* We are leaving the socket descriptor valid such that the client won't reuse it */
      pgagroal_remote_management(client_fd, addr);
   }

   pgagroal_disconnect(client_fd);
   pgagroal_prometheus_self_sockets_sub();
}

static void
shutdown_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
   pgagroal_log_debug("pgagroal: shutdown requested");
   pgagroal_pool_status();
   ev_break(loop, EVBREAK_ALL);
   keep_running = 0;
}

static void
reload_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
   pgagroal_log_debug("pgagroal: reload requested");
   reload_configuration();
}

static void
graceful_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
   struct configuration* config;

   config = (struct configuration*)shmem;

   pgagroal_log_debug("pgagroal: gracefully requested");

   pgagroal_pool_status();
   config->gracefully = true;

   if (atomic_load(&config->active_connections) == 0)
   {
      pgagroal_pool_status();
      keep_running = 0;
      ev_break(loop, EVBREAK_ALL);
   }
}

static void
coredump_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
   pgagroal_log_info("pgagroal: core dump requested");
   pgagroal_pool_status();
   abort();
}

static void
idle_timeout_cb(struct ev_loop* loop, ev_periodic* w, int revents)
{
   if (EV_ERROR & revents)
   {
      pgagroal_log_trace("idle_timeout_cb: got invalid event: %s", strerror(errno));
      return;
   }

   /* pgagroal_idle_timeout() is always in a fork() */
   if (!fork())
   {
      shutdown_ports();
      pgagroal_idle_timeout();
   }
}

static void
max_connection_age_cb(struct ev_loop* loop, ev_periodic* w, int revents)
{
   if (EV_ERROR & revents)
   {
      pgagroal_log_trace("max_connection_age_cb: got invalid event: %s", strerror(errno));
      return;
   }

   /* max_connection_age() is always in a fork() */
   if (!fork())
   {
      shutdown_ports();
      pgagroal_max_connection_age();
   }
}

static void
validation_cb(struct ev_loop* loop, ev_periodic* w, int revents)
{
   if (EV_ERROR & revents)
   {
      pgagroal_log_trace("validation_cb: got invalid event: %s", strerror(errno));
      return;
   }

   /* pgagroal_validation() is always in a fork() */
   if (!fork())
   {
      shutdown_ports();
      pgagroal_validation();
   }
}

static void
disconnect_client_cb(struct ev_loop* loop, ev_periodic* w, int revents)
{
   if (EV_ERROR & revents)
   {
      pgagroal_log_trace("disconnect_client_cb: got invalid event: %s", strerror(errno));
      return;
   }

   /* main_pipeline.periodic is always in a fork() */
   if (!fork())
   {
      shutdown_ports();
      main_pipeline.periodic();
   }
}

static bool
accept_fatal(int error)
{
   switch (error)
   {
      case EAGAIN:
      case ENETDOWN:
      case EPROTO:
      case ENOPROTOOPT:
      case EHOSTDOWN:
#ifdef HAVE_LINUX
      case ENONET:
#endif
      case EHOSTUNREACH:
      case EOPNOTSUPP:
      case ENETUNREACH:
         return false;
         break;
   }

   return true;
}

static void
add_client(pid_t pid)
{
   struct client* c = NULL;

   c = (struct client*)malloc(sizeof(struct client));
   c->pid = pid;
   c->next = NULL;

   if (clients == NULL)
   {
      clients = c;
   }
   else
   {
      struct client* last = NULL;

      last = clients;

      while (last->next != NULL)
      {
         last = last->next;
      }

      last->next = c;
   }
}

static void
remove_client(pid_t pid)
{
   struct client* c = NULL;
   struct client* p = NULL;

   c = clients;
   p = NULL;

   if (c != NULL)
   {
      while (c->pid != pid)
      {
         p = c;
         c = c->next;

         if (c == NULL)
         {
            return;
         }
      }

      if (c == clients)
      {
         clients = c->next;
      }
      else
      {
         p->next = c->next;
      }

      free(c);
   }
}

static void
reload_configuration(void)
{
   char pgsql[MISC_LENGTH];
   struct configuration* config;

   config = (struct configuration*)shmem;

   shutdown_io();
   shutdown_uds();
   shutdown_metrics();
   shutdown_management();

   pgagroal_reload_configuration();

   memset(&pgsql, 0, sizeof(pgsql));
   snprintf(&pgsql[0], sizeof(pgsql), ".s.PGSQL.%d", config->port);

   if (pgagroal_bind_unix_socket(config->unix_socket_dir, &pgsql[0], &unix_pgsql_socket))
   {
      pgagroal_log_fatal("pgagroal: Could not bind to %s/%s", config->unix_socket_dir, &pgsql[0]);
      goto error;
   }

   free(main_fds);
   main_fds = NULL;
   main_fds_length = 0;

   if (pgagroal_bind(config->host, config->port, &main_fds, &main_fds_length))
   {
      pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->port);
      goto error;
   }

   if (main_fds_length > MAX_FDS)
   {
      pgagroal_log_fatal("pgagroal: Too many descriptors %d", main_fds_length);
      goto error;
   }

   start_io();
   start_uds();

   if (config->metrics > 0)
   {
      free(metrics_fds);
      metrics_fds = NULL;
      metrics_fds_length = 0;

      /* Bind metrics socket */
      if (pgagroal_bind(config->host, config->metrics, &metrics_fds, &metrics_fds_length))
      {
         pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->metrics);
         goto error;
      }

      if (metrics_fds_length > MAX_FDS)
      {
         pgagroal_log_fatal("pgagroal: Too many descriptors %d", metrics_fds_length);
         goto error;
      }

      start_metrics();
   }

   if (config->management > 0)
   {
      free(management_fds);
      management_fds = NULL;
      management_fds_length = 0;

      /* Bind management socket */
      if (pgagroal_bind(config->host, config->management, &management_fds, &management_fds_length))
      {
         pgagroal_log_fatal("pgagroal: Could not bind to %s:%d", config->host, config->management);
         goto error;
      }

      if (management_fds_length > MAX_FDS)
      {
         pgagroal_log_fatal("pgagroal: Too many descriptors %d", management_fds_length);
         goto error;
      }

      start_management();
   }

   for (int i = 0; i < main_fds_length; i++)
   {
      pgagroal_log_debug("Socket: %d", *(main_fds + i));
   }
   pgagroal_log_debug("Unix Domain Socket: %d", unix_pgsql_socket);
   for (int i = 0; i < metrics_fds_length; i++)
   {
      pgagroal_log_debug("Metrics: %d", *(metrics_fds + i));
   }
   for (int i = 0; i < management_fds_length; i++)
   {
      pgagroal_log_debug("Remote management: %d", *(management_fds + i));
   }

   return;

error:
   remove_pidfile();
   exit(1);
}

/**
 * Creates the pid file for the running pooler.
 * If a pid file already exists, or if the file cannot be written,
 * the function kills (exits) the current process.
 *
 */
static void
create_pidfile_or_exit(void)
{
   char buffer[64];
   pid_t pid;
   int r;
   int fd;
   struct configuration* config;

   config = (struct configuration*)shmem;

   if (strlen(config->pidfile) > 0)
   {
      pid = getpid();

      fd = open(config->pidfile, O_WRONLY | O_CREAT | O_EXCL, 0640);
      if (errno == EEXIST)
      {
         errx(1, "PID file <%s> exists, is there another instance running ?", config->pidfile); // memo: create pid file error
      }
      else if (errno == EACCES)
      {
         errx(1, "PID file <%s> cannot be created due to lack of permissions", config->pidfile);
      }
      else if (fd < 0)
      {
         err(1, "Could not create PID file <%s>", config->pidfile);
      }

      snprintf(&buffer[0], sizeof(buffer), "%u\n", (unsigned)pid);

      r = write(fd, &buffer[0], strlen(buffer));
      if (r < 0)
      {
         errx(1, "Could not write into PID file <%s>", config->pidfile);
      }

      close(fd);
   }
}

static void
remove_pidfile(void)
{
   struct configuration* config;

   config = (struct configuration*)shmem;

   if (strlen(config->pidfile) > 0)
   {
      if (unlink(config->pidfile))
      {
         warn("Cannot remove PID file <%s>", config->pidfile);
      }
   }
}

static void
shutdown_ports(void)
{
   struct configuration* config;

   config = (struct configuration*)shmem;

   shutdown_io();

   if (config->metrics > 0)
   {
      shutdown_metrics();
   }

   if (config->management > 0)
   {
      shutdown_management();
   }
}
