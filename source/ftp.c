// This file is under the terms of the unlicense (https://github.com/DavidBuchanan314/ftpd/blob/master/LICENSE)

#define ENABLE_LOGGING 1
/* This FTP server implementation is based on RFC 959,
 * (https://tools.ietf.org/html/rfc959), RFC 3659
 * (https://tools.ietf.org/html/rfc3659) and suggested implementation details
 * from https://cr.yp.to/ftp/filesystem.html
 */
#include "ftp.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#ifdef _3DS
#    include <3ds.h>
#    define lstat stat
#elif defined(__SWITCH__)
#    include <switch.h>
#    define lstat stat
#else
#    include <stdbool.h>
#    define BIT(x) (1 << (x))
#endif
#include "console.h"
#include "led.h"
#include "util.h"

#define POLL_UNKNOWN (~(POLLIN | POLLPRI | POLLOUT))

#define XFER_BUFFERSIZE (16 * 1024)
#define SOCK_BUFFERSIZE (8 * 1024)
#define FILE_BUFFERSIZE (32 * 1024)
#define CMD_BUFFERSIZE (4 * 1024)

int LISTEN_PORT;
// #define LISTEN_PORT 5000
#ifdef _3DS
#    define DATA_PORT (LISTEN_PORT + 1)
#else
#    define DATA_PORT 0 /* ephemeral port */
#endif

#include "minIni.h"
#include <assert.h>

int Callback(const char* section, const char* key, const char* value, void* userdata)
{
    (void)userdata; /* this parameter is not used in this example */
    printf("    [%s]\t%s=%s\n", section, key, value);
    return 1;
}

#define FTP_DECLARE(x) static void x(ftp_session_t* session, const char* args)
FTP_DECLARE(ABOR);
FTP_DECLARE(ALLO);
FTP_DECLARE(APPE);
FTP_DECLARE(CDUP);
FTP_DECLARE(CWD);
FTP_DECLARE(DELE);
FTP_DECLARE(FEAT);
FTP_DECLARE(HELP);
FTP_DECLARE(LIST);
FTP_DECLARE(MDTM);
FTP_DECLARE(MKD);
FTP_DECLARE(MLSD);
FTP_DECLARE(MLST);
FTP_DECLARE(MODE);
FTP_DECLARE(NLST);
FTP_DECLARE(NOOP);
FTP_DECLARE(OPTS);
FTP_DECLARE(PASS);
FTP_DECLARE(PASV);
FTP_DECLARE(PORT);
FTP_DECLARE(PWD);
FTP_DECLARE(QUIT);
FTP_DECLARE(REST);
FTP_DECLARE(RETR);
FTP_DECLARE(RMD);
FTP_DECLARE(RNFR);
FTP_DECLARE(RNTO);
FTP_DECLARE(SIZE);
FTP_DECLARE(STAT);
FTP_DECLARE(STOR);
FTP_DECLARE(STOU);
FTP_DECLARE(STRU);
FTP_DECLARE(SYST);
FTP_DECLARE(TYPE);
FTP_DECLARE(USER);

/*! session state */
typedef enum
{
    COMMAND_STATE,       /*!< waiting for a command */
    DATA_CONNECT_STATE,  /*!< waiting for connection after PASV command */
    DATA_TRANSFER_STATE, /*!< data transfer in progress */
} session_state_t;

/*! ftp_session_set_state flags */
typedef enum
{
    CLOSE_PASV = BIT(0), /*!< Close the pasv_fd */
    CLOSE_DATA = BIT(1), /*!< Close the data_fd */
} set_state_flags_t;

/*! ftp_session_t flags */
typedef enum
{
    SESSION_BINARY = BIT(0), /*!< data transfers in binary mode */
    SESSION_PASV = BIT(1),   /*!< have pasv_addr ready for data transfer command */
    SESSION_PORT = BIT(2),   /*!< have peer_addr ready for data transfer command */
    SESSION_RECV = BIT(3),   /*!< data transfer in source mode */
    SESSION_SEND = BIT(4),   /*!< data transfer in sink mode */
    SESSION_RENAME = BIT(5), /*!< last command was RNFR and buffer contains path */
    SESSION_URGENT = BIT(6), /*!< in telnet urgent mode */
} session_flags_t;

/*! ftp_xfer_dir mode */
typedef enum
{
    XFER_DIR_LIST, /*!< Long list */
    XFER_DIR_MLSD, /*!< Machine list directory */
    XFER_DIR_MLST, /*!< Machine list */
    XFER_DIR_NLST, /*!< Short list */
    XFER_DIR_STAT, /*!< Stat command */
} xfer_dir_mode_t;

typedef enum
{
    SESSION_MLST_TYPE = BIT(0),
    SESSION_MLST_SIZE = BIT(1),
    SESSION_MLST_MODIFY = BIT(2),
    SESSION_MLST_PERM = BIT(3),
    SESSION_MLST_UNIX_MODE = BIT(4),
} session_mlst_flags_t;

// { generational fds
typedef unsigned Generation;

// 0 refers to missing fd -1.
// could be -1 but this is unsafe without deleting the default constructor,
// which is impossible on C.
static Generation generation = 1;

typedef struct FdGeneration
{
    int fd;
    Generation generation;
} FdGeneration;

static const __auto_type NO_FD = (FdGeneration){-1, 0};

// ++generation and store every time we open a control or data socket
// control sockets should be even and data sockets should be odd, keep incrementing until it passes
Generation next_even()
{
    while ((++generation & 1) != 0)
        ;
    return generation;
}
Generation next_odd()
{
    while ((++generation & 1) != 1)
        ;
    return generation;
}
// }

/*! ftp session */
struct ftp_session_t
{
    char cwd[4096];                  //< current working directory
    char lwd[4096];                  //< list working directory
    struct sockaddr_in peer_addr;    //< peer address for data connection
    struct sockaddr_in pasv_addr;    //< listen address for PASV connection
    Generation generation;           //< global identifier of session
    int cmd_fd;                      //< socket for command connection
    FdGeneration pasv;               //< listen socket for PASV
    FdGeneration data;               //< socket for data transfer
    time_t timestamp;                //< time from last command
    session_flags_t flags;           //< session flags
    xfer_dir_mode_t dir_mode;        //< dir transfer mode
    session_mlst_flags_t mlst_flags; //< session MLST flags
    session_state_t state;           //< session state
    ftp_session_t* next;             //< link to next session
    ftp_session_t* prev;             //< link to prev session

    loop_status_t (*transfer)(ftp_session_t*); // data transfer callback
    char buffer[XFER_BUFFERSIZE];              // persistent data between callbacks
    char file_buffer[FILE_BUFFERSIZE];         // stdio file buffer
    char cmd_buffer[CMD_BUFFERSIZE];           // command buffer
    size_t bufferpos;                          // persistent buffer position between callbacks
    size_t buffersize;                         // persistent buffer size between callbacks
    size_t cmd_buffersize;
    uint64_t filepos;  // persistent file position between callbacks
    uint64_t filesize; // persistent file size between callbacks
    FILE* fp;          // persistent open file pointer between callbacks
    DIR* dp;           // persistent open directory pointer between callbacks
    bool user_ok;
    bool pass_ok;
    bool led;

    // { structured logs
    unsigned char depth;
    bool prev_cmd; // no point in a bitfield since we're alignment-constrained anyway
    bool prev_pasv;
    bool prev_data;
    // }
};

// { function tracing
typedef struct Printable
{
    ftp_session_t* maybe_session;
} Printable;

static Generation get_generation(const FdGeneration* fd_gen)
{
    if (fd_gen->fd == -1)
        return 0;
    return fd_gen->generation;
}

static const size_t INDENT_WIDTH = 2;

#define BEFORE "("
#define AFTER ") "
#define DATA_FMT BEFORE "%u+%u" AFTER
#define PASV_FMT BEFORE "%u+%u" AFTER
#define CMD_FMT BEFORE "%u" AFTER

static void session_print(const ftp_session_t* session, const char* suffix)
{
    const __auto_type indent = session->depth * INDENT_WIDTH;
    const Generation gen = session->generation;
    const Generation pasv = get_generation(&session->pasv);
    const Generation data = get_generation(&session->data);

    if (data)
        indent_print(indent, DATA_FMT "%s", gen, data, suffix);
    else if (pasv)
        indent_print(indent, PASV_FMT "%s", gen, pasv, suffix);
    else
        indent_print(indent, CMD_FMT "%s", gen, suffix);
}

static void indent_session(const ftp_session_t* session, const char* fmt, ...)
{
    const __auto_type indent = session->depth * INDENT_WIDTH;

    va_list ap;
    va_start(ap, fmt);
    _indent_print(indent, fmt, ap);
    va_end(ap);
}

#define TEST(KEY)                                                           \
    const Generation KEY = get_generation(&session->KEY);                   \
    if (KEY && !session->prev_##KEY)                                        \
        indent_print(indent, "opened " #KEY "=%u!\n", KEY);                 \
    else if (!KEY && session->prev_##KEY)                                   \
        indent_print(indent, "closed " #KEY "=%u!\n", session->prev_##KEY); \
    session->prev_##KEY = KEY;
// }

static Printable enter_fmt(ftp_session_t* session, const char* const fmt, ...)
{
    if (!should_log)
        return (Printable){
            session};

    const __auto_type indent = session->depth * INDENT_WIDTH;
    TEST(pasv)
    TEST(data)

    session_print(session, "{ ");
    session->depth++;

    // entry only:
    va_list ap;
    va_start(ap, fmt);
    _indent_print(0, fmt, ap);
    va_end(ap);

    return (Printable){
        session,
    };
}

#define enter_func(SESSION, FUNC) enter_fmt(SESSION, "%s\n", FUNC)

static void exit_func(const Printable* p)
{
    if (!should_log)
        return;
    if (!p->maybe_session)
        return;
    const __auto_type session = p->maybe_session;
    const __auto_type indent = session->depth * INDENT_WIDTH;
    TEST(pasv)
    TEST(data)

    session->depth--;
    session_print(session, "}\n");
}

static void stub_func(ftp_session_t* session, const char* const func)
{
    if (!should_log)
        return;
    session_print(session, "{} ");
    indent_print(0, "%s\n", func);
}

#define TRACE_FMT(...)                                          \
    __attribute__((cleanup(exit_func))) const Printable frame = \
        enter_fmt(session, __VA_ARGS__);

#define TRACE_ARGS() \
    TRACE_FMT(CYAN "%s %s\n" RESET, __func__, args ? args : "")

#define TRACE()                                                 \
    __attribute__((cleanup(exit_func))) const Printable frame = \
        enter_func(session, __func__);

#define STUB() \
    stub_func(session, __func__)

/*! ftp command descriptor */
typedef struct ftp_command
{
    const char* name;                             /*!< command name */
    void (*handler)(ftp_session_t*, const char*); /*!< command callback */
} ftp_command_t;

/*! ftp command list */
static ftp_command_t ftp_commands[] =
    {
/*! ftp command */
#define FTP_COMMAND(x) \
    {                  \
        #x,            \
        x,             \
    }
/*! ftp alias */
#define FTP_ALIAS(x, y) \
    {                   \
        #x,             \
        y,              \
    }
        FTP_COMMAND(ABOR),
        FTP_COMMAND(ALLO),
        FTP_COMMAND(APPE),
        FTP_COMMAND(CDUP),
        FTP_COMMAND(CWD),
        FTP_COMMAND(DELE),
        FTP_COMMAND(FEAT),
        FTP_COMMAND(HELP),
        FTP_COMMAND(LIST),
        FTP_COMMAND(MDTM),
        FTP_COMMAND(MKD),
        FTP_COMMAND(MLSD),
        FTP_COMMAND(MLST),
        FTP_COMMAND(MODE),
        FTP_COMMAND(NLST),
        FTP_COMMAND(NOOP),
        FTP_COMMAND(OPTS),
        FTP_COMMAND(PASS),
        FTP_COMMAND(PASV),
        FTP_COMMAND(PORT),
        FTP_COMMAND(PWD),
        FTP_COMMAND(QUIT),
        FTP_COMMAND(REST),
        FTP_COMMAND(RETR),
        FTP_COMMAND(RMD),
        FTP_COMMAND(RNFR),
        FTP_COMMAND(RNTO),
        FTP_COMMAND(SIZE),
        FTP_COMMAND(STAT),
        FTP_COMMAND(STOR),
        FTP_COMMAND(STOU),
        FTP_COMMAND(STRU),
        FTP_COMMAND(SYST),
        FTP_COMMAND(TYPE),
        FTP_COMMAND(USER),
        FTP_ALIAS(XCUP, CDUP),
        FTP_ALIAS(XCWD, CWD),
        FTP_ALIAS(XMKD, MKD),
        FTP_ALIAS(XPWD, PWD),
        FTP_ALIAS(XRMD, RMD),
};
/*! number of ftp commands */
static const size_t num_ftp_commands = sizeof(ftp_commands) / sizeof(ftp_commands[0]);

static void update_free_space(void);
static bool get_session_led_setting();
static bool is_session_authenticated(ftp_session_t* session);
static void user_pass_not_set(ftp_session_t* session);

/*! compare ftp command descriptors
 *
 *  @param[in] p1 left side of comparison (ftp_command_t*)
 *  @param[in] p2 right side of comparison (ftp_command_t*)
 *
 *  @returns <0 if p1 <  p2
 *  @returns 0 if  p1 == p2
 *  @returns >0 if p1 >  p2
 */
static int
ftp_command_cmp(const void* p1,
                const void* p2)
{
    ftp_command_t* c1 = (ftp_command_t*)p1;
    ftp_command_t* c2 = (ftp_command_t*)p2;

    /* ordered by command name */
    return strcasecmp(c1->name, c2->name);
}

#ifdef _3DS
/*! SOC service buffer */
static u32* SOCU_buffer = NULL;

/*! Whether LCD is powered */
static bool lcd_power = true;

/*! aptHook cookie */
static aptHookCookie cookie;
#elif defined(__SWITCH__)

/*! appletHook cookie */
static AppletHookCookie cookie;
#endif

/*! server listen address */
static struct sockaddr_in serv_addr;
/*! listen file descriptor */
static int listenfd = -1;
#ifdef _3DS
/*! current data port */
static in_port_t data_port = DATA_PORT;
#endif
/*! list of ftp sessions */
static ftp_session_t* sess_list = NULL;
// number of FTP sessions
static unsigned num_sessions = 0;
/*! socket buffersize */
static int sock_buffersize = SOCK_BUFFERSIZE;
/*! server start time */
static time_t start_time = 0;

/*! Allocate a new data port
 *
 *  @returns next data port
 */
static in_port_t
next_data_port(void)
{
#ifdef _3DS
    if (++data_port >= 10000)
        data_port = DATA_PORT;
    return data_port;
#else
    return 0; /* ephemeral port */
#endif
}

/*! set a socket to non-blocking
 *
 *  @param[in] fd socket
 *
 *  @returns error
 */
static int
ftp_set_socket_nonblocking(int fd)
{
    int rc, flags;

    /* get the socket flags */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        console_print(RED "fcntl: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    /* add O_NONBLOCK to the socket flags */
    rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (rc != 0)
    {
        console_print(RED "fcntl: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    return 0;
}

/*! set socket options
 *
 *  @param[in] fd socket
 *
 *  @returns failure
 */
static int
ftp_set_socket_options(int fd)
{
    int rc;

    /* increase receive buffer size */
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                    &sock_buffersize, sizeof(sock_buffersize));
    if (rc != 0)
    {
        console_print(RED "setsockopt: SO_RCVBUF %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    /* increase send buffer size */
    rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                    &sock_buffersize, sizeof(sock_buffersize));
    if (rc != 0)
    {
        console_print(RED "setsockopt: SO_SNDBUF %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    return 0;
}

/// Even though we set linger to 0 seconds,
/// the OS still takes several seconds to clean up socket memory after close(),
/// leading to OOM-induced errors when transferring directory trees.
/// If we shrink socket buffers to 1 byte before closing, we can greatly delay these errors.
static int
ftp_shrink_socket(int fd)
{
    int rc;
    int ret = 0;

    int stub_buffersize = 1;

    /* stub out receive buffer */
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                    &stub_buffersize, sizeof(stub_buffersize));
    if (rc != 0)
    {
        console_print(RED "ftp_shrink_socket() setsockopt: SO_RCVBUF %d %s\n" RESET, errno, strerror(errno));
        ret = -1;
    }

    /* stub out send buffer */
    rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                    &stub_buffersize, sizeof(stub_buffersize));
    if (rc != 0)
    {
        console_print(RED "ftp_shrink_socket() setsockopt: SO_SNDBUF %d %s\n" RESET, errno, strerror(errno));
        ret = -1;
    }

    return ret;
}

typedef enum SocketCloseType
{
    SocketListen,
    SocketDisconneced = SocketListen,
    SocketConnected,
} SocketCloseType;

typedef enum ShouldShrinkSocket
{
    ShrinkNo,
    ShrinkYes,
} ShouldShrinkSocket;

/*! close a socket
 *
 *  @param[in] fd        socket to close
 *  @param[in] connected whether this socket is connected
 */
static void
ftp_closesocket(int fd,
                SocketCloseType connected,
                ShouldShrinkSocket shrink)
{
    int rc;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    struct pollfd pollinfo;

    //  console_print("0x%X\n", socketGetLastBsdResult());

    // nothing to shutdown for a listen-only socket
    if (connected == SocketConnected)
    {
        /* get peer address and print */
        rc = getpeername(fd, (struct sockaddr*)&addr, &addrlen);
        if (rc != 0)
        {
            console_print(RED "getpeername: %d %s\n" RESET, errno, strerror(errno));
            console_print(YELLOW "closing connection to fd=%d\n" RESET, fd);
        }
        else
            console_print(YELLOW "closing connection to %s:%u\n" RESET,
                          inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* shutdown connection */
        rc = shutdown(fd, SHUT_WR);
        if (rc != 0)
            console_print(RED "shutdown: %d %s\n" RESET, errno, strerror(errno));

        /* wait for client to close connection */
        pollinfo.fd = fd;
        pollinfo.events = POLLIN;
        pollinfo.revents = 0;
        rc = poll(&pollinfo, 1, 250);
        if (rc < 0)
            console_print(RED "poll: %d %s\n" RESET, errno, strerror(errno));
    }

    /* set linger to 0 */
    struct linger linger;
    linger.l_onoff = 1;
    linger.l_linger = 0;
    rc = setsockopt(fd, SOL_SOCKET, SO_LINGER,
                    &linger, sizeof(linger));
    if (rc != 0)
        console_print(RED "setsockopt: SO_LINGER %d %s\n" RESET,
                      errno, strerror(errno));

    // pasv_fd -> data_fd have ftp_set_socket_options() called and need to be shrunken.
    // listenfd -> cmd_fd do not need to be shrunken.
    // I placed this call *after* shutdown(), so if the client is still sending data
    // we won't fetch 1 byte at a time over the network.
    if (shrink == ShrinkYes)
    {
        // Do we need to shrink listen sockets? I don't care enough to test.
        ftp_shrink_socket(fd);
    }

    /* close socket */
    rc = close(fd);
    if (rc != 0)
        console_print(RED "close: %d %s\n" RESET, errno, strerror(errno));
}

/*! close command socket on ftp session
 *
 *  @param[in] session ftp session
 */
static void
ftp_session_close_cmd(ftp_session_t* session)
{
    /* close command socket */
    if (session->cmd_fd >= 0)
    {
        TRACE();
        ftp_closesocket(session->cmd_fd, SocketConnected, ShrinkNo);
    }
    session->cmd_fd = -1;
}

/*! close listen socket on ftp session
 *
 *  @param[in] session ftp session
 */
static void
ftp_session_close_pasv(ftp_session_t* session)
{
    /* close pasv socket */
    if (session->pasv.fd >= 0)
    {
        TRACE();
        console_print(YELLOW "stop listening on %s:%u\n" RESET,
                      inet_ntoa(session->pasv_addr.sin_addr),
                      ntohs(session->pasv_addr.sin_port));

        ftp_closesocket(session->pasv.fd, SocketListen, ShrinkYes);
    }
    session->pasv = NO_FD;
}

/*! close data socket on ftp session
 *
 *  @param[in] session ftp session
 */
static void
ftp_session_close_data(ftp_session_t* session)
{
    /* close data connection */
    if (session->data.fd >= 0)
    {
        TRACE();
        if (session->data.fd != session->cmd_fd)
            ftp_closesocket(session->data.fd, SocketConnected, ShrinkYes);
        session->data = NO_FD;
    }

    /* clear send/recv flags */
    session->flags &= ~(SESSION_RECV | SESSION_SEND);
}

/*! close open file for ftp session
 *
 *  @param[in] session ftp session
 */
static void
ftp_session_close_file(ftp_session_t* session)
{
    int rc;

    if (session->fp != NULL)
    {
        STUB();
        rc = fclose(session->fp);
        if (rc != 0)
            console_print(RED "fclose: %d %s\n" RESET, errno, strerror(errno));
    }

    session->fp = NULL;
    session->filepos = 0;
}

/*! open file for reading for ftp session
 *
 *  @param[in] session ftp session
 *
 *  @returns -1 for error
 */
static int
ftp_session_open_file_read(ftp_session_t* session)
{
    TRACE();
    int rc;
    struct stat st;

    /* open file in read mode */
    if (!strcmp("/config/sys-ftpd/logs/ftpd.log", session->buffer))
    {
        console_print(RED "Tried to open ftpd.log for reading. That's not allowed!\n");
        return -1;
    }

    session->fp = fopen(session->buffer, "rb");
    if (session->fp == NULL)
    {
        console_print(RED "fopen '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));
        return -1;
    }

    /* it's okay if this fails */
    errno = 0;
    rc = setvbuf(session->fp, session->file_buffer, _IOFBF, FILE_BUFFERSIZE);
    if (rc != 0)
    {
        console_print(RED "setvbuf: %d %s\n" RESET, errno, strerror(errno));
    }

    /* get the file size */
    rc = fstat(fileno(session->fp), &st);
    if (rc != 0)
    {
        console_print(RED "fstat '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));
        return -1;
    }
    session->filesize = st.st_size;

    if (session->filepos != 0)
    {
        rc = fseek(session->fp, session->filepos, SEEK_SET);
        if (rc != 0)
        {
            console_print(RED "fseek '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*! read from an open file for ftp session
 *
 *  @param[in] session ftp session
 *
 *  @returns bytes read
 */
static ssize_t
ftp_session_read_file(ftp_session_t* session)
{
    ssize_t rc;

    /* read file at current position */
    rc = fread(session->buffer, 1, sizeof(session->buffer), session->fp);
    if (rc < 0)
    {
        console_print(RED "fread: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    /* adjust file position */
    session->filepos += rc;

    return rc;
}

/*! open file for writing for ftp session
 *
 *  @param[in] session ftp session
 *  @param[in] append  whether to append
 *
 *  @returns -1 for error
 *
 *  @note truncates file
 */
static int
ftp_session_open_file_write(ftp_session_t* session,
                            bool append)
{
    TRACE();
    int rc;
    const char* mode = "wb";

    if (!strcmp("/config/sys-ftpd/logs/ftpd.log", session->buffer))
    {
        console_print(RED "Tried to open ftpd.log for writing. That's not allowed!");
        return -1;
    }

    if (append)
        mode = "ab";
    else if (session->filepos != 0)
    {
        mode = "r+b";
    }

    if (!append)
    {
        unlink(session->buffer);
        // Opening an exisiting file for writing can apparently result in corruption D:
    }

    /* open file in write mode */
    session->fp = fopen(session->buffer, mode);
    if (session->fp == NULL)
    {
        console_print(RED "fopen '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));
        return -1;
    }

    update_free_space();

    /* it's okay if this fails */
    errno = 0;
    rc = setvbuf(session->fp, session->file_buffer, _IOFBF, FILE_BUFFERSIZE);
    if (rc != 0)
    {
        console_print(RED "setvbuf: %d %s\n" RESET, errno, strerror(errno));
    }

    /* check if this had REST but not APPE */
    if (session->filepos != 0 && !append)
    {
        /* seek to the REST offset */
        rc = fseek(session->fp, session->filepos, SEEK_SET);
        if (rc != 0)
        {
            console_print(RED "fseek '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*! write to an open file for ftp session
 *
 *  @param[in] session ftp session
 *
 *  @returns bytes written
 */
static ssize_t
ftp_session_write_file(ftp_session_t* session)
{
    ssize_t rc;

    /* write to file at current position */
    rc = fwrite(session->buffer + session->bufferpos,
                1, session->buffersize - session->bufferpos,
                session->fp);
    if (rc < 0)
    {
        console_print(RED "fwrite: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }
    else if (rc == 0)
        console_print(RED "fwrite: wrote 0 bytes\n" RESET);

    /* adjust file position */
    session->filepos += rc;

    update_free_space();
    return rc;
}

/*! close current working directory for ftp session
 *
 *   @param[in] session ftp session
 */
static void
ftp_session_close_cwd(ftp_session_t* session)
{
    int rc;

    /* close open directory pointer */
    if (session->dp != NULL)
    {
        STUB();
        rc = closedir(session->dp);
        if (rc != 0)
            console_print(RED "closedir: %d %s\n" RESET, errno, strerror(errno));
    }
    session->dp = NULL;
}

/*! open current working directory for ftp session
 *
 *  @param[in] session ftp session
 *
 *  @return -1 for failure
 */
static int
ftp_session_open_cwd(ftp_session_t* session)
{
    indent_session(session, "ftp_session_open_cwd(\"%s\")\n", session->cwd);
    /* open current working directory */
    session->dp = opendir(session->cwd);
    if (session->dp == NULL)
    {
        console_print(RED "opendir '%s': %d %s\n" RESET, session->cwd, errno, strerror(errno));
        return -1;
    }

    return 0;
}

/*! set state for ftp session
 *
 *  @param[in] session ftp session
 *  @param[in] state   state to set
 *  @param[in] flags   flags
 */
static void
ftp_session_set_state(ftp_session_t* session,
                      session_state_t state,
                      set_state_flags_t flags)
{
    Printable frame = {};
    session->state = state;

    bool log = false;
    if ((flags & CLOSE_PASV) && session->pasv.fd >= 0)
        log = true;
    if ((flags & CLOSE_DATA) && session->data.fd >= 0)
        log = true;
    if (state == COMMAND_STATE && (session->fp || session->dp))
        log = true;
    if (log)
        frame = enter_func(session, __func__);

    /* close pasv and data sockets */
    if (flags & CLOSE_PASV)
        ftp_session_close_pasv(session);
    if (flags & CLOSE_DATA)
        ftp_session_close_data(session);

    if (state == COMMAND_STATE)
    {
        /* close file/cwd */
        ftp_session_close_file(session);
        ftp_session_close_cwd(session);
    }
    exit_func(&frame);
}

/*! fill directory entry
 *
 *  @param[in] session ftp session
 *  @param[in] st      stat data
 *  @param[in] path    path to fill
 *  @param[in] len     path length
 *  @param[in] type    type fact
 *
 *  @returns errno
 */
static int
ftp_session_fill_dirent_type(ftp_session_t* session, const struct stat* st,
                             const char* path, size_t len, const char* type)
{
    session->buffersize = 0;

    if (session->dir_mode == XFER_DIR_MLSD || session->dir_mode == XFER_DIR_MLST)
    {
        if (session->dir_mode == XFER_DIR_MLST)
            session->buffer[session->buffersize++] = ' ';

        if (session->mlst_flags & SESSION_MLST_TYPE)
        {
            /* type fact */
            if (!type)
            {
                type = "???";
                if (S_ISREG(st->st_mode))
                    type = "file";
                else if (S_ISDIR(st->st_mode))
                    type = "dir";
#if !defined(_3DS) && !defined(__SWITCH__)
                else if (S_ISLNK(st->st_mode))
                    type = "os.unix=symlink";
                else if (S_ISCHR(st->st_mode))
                    type = "os.unix=character";
                else if (S_ISBLK(st->st_mode))
                    type = "os.unix=block";
                else if (S_ISFIFO(st->st_mode))
                    type = "os.unix=fifo";
                else if (S_ISSOCK(st->st_mode))
                    type = "os.unix=socket";
#endif
            }

            session->buffersize +=
                sprintf(session->buffer + session->buffersize, "Type=%s;", type);
        }

        if (session->mlst_flags & SESSION_MLST_SIZE)
        {
            /* size fact */
            session->buffersize +=
                sprintf(session->buffer + session->buffersize, "Size=%lld;",
                        (signed long long)st->st_size);
        }

        if (session->mlst_flags & SESSION_MLST_MODIFY)
        {
            /* mtime fact */
            struct tm* tm = gmtime(&st->st_mtime);
            if (tm == NULL)
                return errno;

            session->buffersize +=
                strftime(session->buffer + session->buffersize,
                         sizeof(session->buffer) - session->buffersize,
                         "Modify=%Y%m%d%H%M%S;", tm);
            if (session->buffersize == 0)
                return EOVERFLOW;
        }

        if (session->mlst_flags & SESSION_MLST_PERM)
        {
            /* permission fact */
            strcpy(session->buffer + session->buffersize, "Perm=");
            session->buffersize += strlen("Perm=");

            /* append permission */
            if (S_ISREG(st->st_mode) && (st->st_mode & S_IWUSR))
                session->buffer[session->buffersize++] = 'a';

            /* create permission */
            if (S_ISDIR(st->st_mode) && (st->st_mode & S_IWUSR))
                session->buffer[session->buffersize++] = 'c';

            /* delete permission */
            session->buffer[session->buffersize++] = 'd';

            /* chdir permission */
            if (S_ISDIR(st->st_mode) && (st->st_mode & S_IXUSR))
                session->buffer[session->buffersize++] = 'e';

            /* rename permission */
            session->buffer[session->buffersize++] = 'f';

            /* list permission */
            if (S_ISDIR(st->st_mode) && (st->st_mode & S_IRUSR))
                session->buffer[session->buffersize++] = 'l';

            /* mkdir permission */
            if (S_ISDIR(st->st_mode) && (st->st_mode & S_IWUSR))
                session->buffer[session->buffersize++] = 'm';

            /* delete permission */
            if (S_ISDIR(st->st_mode) && (st->st_mode & S_IWUSR))
                session->buffer[session->buffersize++] = 'p';

            /* read permission */
            if (S_ISREG(st->st_mode) && (st->st_mode & S_IRUSR))
                session->buffer[session->buffersize++] = 'r';

            /* write permission */
            if (S_ISREG(st->st_mode) && (st->st_mode & S_IWUSR))
                session->buffer[session->buffersize++] = 'w';

            session->buffer[session->buffersize++] = ';';
        }

        if (session->mlst_flags & SESSION_MLST_UNIX_MODE)
        {
            /* unix mode fact */
            mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX | S_ISGID | S_ISUID;
            session->buffersize +=
                sprintf(session->buffer + session->buffersize, "UNIX.mode=0%lo;",
                        (unsigned long)(st->st_mode & mask));
        }

        /* make sure space precedes name */
        if (session->buffer[session->buffersize - 1] != ' ')
            session->buffer[session->buffersize++] = ' ';
    }
    else if (session->dir_mode != XFER_DIR_NLST)
    {
        if (session->dir_mode == XFER_DIR_STAT)
            session->buffer[session->buffersize++] = ' ';

        /* perms nlinks owner group size */
        session->buffersize +=
            sprintf(session->buffer + session->buffersize,
                    "%c%c%c%c%c%c%c%c%c%c %lu 3DS 3DS %lld ",
                    S_ISREG(st->st_mode) ? '-' : S_ISDIR(st->st_mode) ? 'd'
                                             :
#if !defined(_3DS) && !defined(__SWITCH__)
                                             S_ISLNK(st->st_mode)    ? 'l'
                                             : S_ISCHR(st->st_mode)  ? 'c'
                                             : S_ISBLK(st->st_mode)  ? 'b'
                                             : S_ISFIFO(st->st_mode) ? 'p'
                                             : S_ISSOCK(st->st_mode) ? 's'
                                                                     :
#endif
                                                                     '?',
                    st->st_mode & S_IRUSR ? 'r' : '-',
                    st->st_mode & S_IWUSR ? 'w' : '-',
                    st->st_mode & S_IXUSR ? 'x' : '-',
                    st->st_mode & S_IRGRP ? 'r' : '-',
                    st->st_mode & S_IWGRP ? 'w' : '-',
                    st->st_mode & S_IXGRP ? 'x' : '-',
                    st->st_mode & S_IROTH ? 'r' : '-',
                    st->st_mode & S_IWOTH ? 'w' : '-',
                    st->st_mode & S_IXOTH ? 'x' : '-',
                    (unsigned long)st->st_nlink,
                    (signed long long)st->st_size);

        /* timestamp */
        struct tm* tm = gmtime(&st->st_mtime);
        if (tm)
        {
            const char* fmt = "%b %e %Y ";
            if (session->timestamp > st->st_mtime && session->timestamp - st->st_mtime < (60 * 60 * 24 * 365 / 2))
            {
                fmt = "%b %e %H:%M ";
            }

            session->buffersize +=
                strftime(session->buffer + session->buffersize,
                         sizeof(session->buffer) - session->buffersize,
                         fmt, tm);
        }
        else
        {
            session->buffersize +=
                sprintf(session->buffer + session->buffersize, "Jan 1 1970 ");
        }
    }

    if (session->buffersize + len + 2 > sizeof(session->buffer))
    {
        /* buffer will overflow */
        return EOVERFLOW;
    }

    /* copy path */
    memcpy(session->buffer + session->buffersize, path, len);
    len = session->buffersize + len;
    session->buffer[len++] = '\r';
    session->buffer[len++] = '\n';
    session->buffersize = len;

    return 0;
}

/*! fill directory entry
 *
 *  @param[in] session ftp session
 *  @param[in] st      stat data
 *  @param[in] path    path to fill
 *  @param[in] len     path length
 *
 *  @returns errno
 */
static int
ftp_session_fill_dirent(ftp_session_t* session, const struct stat* st,
                        const char* path, size_t len)
{
    return ftp_session_fill_dirent_type(session, st, path, len, NULL);
}

/*! transfer loop
 *
 *  Try to transfer as much data as the sockets will allow without blocking
 *
 *  @param[in] session ftp session
 */
static void
ftp_session_transfer(ftp_session_t* session)
{
    int rc;
    do
    {
        rc = session->transfer(session);
    } while (rc == 0);
}

/*! encode a path
 *
 *  @param[in]     path   path to encode
 *  @param[in,out] len    path length
 *  @param[in]     quotes whether to encode quotes
 *
 *  @returns encoded path
 *
 *  @note The caller must free the returned path
 */
static char*
encode_path(const char* path,
            size_t* len,
            bool quotes)
{
    bool enc = false;
    size_t i, diff = 0;
    char *out, *p = (char*)path;

    /* check for \n that needs to be encoded */
    if (memchr(p, '\n', *len) != NULL)
        enc = true;

    if (quotes)
    {
        /* check for " that needs to be encoded */
        p = (char*)path;
        do
        {
            p = memchr(p, '"', path + *len - p);
            if (p != NULL)
            {
                ++p;
                ++diff;
            }
        } while (p != NULL);
    }

    /* check if an encode was needed */
    if (!enc && diff == 0)
        return strdup(path);

    /* allocate space for encoded path */
    p = out = (char*)malloc(*len + diff);
    if (out == NULL)
        return NULL;

    /* copy the path while performing encoding */
    for (i = 0; i < *len; ++i)
    {
        if (*path == '\n')
        {
            /* encoded \n is \0 */
            *p++ = 0;
        }
        else if (quotes && *path == '"')
        {
            /* encoded " is "" */
            *p++ = '"';
            *p++ = '"';
        }
        else
            *p++ = *path;
        ++path;
    }

    *len += diff;
    return out;
}

/*! decode a path
 *
 *  @param[in] session ftp session
 *  @param[in] len     command length
 */
static void
decode_path(ftp_session_t* session,
            size_t len)
{
    size_t i;

    /* decode \0 from the first command */
    for (i = 0; i < len; ++i)
    {
        /* this is an encoded \n */
        if (session->cmd_buffer[i] == 0)
            session->cmd_buffer[i] = '\n';
    }
}

/*! fill cdir directory entry
 *
 *  @param[in] session ftp session
 *  @param[in] path    path to fill
 *
 *  @returns errno
 */
static int
ftp_session_fill_dirent_cdir(ftp_session_t* session, const char* path)
{
    int rc;
    struct stat st;
    char* buffer;
    size_t len;

    rc = stat(path, &st);
    /* double-check this was a directory */
    if (rc == 0 && !S_ISDIR(st.st_mode))
    {
        /* shouldn't happen but just in case */
        rc = -1;
        errno = ENOTDIR;
    }
    if (rc != 0)
        return errno;

    /* encode \n in path */
    len = strlen(path);
    buffer = encode_path(path, &len, false);
    if (!buffer)
        return ENOMEM;

    /* fill dirent with listed directory as type=cdir */
    rc = ftp_session_fill_dirent_type(session, &st, buffer, len, "cdir");
    free(buffer);

    return rc;
}

/*! send a response on the command socket
 *
 *  @param[in] session ftp session
 *  @param[in] buffer  buffer to send
 *  @param[in] len     buffer length
 */
static void
ftp_send_response_buffer(ftp_session_t* session,
                         const char* buffer,
                         size_t len)
{
    ssize_t rc, to_send;

    if (session->cmd_fd < 0)
        return;

    /* send response */
    to_send = len;
    console_print(GREEN "%.*s" RESET, (int)len, buffer);
    rc = send(session->cmd_fd, buffer, to_send, 0);
    if (rc < 0)
    {
        TRACE();
        console_print(RED "send: %d %s\n" RESET, errno, strerror(errno));
        ftp_session_close_cmd(session);
    }
    else if (rc != to_send)
    {
        TRACE();
        console_print(RED "only sent %u/%u bytes\n" RESET,
                      (unsigned int)rc, (unsigned int)to_send);
        ftp_session_close_cmd(session);
    }
}

// Additional space scoped within a command.
static char tmp_buf[CMD_BUFFERSIZE];

__attribute__((format(printf, 3, 4)))
/*! send ftp response to ftp session's peer
 *
 *  @param[in] session ftp session
 *  @param[in] code    response code
 *  @param[in] fmt     format string
 *  @param[in] ...     format arguments
 */
static void
ftp_send_response(ftp_session_t* session,
                  int code,
                  const char* fmt, ...)
{
    // { borrow tmp_buf
    ssize_t rc;
    va_list ap;

    if (session->cmd_fd < 0)
        return;

    /* print response code and message to buffer */
    va_start(ap, fmt);
    if (code > 0)
        rc = sprintf(tmp_buf, "%d ", code);
    else
        rc = sprintf(tmp_buf, "%d-", -code);
    rc += vsnprintf(tmp_buf + rc, sizeof(tmp_buf) - rc, fmt, ap);
    va_end(ap);

    if (rc >= sizeof(tmp_buf))
    {
        /* couldn't fit message; just send code */
        console_print(RED "%s: buffersize too small\n" RESET, __func__);
        if (code > 0)
            rc = sprintf(tmp_buf, "%d \r\n", code);
        else
            rc = sprintf(tmp_buf, "%d-\r\n", -code);
    }

    ftp_send_response_buffer(session, tmp_buf, rc);
    // } tmp_buf
}

/*! destroy ftp session
 *
 *  @param[in] session ftp session
 *
 *  @returns the next session in the list
 */
static ftp_session_t*
ftp_session_destroy(ftp_session_t* session)
{
    Printable frame = enter_func(session, __func__);
    ftp_session_t* next = session->next;

    /* close all sockets/files */
    ftp_session_close_cmd(session);
    ftp_session_close_pasv(session);
    ftp_session_close_data(session);
    ftp_session_close_file(session);
    ftp_session_close_cwd(session);

    /* unlink from sessions list */
    if (session->next)
        session->next->prev = session->prev;
    if (session == sess_list)
        sess_list = session->next;
    else
    {
        session->prev->next = session->next;
        if (session == sess_list->prev)
            sess_list->prev = session->prev;
    }

    exit_func(&frame);

    /* deallocate */
    num_sessions--;
    free(session);

    return next;
}

#define MAX_SESSIONS 16

/*! allocate new ftp session
 *
 *  @param[in] listen_fd socket to accept connection from
 *  @return 0 or error code
 */
static int
ftp_session_new(int listen_fd)
{
    ssize_t rc;
    int new_fd;
    ftp_session_t* session;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    /* accept connection */
    new_fd = accept(listen_fd, (struct sockaddr*)&addr, &addrlen);
    if (new_fd < 0)
    {
        console_print(RED "accept: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    console_print(CYAN "accepted connection from %s:%u\n" RESET,
                  inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    // if you have 16 FTP sessions open at a time, chances are you're not succeeding
    // with allocations anyway.
    if (num_sessions >= MAX_SESSIONS)
    {
        console_print("too many sessions (%u >= %u)\n", num_sessions, MAX_SESSIONS);
        ftp_closesocket(new_fd, SocketConnected, ShrinkNo);
        return -1;
    }

    /* allocate a new session */
    session = (ftp_session_t*)calloc(1, sizeof(ftp_session_t));
    if (session == NULL)
    {
        console_print(RED "failed to allocate session\n" RESET);
        ftp_closesocket(new_fd, SocketConnected, ShrinkNo);
        return -1;
    }

    /* initialize session */
    strcpy(session->cwd, "/");
    session->peer_addr.sin_addr.s_addr = INADDR_ANY;
    session->generation = next_even();
    session->cmd_fd = new_fd;
    session->pasv = NO_FD;
    session->data = NO_FD;
    session->mlst_flags = SESSION_MLST_TYPE | SESSION_MLST_SIZE | SESSION_MLST_MODIFY | SESSION_MLST_PERM;
    session->state = COMMAND_STATE;
    session->user_ok = false;
    session->pass_ok = false;
    session->led = get_session_led_setting();
    TRACE();

    /* Add new session to end of list */
    // This is some baffling logic... a doubly-linked half-circular list, where
    // [0].prev wraps around to [n-1], yet [n-1].next terminates in NULL???
    // And the words are off by a *single character*...
    if (sess_list == NULL)
    {
        sess_list = session;
        session->prev = session;
    }
    else
    {
        sess_list->prev->next = session; // forward: install new tail
        session->prev = sess_list->prev; // reverse: link old tail
        sess_list->prev = session;       // reverse: install new tail
    }
    num_sessions++;

    /* copy socket address to pasv address */
    addrlen = sizeof(session->pasv_addr);
    rc = getsockname(new_fd, (struct sockaddr*)&session->pasv_addr, &addrlen);
    if (rc != 0)
    {
        console_print(RED "getsockname: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 451, "Failed to get connection info\r\n");
        ftp_session_destroy(session);
        return -1;
    }

    /* send initiator response */
    ftp_send_response(session, 220, "Hello!\r\n");
    return 0;
}

/*! accept PASV connection for ftp session
 *
 *  @param[in] session ftp session
 *
 *  @returns -1 for failure
 */
static int
ftp_session_accept(ftp_session_t* session)
{
    TRACE();
    int rc, new_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    if (session->flags & SESSION_PASV)
    {
        /* clear PASV flag */
        session->flags &= ~SESSION_PASV;

        /* tell the peer that we're ready to accept the connection */
        ftp_send_response(session, 150, "Ready\r\n");

        /* accept connection from peer */
        new_fd = accept(session->pasv.fd, (struct sockaddr*)&addr, &addrlen);
        if (new_fd < 0)
        {
            console_print(RED "accept: %d %s\n" RESET, errno, strerror(errno));
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            ftp_send_response(session, 425, "Failed to establish connection\r\n");
            return -1;
        }

        /* set the socket to non-blocking */
        rc = ftp_set_socket_nonblocking(new_fd);
        if (rc != 0)
        {
            // pasv_fd has large buffers so new_fd will inherit them, and must be shrunken.
            ftp_closesocket(new_fd, SocketConnected, ShrinkYes);
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            ftp_send_response(session, 425, "Failed to establish connection\r\n");
            return -1;
        }

        console_print(CYAN "accepted data connection from %s:%u\n" RESET,
                      inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* we are ready to transfer data */
        session->data = (FdGeneration){
            new_fd,
            session->pasv.generation,
        };
        ftp_session_set_state(session, DATA_TRANSFER_STATE, CLOSE_PASV);

        return 0;
    }
    else
    {
        /* peer didn't send PASV command */
        ftp_send_response(session, 503, "Bad sequence of commands\r\n");
        return -1;
    }
}

/*! connect to peer for ftp session
 *
 *  @param[in] session ftp session
 *
 *  @returns -1 for failure
 */
static int
ftp_session_connect(ftp_session_t* session)
{
    int rc;

    /* clear PORT flag */
    session->flags &= ~SESSION_PORT;

    /* create a new socket */
    session->data = NO_FD;
    session->data.fd = socket(AF_INET, SOCK_STREAM, 0);
    TRACE();
    if (session->data.fd < 0)
    {
        console_print(RED "socket: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }
    session->data.generation = next_odd();

    /* set socket options */
    rc = ftp_set_socket_options(session->data.fd);
    if (rc != 0)
    {
        ftp_closesocket(session->data.fd, SocketDisconneced, ShrinkYes);
        session->data = NO_FD;
        return -1;
    }

    /* set socket to non-blocking */
    rc = ftp_set_socket_nonblocking(session->data.fd);
    if (rc != 0)
        return -1;

    /* connect to peer */
    rc = connect(session->data.fd, (struct sockaddr*)&session->peer_addr,
                 sizeof(session->peer_addr));
    if (rc != 0)
    {
        if (errno != EINPROGRESS)
        {
            console_print(RED "connect: %d %s\n" RESET, errno, strerror(errno));
            ftp_closesocket(session->data.fd, SocketDisconneced, ShrinkYes);
            session->data = NO_FD;
            return -1;
        }
    }
    else
    {
        console_print(CYAN "connected to %s:%u\n" RESET,
                      inet_ntoa(session->peer_addr.sin_addr),
                      ntohs(session->peer_addr.sin_port));

        ftp_session_set_state(session, DATA_TRANSFER_STATE, CLOSE_PASV);
        ftp_send_response(session, 150, "Ready\r\n");
    }

    return 0;
}

/*! read command for ftp session
 *
 *  @param[in] session ftp session
 *  @param[in] events  poll events
 */
static void
ftp_session_read_command(ftp_session_t* session,
                         int events)
{
    char *buffer, *args, *next = NULL;
    size_t i, len;
    int atmark;
    ssize_t rc;
    ftp_command_t key, *command;

    /* check out-of-band data */
    if (events & POLLPRI)
    {
        session->flags |= SESSION_URGENT;

        /* check if we are at the urgent marker */
        atmark = sockatmark(session->cmd_fd);
        if (atmark < 0)
        {
            TRACE();
            console_print(RED "sockatmark: %d %s\n" RESET, errno, strerror(errno));
            ftp_session_close_cmd(session);
            return;
        }

        if (!atmark)
        {
            /* discard in-band data */
            rc = recv(session->cmd_fd, session->cmd_buffer, sizeof(session->cmd_buffer), 0);
            if (rc < 0 && errno != EWOULDBLOCK)
            {
                TRACE();
                console_print(RED "recv: %d %s\n" RESET, errno, strerror(errno));
                ftp_session_close_cmd(session);
            }

            return;
        }

        /* retrieve the urgent data */
        rc = recv(session->cmd_fd, session->cmd_buffer, sizeof(session->cmd_buffer), MSG_OOB);
        if (rc < 0)
        {
            /* EWOULDBLOCK means out-of-band data is on the way */
            if (errno == EWOULDBLOCK)
                return;

            /* error retrieving out-of-band data */
            TRACE();
            console_print(RED "recv (oob): %d %s\n" RESET, errno, strerror(errno));
            ftp_session_close_cmd(session);
            return;
        }

        /* reset the command buffer */
        session->cmd_buffersize = 0;
        return;
    }

    /* prepare to receive data */
    buffer = session->cmd_buffer + session->cmd_buffersize;
    len = sizeof(session->cmd_buffer) - session->cmd_buffersize;
    if (len == 0)
    {
        /* error retrieving command */
        TRACE();
        console_print(RED "Exceeded command buffer size\n" RESET);
        ftp_session_close_cmd(session);
        return;
    }

    /* retrieve command data */
    rc = recv(session->cmd_fd, buffer, len, 0);
    if (rc < 0)
    {
        /* error retrieving command */
        TRACE();
        console_print(RED "recv: %d %s\n" RESET, errno, strerror(errno));
        ftp_session_close_cmd(session);
        return;
    }
    if (rc == 0)
    {
        /* peer closed connection */
        TRACE();
        debug_print("peer closed connection\n");
        ftp_session_close_cmd(session);
        return;
    }
    else
    {
        session->cmd_buffersize += rc;
        len = sizeof(session->cmd_buffer) - session->cmd_buffersize;

        if (session->flags & SESSION_URGENT)
        {
            /* look for telnet data mark */
            for (i = 0; i < session->cmd_buffersize; ++i)
            {
                if ((unsigned char)session->cmd_buffer[i] == 0xF2)
                {
                    /* ignore all data that precedes the data mark */
                    if (i < session->cmd_buffersize - 1)
                        memmove(session->cmd_buffer, session->cmd_buffer + i + 1, len - i - 1);
                    session->cmd_buffersize -= i + 1;
                    session->flags &= ~SESSION_URGENT;
                    break;
                }
            }
        }

        /* loop through commands */
        while (true)
        {
            /* must have at least enough data for the delimiter */
            if (session->cmd_buffersize < 1)
                return;

            /* look for \r\n or \n delimiter */
            for (i = 0; i < session->cmd_buffersize; ++i)
            {
                if (i < session->cmd_buffersize - 1 && session->cmd_buffer[i] == '\r' && session->cmd_buffer[i + 1] == '\n')
                {
                    /* we found a \r\n delimiter */
                    session->cmd_buffer[i] = 0;
                    next = &session->cmd_buffer[i + 2];
                    break;
                }
                else if (session->cmd_buffer[i] == '\n')
                {
                    /* we found a \n delimiter */
                    session->cmd_buffer[i] = 0;
                    next = &session->cmd_buffer[i + 1];
                    break;
                }
            }

            /* check if a delimiter was found */
            if (i == session->cmd_buffersize)
                return;

            /* decode the command */
            decode_path(session, i);

            /* split command from arguments */
            args = buffer = session->cmd_buffer;
            while (*args && !isspace((int)*args))
                ++args;
            if (*args)
                *args++ = 0;

            /* look up the command */
            key.name = buffer;
            command = bsearch(&key, ftp_commands,
                              num_ftp_commands, sizeof(ftp_command_t),
                              ftp_command_cmp);

            /* update command timestamp */
            session->timestamp = time(NULL);

            /* execute the command */
            if (command == NULL)
            {
                /* send header */
                ftp_send_response(session, 502, "Invalid command \"");

                /* send command */
                len = strlen(buffer);
                buffer = encode_path(buffer, &len, false);
                if (buffer != NULL)
                    ftp_send_response_buffer(session, buffer, len);
                else
                    ftp_send_response_buffer(session, key.name, strlen(key.name));
                free(buffer);

                /* send args (if any) */
                if (*args != 0)
                {
                    ftp_send_response_buffer(session, " ", 1);

                    len = strlen(args);
                    buffer = encode_path(args, &len, false);
                    if (buffer != NULL)
                        ftp_send_response_buffer(session, buffer, len);
                    else
                        ftp_send_response_buffer(session, args, strlen(args));
                    free(buffer);
                }

                /* send footer */
                ftp_send_response_buffer(session, "\"\r\n", 3);
            }
            else if (session->state != COMMAND_STATE)
            {
                /* only some commands are available during data transfer */
                if (strcasecmp(command->name, "ABOR") != 0 && strcasecmp(command->name, "STAT") != 0 && strcasecmp(command->name, "QUIT") != 0)
                {
                    TRACE();
                    ftp_send_response(session, 503, "Invalid command during transfer\r\n");
                    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                    ftp_session_close_cmd(session);
                }
                else
                    command->handler(session, args);
            }
            else
            {
                /* clear RENAME flag for all commands except RNTO */
                if (strcasecmp(command->name, "RNTO") != 0)
                    session->flags &= ~SESSION_RENAME;

                command->handler(session, args);
            }

            /* remove executed command from the command buffer */
            len = session->cmd_buffer + session->cmd_buffersize - next;
            if (len > 0)
                memmove(session->cmd_buffer, next, len);
            session->cmd_buffersize = len;
        }
    }
}

static bool is_poll_err(short revents)
{
    if (revents & POLLERR)
        return true;
    if ((revents & POLLHUP) && !(revents & POLLIN))
        return true;
    return false;
}

/*! dispatch work based on poll results
 *
 *  @param[in] session ftp session
 *
 *  @returns next session, if present
 */
static ftp_session_t*
ftp_session_dispatch(ftp_session_t* session, const struct pollfd* pollinfo, nfds_t nfds, int rc)
{
    if (rc < 0)
    {
        ftp_session_close_cmd(session);
    }
    else if (rc > 0)
    {
        /* check the command socket */
        if (pollinfo[0].revents != 0)
        {
            /* handle command */
            if (pollinfo[0].revents & POLL_UNKNOWN)
                console_print(YELLOW "cmd_fd: revents=0x%08X\n" RESET, pollinfo[0].revents);

            /* we need to read a new command */
            // IDK the correct POLLHUP handling. "The control connection shall be closed
            // by the server at the user's request" (https://www.rfc-editor.org/info/rfc959/#page-44)
            if (is_poll_err(pollinfo[0].revents))
            {
                TRACE();
                debug_print("cmd revents=0x%x\n", pollinfo[0].revents);
                ftp_session_close_cmd(session);
            }
            else if (pollinfo[0].revents & (POLLIN | POLLPRI))
                ftp_session_read_command(session, pollinfo[0].revents);
        }

        /* check the data/pasv socket */
        if (nfds > 1 && pollinfo[1].revents != 0)
        {
            switch (session->state)
            {
            case COMMAND_STATE:
                /* this shouldn't happen? */
                break;

            case DATA_CONNECT_STATE:
                if (pollinfo[1].revents & POLL_UNKNOWN)
                    console_print(YELLOW "pasv_fd: revents=0x%08X\n" RESET, pollinfo[1].revents);

                /* we need to accept the PASV connection */
                if (pollinfo[1].revents & (POLLERR | POLLHUP))
                {
                    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                    ftp_send_response(session, 426, "Data connection failed\r\n");
                }
                else if (pollinfo[1].revents & POLLIN)
                {
                    if (ftp_session_accept(session) != 0)
                        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                }
                else if (pollinfo[1].revents & POLLOUT)
                {

                    console_print(CYAN "connected to %s:%u\n" RESET,
                                  inet_ntoa(session->peer_addr.sin_addr),
                                  ntohs(session->peer_addr.sin_port));

                    ftp_session_set_state(session, DATA_TRANSFER_STATE, CLOSE_PASV);
                    ftp_send_response(session, 150, "Ready\r\n");
                }
                break;

            case DATA_TRANSFER_STATE:
                if (pollinfo[1].revents & POLL_UNKNOWN)
                    console_print(YELLOW "data_fd: revents=0x%08X\n" RESET, pollinfo[1].revents);

                /* we need to transfer data */
                // POLLHUP is abnormal, but keep reading remaining data.
                // (https://www.rfc-editor.org/info/rfc959/#page-45)
                if (is_poll_err(pollinfo[1].revents))
                {
                    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                    ftp_send_response(session, 426, "Data connection failed\r\n");
                }
                else if (pollinfo[1].revents & (POLLIN | POLLOUT))
                    ftp_session_transfer(session);
                break;
            }
        }
    }

    /* still connected to peer; return next session */
    if (session->cmd_fd >= 0)
        return session->next;

    /* disconnected from peer; destroy it and return next session */
    debug_print("disconnected from peer\n");
    if (session->led)
    {
        flash_led_disconnect();
    }

    return ftp_session_destroy(session);
}

/* Update free space in status bar */
static void
update_free_space(void)
{
}

/*! Update status bar */
static int
update_status(void)
{
#if defined(_3DS) || defined(__SWITCH__)
//  console_set_status("\n" GREEN STATUS_STRING " "
#    ifdef ENABLE_LOGGING
//                     "DEBUG "
#    endif
    //                    CYAN "%s:%u" RESET,
    //                  inet_ntoa(serv_addr.sin_addr),
    //                ntohs(serv_addr.sin_port));
    update_free_space();
#elif 0 // defined(__SWITCH__)
    char hostname[128];
    socklen_t addrlen = sizeof(serv_addr);
    int rc;
    rc = gethostname(hostname, sizeof(hostname));
    if (rc != 0)
    {
        console_print(RED "gethostname: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }
    console_set_status("\n" GREEN STATUS_STRING " test "
#    ifdef ENABLE_LOGGING
                       "DEBUG "
#    endif
                       CYAN "%s:%u" RESET,
                       hostname,
                       ntohs(serv_addr.sin_port));
    update_free_space();
#else
    char hostname[128];
    socklen_t addrlen = sizeof(serv_addr);
    int rc;

    rc = getsockname(listenfd, (struct sockaddr*)&serv_addr, &addrlen);
    if (rc != 0)
    {
        console_print(RED "getsockname: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    rc = gethostname(hostname, sizeof(hostname));
    if (rc != 0)
    {
        console_print(RED "gethostname: %d %s\n" RESET, errno, strerror(errno));
        return -1;
    }

    console_set_status(GREEN STATUS_STRING " "
#    ifdef ENABLE_LOGGING
                                           "DEBUG "
#    endif
                       YELLOW "IP:" CYAN "%s " YELLOW "Port:" CYAN "%u" RESET,
                       hostname,
                       ntohs(serv_addr.sin_port));
#endif

    return 0;
}

#ifdef _3DS
/*! Handle apt events
 *
 *  @param[in] type    Event type
 *  @param[in] closure Callback closure
 */
static void
apt_hook(APT_HookType type,
         void* closure)
{
    switch (type)
    {
    case APTHOOK_ONSUSPEND:
    case APTHOOK_ONSLEEP:
        /* turn on backlight, or you can't see the home menu! */
        if (R_SUCCEEDED(gspLcdInit()))
        {
            GSPLCD_PowerOnBacklight(GSPLCD_SCREEN_BOTH);
            gspLcdExit();
        }
        break;

    case APTHOOK_ONRESTORE:
    case APTHOOK_ONWAKEUP:
        /* restore backlight power state */
        if (R_SUCCEEDED(gspLcdInit()))
        {
            (lcd_power ? GSPLCD_PowerOnBacklight : GSPLCD_PowerOffBacklight)(GSPLCD_SCREEN_BOTH);
            gspLcdExit();
        }
        break;

    default:
        break;
    }
}
#elif defined(__SWITCH__)
/*! Handle applet events
 *
 *  @param[in] type    Event type
 *  @param[in] closure Callback closure
 */
static void
applet_hook(AppletHookType type,
            void* closure)
{
    (void)closure;
    (void)type;
    /* stubbed for now */
    switch (type)
    {
    default:
        break;
    }
}
#endif

void ftp_pre_init(void)
{
    start_time = time(NULL);

    /* register applet hook */
    appletHook(&cookie, applet_hook, NULL);
}

/*! initialize ftp subsystem */
int ftp_init(void)
{
    int rc = 0;

    /* allocate socket to listen for clients */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
    {
        console_print(RED "socket: %d %s\n" RESET, errno, strerror(errno));
        ftp_exit();
        return -1;
    }

    /* get address to listen on */
    serv_addr.sin_family = AF_INET;

    serv_addr.sin_addr.s_addr = INADDR_ANY;
    char str_port[100];
    ini_gets("Port", "port:", "dummy", str_port, sizearray(str_port), CONFIGPATH);
    LISTEN_PORT = atoi(str_port);
    serv_addr.sin_port = htons(LISTEN_PORT);

    /* reuse address */
    {
        int yes = 1;
        rc = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (rc != 0)
        {
            console_print(RED "setsockopt: %d %s\n" RESET, errno, strerror(errno));
            ftp_exit();
            return -1;
        }
    }

    /* bind socket to listen address */
    rc = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (rc != 0)
    {
        console_print(RED "bind: %d %s\n" RESET, errno, strerror(errno));
        ftp_exit();
        return -1;
    }

    /* listen on socket */
    rc = listen(listenfd, 5);
    if (rc != 0)
    {
        console_print(RED "listen: %d %s\n" RESET, errno, strerror(errno));
        ftp_exit();
        return -1;
    }

    /* print server address */
    rc = update_status();
    if (rc != 0)
    {
        ftp_exit();
        return -1;
    }

    return 0;
}

/*! deinitialize ftp subsystem */
void ftp_exit(void)
{

    debug_print("exiting ftp server\n");

    /* clean up all sessions */
    while (sess_list != NULL)
        ftp_session_destroy(sess_list);
    if (num_sessions != 0)
    {
        console_print("error, num_sessions = %u at ftp_exit()", num_sessions);
        num_sessions = 0;
    }

    /* stop listening for new clients */
    if (listenfd >= 0)
        ftp_closesocket(listenfd, SocketListen, ShrinkNo);

    /* deinitialize socket driver */
    console_print(CYAN "Waiting for socketExit()...\n" RESET);
    console_flush();
}

void ftp_post_exit(void)
{
}

// ms
// static const int POLL_TIMEOUT = 1000;
static const int POLL_TIMEOUT = -1; // forever

/*! ftp look
 *
 *  @returns whether to keep looping
 */
loop_status_t
ftp_iter(void)
{
    int rc;

#define MAX_POLLFDS (1 + 2 * MAX_SESSIONS)

    struct pollfd pollinfo[MAX_POLLFDS];
    nfds_t session_to_fdend[MAX_SESSIONS] = {};

    /* we will poll for new client connections */
    pollinfo[0].fd = listenfd;
    pollinfo[0].events = POLLIN;
    pollinfo[0].revents = 0;
    nfds_t nfds = 1;

    // add fds from active sessions
    // pollfd::events controls whether to be woken up when we can read or write data.
    ftp_session_t* session = sess_list;
    for (
        int sess_idx = 0;
        // i don't trust the linked list to remain under MAX_SESSIONS
        sess_idx < MAX_SESSIONS && session != NULL;
        sess_idx++, session = session->next)
    {
        pollinfo[nfds].fd = session->cmd_fd;
        pollinfo[nfds].events = POLLIN | POLLPRI;
        pollinfo[nfds].revents = 0;
        nfds++;

        switch (session->state)
        {
        case COMMAND_STATE:
            /* we are waiting to read a command */
            break;

        case DATA_CONNECT_STATE:
            if (session->flags & SESSION_PASV)
            {
                /* we are waiting for a PASV connection */
                pollinfo[nfds].fd = session->pasv.fd;
                pollinfo[nfds].events = POLLIN;
            }
            else
            {
                /* we are waiting to complete a PORT connection */
                pollinfo[nfds].fd = session->data.fd;
                pollinfo[nfds].events = POLLOUT;
            }
            pollinfo[nfds].revents = 0;
            nfds++;
            break;

        case DATA_TRANSFER_STATE:
            /* we need to transfer data */
            pollinfo[nfds].fd = session->data.fd;
            if (session->flags & SESSION_RECV)
                pollinfo[nfds].events = POLLIN;
            else
                pollinfo[nfds].events = POLLOUT;
            pollinfo[nfds].revents = 0;
            nfds++;
            break;
        }

        session_to_fdend[sess_idx] = nfds;
    }

    /* poll for incoming connections or readiness */
    // On success, poll() returns a nonnegative value which is the number
    // of elements in the pollfds whose revents fields have been set to a
    // nonzero value (indicating an event or an error).  A return value
    // of zero indicates that the system call timed out before any file
    // descriptors became ready.
    //
    // On error, -1 is returned, and errno is set to indicate the error.
    rc = poll(pollinfo, nfds, POLL_TIMEOUT);
    if (rc < 0)
    {
        /* wifi got disabled */
        console_print(RED "poll: FAILED! %d %s\n" RESET, errno, strerror(errno));

        // if we encounter an error polling, tear down all sessions and the listen fd.
        // if we encounter an error in a session, tear down the session (and the next
        // error and so on) until it stops.
        // FIXME we don't actually tear down sessions on OOM!
        if (errno == ENETDOWN)
            return LOOP_RESTART;
        if (errno == ENOMEM)
            return LOOP_RESTART; // exits loop(), calls ftp_exit() and ftp_init(), just without delay

        return LOOP_EXIT;
    }
    else if (rc == 0)
        goto timeout_skip; // could return early but skip to later for extensibility

    // dispatch new connections
    if (pollinfo[0].revents)
    {
        if (pollinfo[0].revents & POLLIN)
        {
            /* we got a new client */
            if (ftp_session_new(listenfd) != 0)
                // error
                return LOOP_RESTART;
            else
                // The session linked list no longer matches our pollinfo list.
                // Call poll() again with the new list.
                // (Since ftp_session_new() *appends* to the list, we technically could stop
                // when fd_start >= nfds, but this is unpleasantly brittle and starves the new
                // session of polls.)
                return LOOP_CONTINUE;
        }
        else
        {
            console_print(YELLOW "listenfd: revents=0x%08X\n" RESET, pollinfo[0].revents);
        }
    }

    // dispatch existing sessions
    nfds_t fd_start = 1;
    session = sess_list;
    for (int sess_idx = 0; sess_idx < MAX_SESSIONS && session != NULL; sess_idx++)
    {
        const nfds_t fd_end = session_to_fdend[sess_idx];
        session = ftp_session_dispatch(session, pollinfo + fd_start, fd_end - fd_start, rc);
        fd_start = fd_end;
    }

timeout_skip:
#ifdef _3DS
    /* check if the user wants to exit */
    hidScanInput();
    u32 down = hidKeysDown();

    if (down & KEY_B)
        return LOOP_EXIT;

    /* check if the user wants to toggle the LCD power */
    if (down & KEY_START)
    {
        lcd_power = !lcd_power;
        apt_hook(APTHOOK_ONRESTORE, NULL);
    }
#elif defined(__SWITCH__)
    /* check if the user wants to exit */
#endif

    return LOOP_CONTINUE;
}

/*! change to parent directory
 *
 *  @param[in] session ftp session
 */
static void
cd_up(ftp_session_t* session)
{
    char *slash = NULL, *p;

    /* remove basename from cwd */
    for (p = session->cwd; *p; ++p)
    {
        if (*p == '/')
            slash = p;
    }
    *slash = 0;
    if (strlen(session->cwd) == 0)
        strcat(session->cwd, "/");
}

/*! validate a path
 *
 *  @param[in] args path to validate
 */
static int
validate_path(const char* args)
{
    const char* p;

    /* make sure no path components are '..' */
    p = args;
    while ((p = strstr(p, "/..")) != NULL)
    {
        if (p[3] == 0 || p[3] == '/')
            return -1;
    }

    /* make sure there are no '//' */
    if (strstr(args, "//") != NULL)
        return -1;

    return 0;
}

/*! get a path relative to cwd
 *
 *  @param[in] session ftp session
 *  @param[in] cwd     working directory
 *  @param[in] args    path to make
 *
 *  @returns error
 *
 *  @note the output goes to session->buffer
 */
static int
build_path(ftp_session_t* session,
           const char* cwd,
           const char* args)
{
    int rc;
    char* p;

    session->buffersize = 0;
    memset(session->buffer, 0, sizeof(session->buffer));

    /* make sure the input is a valid path */
    if (validate_path(args) != 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (args[0] == '/')
    {
        /* this is an absolute path */
        size_t len = strlen(args);
        if (len > sizeof(session->buffer) - 1)
        {
            errno = ENAMETOOLONG;
            return -1;
        }

        memcpy(session->buffer, args, len);
        session->buffersize = len;
    }
    else
    {
        /* this is a relative path */
        if (strcmp(cwd, "/") == 0)
            rc = snprintf(session->buffer, sizeof(session->buffer), "/%s",
                          args);
        else
            rc = snprintf(session->buffer, sizeof(session->buffer), "%s/%s",
                          cwd, args);

        if (rc >= sizeof(session->buffer))
        {
            errno = ENAMETOOLONG;
            return -1;
        }

        session->buffersize = rc;
    }

    /* remove trailing / */
    p = session->buffer + session->buffersize;
    while (p > session->buffer && *--p == '/')
    {
        *p = 0;
        --session->buffersize;
    }

    /* if we ended with an empty path, it is the root directory */
    if (session->buffersize == 0)
        session->buffer[session->buffersize++] = '/';

    return 0;
}

/*! transfer a directory listing
 *
 *  @param[in] session ftp session
 *
 *  @returns whether to call again
 */
static loop_status_t
list_transfer(ftp_session_t* session)
{
    ssize_t rc;
    size_t len;
    char* buffer;
    struct stat st;
    struct dirent* dent;

    /* check if we sent all available data */
    if (session->bufferpos == session->buffersize)
    {
        /* check xfer dir type */
        if (session->dir_mode == XFER_DIR_STAT)
            rc = 213;
        else
            rc = 226;

        /* check if this was for a file */
        if (session->dp == NULL)
        {
            /* we already sent the file's listing */
            TRACE();
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            ftp_send_response(session, rc, "OK\r\n");
            return LOOP_EXIT;
        }

        /* get the next directory entry */
        dent = readdir(session->dp);
        if (dent == NULL)
        {
            /* we have exhausted the directory listing */
            TRACE();
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            ftp_send_response(session, rc, "OK\r\n");
            return LOOP_EXIT;
        }

        /* TODO I think we are supposed to return entries for . and .. */
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
            return LOOP_CONTINUE;

        /* check if this was a NLST */
        if (session->dir_mode == XFER_DIR_NLST)
        {
            /* NLST gives the whole path name */
            session->buffersize = 0;
            if (build_path(session, session->lwd, dent->d_name) == 0)
            {
                /* encode \n in path */
                len = session->buffersize;
                buffer = encode_path(session->buffer, &len, false);
                if (buffer != NULL)
                {
                    /* copy to the session buffer to send */
                    memcpy(session->buffer, buffer, len);
                    free(buffer);
                    session->buffer[len++] = '\r';
                    session->buffer[len++] = '\n';
                    session->buffersize = len;
                }
            }
        }
        else
        {
#ifdef _3DS
            /* the sdmc directory entry already has the type and size, so no need to do a slow stat */
            u32 magic = *(u32*)session->dp->dirData->dirStruct;

            if (magic == SDMC_DIRITER_MAGIC)
            {
                sdmc_dir_t* dir = (sdmc_dir_t*)session->dp->dirData->dirStruct;
                FS_DirectoryEntry* entry = &dir->entry_data[dir->index];

                if (entry->attributes & FS_ATTRIBUTE_DIRECTORY)
                    st.st_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH;
                else
                    st.st_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;

                if (!(entry->attributes & FS_ATTRIBUTE_READ_ONLY))
                    st.st_mode |= S_IWUSR | S_IWGRP | S_IWOTH;

                st.st_size = entry->fileSize;
                st.st_mtime = 0;

                bool getmtime = true;
                if (session->dir_mode == XFER_DIR_MLSD || session->dir_mode == XFER_DIR_MLST)
                {
                    if (!(session->mlst_flags & SESSION_MLST_MODIFY))
                        getmtime = false;
                }
                else if (session->dir_mode == XFER_DIR_NLST)
                    getmtime = false;

                if ((rc = build_path(session, session->lwd, dent->d_name)) != 0)
                    console_print(RED "build_path: %d %s\n" RESET, errno, strerror(errno));
                else if (getmtime)
                {
                    uint64_t mtime = 0;
                    if ((rc = sdmc_getmtime(session->buffer, &mtime)) != 0)
                        console_print(RED "sdmc_getmtime '%s': 0x%x\n" RESET, session->buffer, rc);
                    else
                        st.st_mtime = mtime;
                }
            }
            else
            {
                /* lstat the entry */
                if ((rc = build_path(session, session->lwd, dent->d_name)) != 0)
                    console_print(RED "build_path: %d %s\n" RESET, errno, strerror(errno));
                else if ((rc = lstat(session->buffer, &st)) != 0)
                    console_print(RED "stat '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));

                if (rc != 0)
                {
                    /* an error occurred */
                    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                    ftp_send_response(session, 550, "unavailable\r\n");
                    return LOOP_EXIT;
                }
            }
#else
            /* lstat the entry */
            if ((rc = build_path(session, session->lwd, dent->d_name)) != 0)
                console_print(RED "build_path: %d %s\n" RESET, errno, strerror(errno));
            else if ((rc = lstat(session->buffer, &st)) != 0)
                console_print(RED "stat '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));

            if (rc != 0)
            {
#    ifndef __SWITCH__
                /* an error occurred */
                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 550, "unavailable\r\n");
                return LOOP_EXIT;
#    else
                // probably archive bit set; list name with dummy stats
                memset(&st, 0, sizeof(st));
                console_print(RED "%s: type %u\n" RESET, dent->d_name, dent->d_type);
                switch (dent->d_type)
                {
                case DT_BLK:
                    st.st_mode = S_IFBLK;
                    break;

                case DT_CHR:
                    st.st_mode = S_IFCHR;
                    break;

                case DT_DIR:
                    st.st_mode = S_IFDIR;
                    break;

                case DT_FIFO:
                    st.st_mode = S_IFIFO;
                    break;

                case DT_LNK:
                    st.st_mode = S_IFLNK;
                    break;

                case DT_REG:
                case DT_UNKNOWN:
                    st.st_mode = S_IFREG;
                    break;

                case DT_SOCK:
                    st.st_mode = S_IFSOCK;
                    break;
                }
#    endif
            }
#endif
            /* encode \n in path */
            len = strlen(dent->d_name);
            buffer = encode_path(dent->d_name, &len, false);
            if (buffer != NULL)
            {
                rc = ftp_session_fill_dirent(session, &st, buffer, len);
                free(buffer);
                if (rc != 0)
                {
                    TRACE();
                    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                    ftp_send_response(session, 425, "%s\r\n", strerror(rc));
                    return LOOP_EXIT;
                }
            }
            else
                session->buffersize = 0;
        }
        session->bufferpos = 0;
    }

    /* send any pending data */
    rc = send(session->data.fd, session->buffer + session->bufferpos,
              session->buffersize - session->bufferpos, 0);
    if (rc <= 0)
    {
        /* error sending data */
        TRACE();
        if (rc < 0)
        {
            if (errno == EWOULDBLOCK)
                return LOOP_EXIT;
            console_print(RED "send: %d %s\n" RESET, errno, strerror(errno));
        }
        else
            console_print(YELLOW "send: %d %s\n" RESET, ECONNRESET, strerror(ECONNRESET));

        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
        ftp_send_response(session, 426, "Connection broken during transfer\r\n");
        return LOOP_EXIT;
    }

    /* we can try to send more data */
    session->bufferpos += rc;
    return LOOP_CONTINUE;
}

/*! send a file to the client
 *
 *  @param[in] session ftp session
 *
 *  @returns whether to call again
 */
static loop_status_t
retrieve_transfer(ftp_session_t* session)
{
    ssize_t rc;

    if (session->bufferpos == session->buffersize)
    {
        /* we have sent all the data so read some more */
        rc = ftp_session_read_file(session);
        if (rc <= 0)
        {
            /* can't read any more data */
            TRACE();
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            if (rc < 0)
                ftp_send_response(session, 451, "Failed to read file\r\n");
            else
                ftp_send_response(session, 226, "OK\r\n");
            return LOOP_EXIT;
        }

        /* we read some data so reset the session buffer to send */
        session->bufferpos = 0;
        session->buffersize = rc;
    }

    /* send any pending data */
    size_t send_size = session->buffersize - session->bufferpos;
    if (send_size > 0x1000)
        send_size = 0x1000;
    rc = send(session->data.fd, session->buffer + session->bufferpos,
              send_size, 0);
    if (rc <= 0)
    {
        /* error sending data */
        TRACE();
        if (rc < 0)
        {
            if (errno == EWOULDBLOCK)
                return LOOP_EXIT;
            console_print(RED "send: %d %s\n" RESET, errno, strerror(errno));
        }
        else
            console_print(YELLOW "send: %d %s\n" RESET, ECONNRESET, strerror(ECONNRESET));

        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
        ftp_send_response(session, 426, "Connection broken during transfer\r\n");
        return LOOP_EXIT;
    }

    /* we can try to send more data */
    session->bufferpos += rc;
    return LOOP_CONTINUE;
}

/*! send a file to the client
 *
 *  @param[in] session ftp session
 *
 *  @returns whether to call again
 */
static loop_status_t
store_transfer(ftp_session_t* session)
{
    ssize_t rc;

    if (session->bufferpos == session->buffersize)
    {
        /* we have written all the received data, so try to get some more */
        rc = recv(session->data.fd, session->buffer, sizeof(session->buffer), 0);
        if (rc <= 0)
        {
            /* can't read any more data */
            TRACE();
            if (rc < 0)
            {
                if (errno == EWOULDBLOCK)
                    return LOOP_EXIT;
                console_print(RED "recv: %d %s\n" RESET, errno, strerror(errno));
            }

            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);

            if (rc == 0)
                ftp_send_response(session, 226, "OK\r\n");
            else
                ftp_send_response(session, 426, "Connection broken during transfer\r\n");
            return LOOP_EXIT;
        }

        /* we received some data so reset the session buffer to write */
        session->bufferpos = 0;
        session->buffersize = rc;
    }

    rc = ftp_session_write_file(session);
    if (rc <= 0)
    {
        /* error writing data */
        TRACE();
        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
        ftp_send_response(session, 451, "Failed to write file\r\n");
        return LOOP_EXIT;
    }

    /* we can try to receive more data */
    session->bufferpos += rc;
    return LOOP_CONTINUE;
}

/*! ftp_xfer_file mode */
typedef enum
{
    XFER_FILE_RETR, /*!< Retrieve a file */
    XFER_FILE_STOR, /*!< Store a file */
    XFER_FILE_APPE, /*!< Append a file */
} xfer_file_mode_t;

/*! Transfer a file
 *
 *  @param[in] session ftp session
 *  @param[in] args    ftp arguments
 *  @param[in] mode    transfer mode
 *
 *  @returns failure
 */
static void
ftp_xfer_file(ftp_session_t* session,
              const char* args,
              xfer_file_mode_t mode)
{
    TRACE_FMT("ftp_xfer_file(\"%s\", %u, %d)\n", args ? args : "", mode);
    int rc;

    /* build the path of the file to transfer */
    if (build_path(session, session->cwd, args) != 0)
    {
        rc = errno;
        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
        ftp_send_response(session, 553, "%s\r\n", strerror(rc));
        return;
    }

    /* open the file for retrieving or storing */
    if (mode == XFER_FILE_RETR)
        rc = ftp_session_open_file_read(session);
    else
        rc = ftp_session_open_file_write(session, mode == XFER_FILE_APPE);

    if (rc != 0)
    {
        /* error opening the file */
        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
        ftp_send_response(session, 450, "failed to open file\r\n");
        return;
    }

    if (session->flags & (SESSION_PORT | SESSION_PASV))
    {
        ftp_session_set_state(session, DATA_CONNECT_STATE, CLOSE_DATA);

        if (session->flags & SESSION_PORT)
        {
            /* setup connection */
            rc = ftp_session_connect(session);
            if (rc != 0)
            {
                /* error connecting */
                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 425, "can't open data connection\r\n");
                return;
            }
        }

        /* set up the transfer */
        session->flags &= ~(SESSION_RECV | SESSION_SEND);
        if (mode == XFER_FILE_RETR)
        {
            session->flags |= SESSION_SEND;
            session->transfer = retrieve_transfer;
        }
        else
        {
            session->flags |= SESSION_RECV;
            session->transfer = store_transfer;
        }

        session->bufferpos = 0;
        session->buffersize = 0;

        return;
    }

    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
    ftp_send_response(session, 503, "Bad sequence of commands\r\n");
}

/*! Transfer a directory
 *
 *  @param[in] session    ftp session
 *  @param[in] args       ftp arguments
 *  @param[in] mode       transfer mode
 *  @param[in] workaround whether to workaround LIST -a
 */
static void
ftp_xfer_dir(ftp_session_t* session,
             const char* args,
             xfer_dir_mode_t mode,
             bool workaround)
{
    TRACE_FMT("ftp_xfer_dir(\"%s\", %u, %d)\n", args ? args : "", mode, workaround);
    ssize_t rc;
    size_t len;
    struct stat st;
    char* buffer;

    /* set up the transfer */
    session->dir_mode = mode;
    session->flags &= ~SESSION_RECV;
    session->flags |= SESSION_SEND;

    session->transfer = list_transfer;
    session->buffersize = 0;
    session->bufferpos = 0;

    if (strlen(args) > 0)
    {
        /* an argument was provided */
        if (build_path(session, session->cwd, args) != 0)
        {
            /* error building path */
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            ftp_send_response(session, 550, "%s\r\n", strerror(errno));
            return;
        }

        /* check if this is a directory */
        session->dp = opendir(session->buffer);
        if (session->dp == NULL)
        {
            /* not a directory; check if it is a file */
            rc = stat(session->buffer, &st);
            if (rc != 0)
            {
                /* error getting stat */
                rc = errno;

                /* work around broken clients that think LIST -a is valid */
                if (workaround && mode == XFER_DIR_LIST)
                {
                    if (args[0] == '-' && (args[1] == 'a' || args[1] == 'l'))
                    {
                        if (args[2] == 0)
                            buffer = strdup(args + 2);
                        else
                            buffer = strdup(args + 3);

                        if (buffer != NULL)
                        {
                            ftp_xfer_dir(session, buffer, mode, false);
                            free(buffer);
                            return;
                        }

                        rc = ENOMEM;
                    }
                }

                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 550, "%s\r\n", strerror(rc));
                return;
            }
            else if (mode == XFER_DIR_MLSD)
            {
                /* specified file instead of directory for MLSD */
                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 501, "%s\r\n", strerror(EINVAL));
                return;
            }
            else if (mode == XFER_DIR_NLST)
            {
                /* NLST uses full path name */
                len = session->buffersize;
                buffer = encode_path(session->buffer, &len, false);
            }
            else
            {
                /* everything else uses base name */
                const char* base = strrchr(session->buffer, '/') + 1;

                len = strlen(base);
                buffer = encode_path(base, &len, false);
            }

            if (buffer)
            {
                rc = ftp_session_fill_dirent(session, &st, buffer, len);
                free(buffer);
            }
            else
                rc = ENOMEM;

            if (rc != 0)
            {
                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 550, "%s\r\n", strerror(rc));
                return;
            }
        }
        else
        {
            /* it was a directory, so set it as the lwd */
            memcpy(session->lwd, session->buffer, session->buffersize);
            session->lwd[session->buffersize] = 0;
            session->buffersize = 0;

            if (session->dir_mode == XFER_DIR_MLSD && (session->mlst_flags & SESSION_MLST_TYPE))
            {
                /* send this directory as type=cdir */
                rc = ftp_session_fill_dirent_cdir(session, session->lwd);
                if (rc != 0)
                {
                    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                    ftp_send_response(session, 550, "%s\r\n", strerror(rc));
                    return;
                }
            }
        }
    }
    else if (ftp_session_open_cwd(session) != 0)
    {
        /* no argument, but opening cwd failed */
        ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
        ftp_send_response(session, 550, "%s\r\n", strerror(errno));
        return;
    }
    else
    {
        /* set the cwd as the lwd */
        strcpy(session->lwd, session->cwd);
        session->buffersize = 0;

        if (session->dir_mode == XFER_DIR_MLSD && (session->mlst_flags & SESSION_MLST_TYPE))
        {
            /* send this directory as type=cdir */
            rc = ftp_session_fill_dirent_cdir(session, session->lwd);
            if (rc != 0)
            {
                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 550, "%s\r\n", strerror(rc));
                return;
            }
        }
    }

    if (mode == XFER_DIR_MLST || mode == XFER_DIR_STAT)
    {
        /* this is a little different; we have to send the data over the command socket */
        ftp_session_set_state(session, DATA_TRANSFER_STATE, CLOSE_PASV | CLOSE_DATA);
        session->data = (FdGeneration){
            session->cmd_fd,
            session->generation,
        };
        session->flags |= SESSION_SEND;
        ftp_send_response(session, -213, "Status\r\n");
        return;
    }
    else if (session->flags & (SESSION_PORT | SESSION_PASV))
    {
        ftp_session_set_state(session, DATA_CONNECT_STATE, CLOSE_DATA);

        if (session->flags & SESSION_PORT)
        {
            /* setup connection */
            rc = ftp_session_connect(session);
            if (rc != 0)
            {
                /* error connecting */
                ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
                ftp_send_response(session, 425, "can't open data connection\r\n");
            }
        }

        return;
    }

    /* we must have got LIST/MLSD/MLST/NLST without a preceding PORT or PASV */
    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
    ftp_send_response(session, 503, "Bad sequence of commands\r\n");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                          F T P   C O M M A N D S                          *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*! @fn static void ABOR(ftp_session_t *session, const char *args)
 *
 *  @brief abort a transfer
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(ABOR)
{
    TRACE_ARGS();

    if (session->state == COMMAND_STATE)
    {
        ftp_send_response(session, 225, "No transfer to abort\r\n");
        return;
    }

    /* abort the transfer */
    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);

    /* send response for this request */
    ftp_send_response(session, 225, "Aborted\r\n");

    /* send response for transfer */
    ftp_send_response(session, 425, "Transfer aborted\r\n");
}

/*! @fn static void ALLO(ftp_session_t *session, const char *args)
 *
 *  @brief allocate space
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(ALLO)
{
    TRACE_ARGS();

    ftp_session_set_state(session, COMMAND_STATE, 0);

    ftp_send_response(session, 202, "superfluous command\r\n");
}

/*! @fn static void APPE(ftp_session_t *session, const char *args)
 *
 *  @brief append data to a file
 *
 *  @note requires a PASV or PORT connection
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(APPE)
{
    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* open the file in append mode */
    ftp_xfer_file(session, args, XFER_FILE_APPE);
}

/*! @fn static void CDUP(ftp_session_t *session, const char *args)
 *
 *  @brief CWD to parent directory
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(CDUP)
{
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* change to parent directory */
    cd_up(session);
    ftp_send_response(session, 200, "OK\r\n");
}

/*! @fn static void CWD(ftp_session_t *session, const char *args)
 *
 *  @brief change working directory
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(CWD)
{
    struct stat st;
    int rc;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* .. is equivalent to CDUP */
    if (strcmp(args, "..") == 0)
    {
        cd_up(session);
        ftp_send_response(session, 200, "OK\r\n");
        return;
    }

    /* build the new cwd path */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }

    /* get the path status */
    rc = stat(session->buffer, &st);
    if (rc != 0)
    {
        console_print(RED "stat '%s': %d %s\n" RESET, session->buffer, errno, strerror(errno));
        ftp_send_response(session, 550, "unavailable\r\n");
        return;
    }

    /* make sure it is a directory */
    if (!S_ISDIR(st.st_mode))
    {
        ftp_send_response(session, 553, "not a directory\r\n");
        return;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"

    /* copy the path into the cwd */
    strncpy(session->cwd, session->buffer, sizeof(session->cwd));

#pragma GCC diagnostic pop

    ftp_send_response(session, 200, "OK\r\n");
}

/*! @fn static void DELE(ftp_session_t *session, const char *args)
 *
 *  @brief delete a file
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(DELE)
{
    int rc;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the file path */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }

    /* try to unlink the path */
    rc = unlink(session->buffer);
    if (rc != 0)
    {
        /* error unlinking the file */
        console_print(RED "unlink: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 550, "failed to delete file\r\n");
        return;
    }

    update_free_space();
    ftp_send_response(session, 250, "OK\r\n");
}

/*! @fn static void FEAT(ftp_session_t *session, const char *args)
 *
 *  @brief list server features
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(FEAT)
{
    TRACE_ARGS();

    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* list our features */
    ftp_send_response(session, -211, "\r\n"
                                     " MDTM\r\n"
                                     " MLST Type%s;Size%s;Modify%s;Perm%s;UNIX.mode%s;\r\n"
                                     " PASV\r\n"
                                     " SIZE\r\n"
                                     " TVFS\r\n"
                                     " UTF8\r\n"
                                     "\r\n"
                                     "211 End\r\n",
                      session->mlst_flags & SESSION_MLST_TYPE ? "*" : "",
                      session->mlst_flags & SESSION_MLST_SIZE ? "*" : "",
                      session->mlst_flags & SESSION_MLST_MODIFY ? "*" : "",
                      session->mlst_flags & SESSION_MLST_PERM ? "*" : "",
                      session->mlst_flags & SESSION_MLST_UNIX_MODE ? "*" : "");
}

/*! @fn static void HELP(ftp_session_t *session, const char *args)
 *
 *  @brief print server help
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(HELP)
{
    TRACE_ARGS();

    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* list our accepted commands */
    ftp_send_response(session, -214,
                      "The following commands are recognized\r\n"
                      " ABOR ALLO APPE CDUP CWD DELE FEAT HELP LIST MDTM MKD MLSD MLST MODE\r\n"
                      " NLST NOOP OPTS PASS PASV PORT PWD QUIT REST RETR RMD RNFR RNTO STAT\r\n"
                      " STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD XPWD XRMD\r\n"
                      "214 End\r\n");
}

/*! @fn static void LIST(ftp_session_t *session, const char *args)
 *
 *  @brief retrieve a directory listing
 *
 *  @note Requires a PORT or PASV connection
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(LIST)
{
    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* open the path in LIST mode */
    ftp_xfer_dir(session, args, XFER_DIR_LIST, true);
}

/*! @fn static void MDTM(ftp_session_t *session, const char *args)
 *
 *  @brief get last modification time
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(MDTM)
{
    int rc;
#ifdef _3DS
    uint64_t mtime;
#else
    struct stat st;
#endif
    time_t t_mtime;
    struct tm* tm;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the path */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }

#ifdef _3DS
    rc = sdmc_getmtime(session->buffer, &mtime);
    if (rc != 0)
    {
        ftp_send_response(session, 550, "Error getting mtime\r\n");
        return;
    }
    t_mtime = mtime;
#else
    rc = stat(session->buffer, &st);
    if (rc != 0)
    {
        ftp_send_response(session, 550, "Error getting mtime\r\n");
        return;
    }
    t_mtime = st.st_mtime;
#endif

    tm = gmtime(&t_mtime);
    if (tm == NULL)
    {
        ftp_send_response(session, 550, "Error getting mtime\r\n");
        return;
    }

    session->buffersize = strftime(session->buffer, sizeof(session->buffer), "%Y%m%d%H%M%S", tm);
    if (session->buffersize == 0)
    {
        ftp_send_response(session, 550, "Error getting mtime\r\n");
        return;
    }

    session->buffer[session->buffersize] = 0;

    ftp_send_response(session, 213, "%s\r\n", session->buffer);
}
/*! @fn static void MKD(ftp_session_t *session, const char *args)
 *
 *  @brief create a directory
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(MKD)
{
    int rc;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the path */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }
    console_print("mkdir: %s\n", session->buffer);

    /* try to create the directory */
    rc = mkdir(session->buffer, 0755);
    if (rc != 0 && errno != EEXIST)
    {
        /* mkdir failure */
        console_print(RED "mkdir: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 550, "failed to create directory\r\n");
        return;
    }

    update_free_space();
    ftp_send_response(session, 250, "OK\r\n");
}

/*! @fn static void MLSD(ftp_session_t *session, const char *args)
 *
 *  @brief set transfer mode
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(MLSD)
{
    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* open the path in MLSD mode */
    ftp_xfer_dir(session, args, XFER_DIR_MLSD, true);
}

/*! @fn static void MLST(ftp_session_t *session, const char *args)
 *
 *  @brief set transfer mode
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(MLST)
{
    struct stat st;
    int rc;
    char* path;
    size_t len;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the path */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 501, "%s\r\n", strerror(errno));
        return;
    }

    /* stat path */
    rc = lstat(session->buffer, &st);
    if (rc != 0)
    {
        ftp_send_response(session, 550, "%s\r\n", strerror(errno));
        return;
    }

    /* encode \n in path */
    len = session->buffersize;
    path = encode_path(session->buffer, &len, true);
    if (!path)
    {
        ftp_send_response(session, 550, "%s\r\n", strerror(ENOMEM));
        return;
    }

    session->dir_mode = XFER_DIR_MLST;
    rc = ftp_session_fill_dirent(session, &st, path, len);
    free(path);
    if (rc != 0)
    {
        ftp_send_response(session, 550, "%s\r\n", strerror(errno));
        return;
    }

    path = malloc(session->buffersize + 1);
    if (!path)
    {
        ftp_send_response(session, 550, "%s\r\n", strerror(ENOMEM));
        return;
    }

    memcpy(path, session->buffer, session->buffersize);
    path[session->buffersize] = 0;
    ftp_send_response(session, -250, "Status\r\n%s250 End\r\n", path);
    free(path);
}

/*! @fn static void MODE(ftp_session_t *session, const char *args)
 *
 *  @brief set transfer mode
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(MODE)
{
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* we only accept S (stream) mode */
    if (strcasecmp(args, "S") == 0)
    {
        ftp_send_response(session, 200, "OK\r\n");
        return;
    }

    ftp_send_response(session, 504, "unavailable\r\n");
}

/*! @fn static void NLST(ftp_session_t *session, const char *args)
 *
 *  @brief retrieve a name list
 *
 *  @note Requires a PASV or PORT connection
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(NLST)
{
    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* open the path in NLST mode */
    return ftp_xfer_dir(session, args, XFER_DIR_NLST, false);
}

/*! @fn static void NOOP(ftp_session_t *session, const char *args)
 *
 *  @brief no-op
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(NOOP)
{
    TRACE_ARGS();

    /* this is a no-op */
    ftp_send_response(session, 200, "OK\r\n");
}

/*! @fn static void OPTS(ftp_session_t *session, const char *args)
 *
 *  @brief set options
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(OPTS)
{
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* we accept the following UTF8 options */
    if (strcasecmp(args, "UTF8") == 0 || strcasecmp(args, "UTF8 ON") == 0 || strcasecmp(args, "UTF8 NLST") == 0)
    {
        ftp_send_response(session, 200, "OK\r\n");
        return;
    }

    /* check MLST options */
    if (strncasecmp(args, "MLST ", 5) == 0)
    {
        static const struct
        {
            const char* name;
            session_mlst_flags_t flag;
        } mlst_flags[] =
            {
                {
                    "Type;",
                    SESSION_MLST_TYPE,
                },
                {
                    "Size;",
                    SESSION_MLST_SIZE,
                },
                {
                    "Modify;",
                    SESSION_MLST_MODIFY,
                },
                {
                    "Perm;",
                    SESSION_MLST_PERM,
                },
                {
                    "UNIX.mode;",
                    SESSION_MLST_UNIX_MODE,
                },
            };
        static const size_t num_mlst_flags = sizeof(mlst_flags) / sizeof(mlst_flags[0]);

        session_mlst_flags_t flags = 0;
        args += 5;
        const char* p = args;
        while (*p)
        {
            for (size_t i = 0; i < num_mlst_flags; ++i)
            {
                if (strncasecmp(mlst_flags[i].name, p, strlen(mlst_flags[i].name)) == 0)
                {
                    flags |= mlst_flags[i].flag;
                    p += strlen(mlst_flags[i].name) - 1;
                    break;
                }
            }

            while (*p && *p != ';')
                ++p;

            if (*p == ';')
                ++p;
        }

        session->mlst_flags = flags;
        ftp_send_response(session, 200, "MLST OPTS%s%s%s%s%s%s\r\n",
                          flags ? " " : "",
                          flags & SESSION_MLST_TYPE ? "Type;" : "",
                          flags & SESSION_MLST_SIZE ? "Size;" : "",
                          flags & SESSION_MLST_MODIFY ? "Modify;" : "",
                          flags & SESSION_MLST_PERM ? "Perm;" : "",
                          flags & SESSION_MLST_UNIX_MODE ? "UNIX.mode;" : "");
        return;
    }

    ftp_send_response(session, 504, "invalid argument\r\n");
}

/*! @fn static void PASV(ftp_session_t *session, const char *args)
 *
 *  @brief request an address to connect to
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(PASV)
{
    int rc;
    char buffer[INET_ADDRSTRLEN + 10];
    char* p;
    in_port_t port;

    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    memset(buffer, 0, sizeof(buffer));

    /* reset the state */
    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
    session->flags &= ~(SESSION_PASV | SESSION_PORT);

    /* create a socket to listen on */
    session->pasv = NO_FD;
    session->pasv.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (session->pasv.fd < 0)
    {
        console_print(RED "socket: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 451, "\r\n");
        return;
    }
    session->pasv.generation = next_odd();

    /* set the socket options */
    rc = ftp_set_socket_options(session->pasv.fd);
    if (rc != 0)
    {
        /* failed to set socket options */
        ftp_session_close_pasv(session);
        ftp_send_response(session, 451, "\r\n");
        return;
    }

    /* grab a new port */
    session->pasv_addr.sin_port = htons(next_data_port());

#if defined(_3DS) || defined(__SWITCH__)
    console_print(YELLOW "binding to %s:%u\n" RESET,
                  inet_ntoa(session->pasv_addr.sin_addr),
                  ntohs(session->pasv_addr.sin_port));
#endif

    /* bind to the port */
    rc = bind(session->pasv.fd, (struct sockaddr*)&session->pasv_addr,
              sizeof(session->pasv_addr));
    if (rc != 0)
    {
        /* failed to bind */
        console_print(RED "bind: %d %s\n" RESET, errno, strerror(errno));
        ftp_session_close_pasv(session);
        ftp_send_response(session, 451, "\r\n");
        return;
    }

    /* listen on the socket */
    rc = listen(session->pasv.fd, 1);
    if (rc != 0)
    {
        /* failed to listen */
        console_print(RED "listen: %d %s\n" RESET, errno, strerror(errno));
        ftp_session_close_pasv(session);
        ftp_send_response(session, 451, "\r\n");
        return;
    }

#ifndef _3DS
    {
        /* get the socket address since we requested an ephemeral port */
        socklen_t addrlen = sizeof(session->pasv_addr);
        rc = getsockname(session->pasv.fd, (struct sockaddr*)&session->pasv_addr,
                         &addrlen);
        if (rc != 0)
        {
            /* failed to get socket address */
            console_print(RED "getsockname: %d %s\n" RESET, errno, strerror(errno));
            ftp_session_close_pasv(session);
            ftp_send_response(session, 451, "\r\n");
            return;
        }
    }
#endif

    /* we are now listening on the socket */
    console_print(YELLOW "listening on %s:%u\n" RESET,
                  inet_ntoa(session->pasv_addr.sin_addr),
                  ntohs(session->pasv_addr.sin_port));
    session->flags |= SESSION_PASV;

    /* print the address in the ftp format */
    port = ntohs(session->pasv_addr.sin_port);
    strcpy(buffer, inet_ntoa(session->pasv_addr.sin_addr));
    sprintf(buffer + strlen(buffer), ",%u,%u",
            port >> 8, port & 0xFF);
    for (p = buffer; *p; ++p)
    {
        if (*p == '.')
            *p = ',';
    }

    ftp_send_response(session, 227, "Entering Passive Mode (%s)\r\n", buffer);
}

/*! @fn static void PORT(ftp_session_t *session, const char *args)
 *
 *  @brief provide an address for the server to connect to
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(PORT)
{
    char *addrstr, *p, *portstr = NULL;
    int commas = 0, rc;
    short port = 0;
    unsigned long val;
    struct sockaddr_in addr;

    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* reset the state */
    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
    session->flags &= ~(SESSION_PASV | SESSION_PORT);

    /* dup the args since they are const and we need to change it */
    addrstr = strdup(args);
    if (addrstr == NULL)
    {
        ftp_send_response(session, 425, "%s\r\n", strerror(ENOMEM));
        return;
    }

    /* replace a,b,c,d,e,f with a.b.c.d\0e.f */
    for (p = addrstr; *p; ++p)
    {
        if (*p == ',')
        {
            if (commas != 3)
                *p = '.';
            else
            {
                *p = 0;
                portstr = p + 1;
            }
            ++commas;
        }
    }

    /* make sure we got the right number of values */
    if (commas != 5)
    {
        free(addrstr);
        ftp_send_response(session, 501, "%s\r\n", strerror(EINVAL));
        return;
    }

    /* parse the address */
    rc = inet_aton(addrstr, &addr.sin_addr);
    if (rc == 0)
    {
        free(addrstr);
        ftp_send_response(session, 501, "%s\r\n", strerror(EINVAL));
        return;
    }

    /* parse the port */
    val = 0;
    port = 0;
    for (p = portstr; *p; ++p)
    {
        if (!isdigit((int)*p))
        {
            if (p == portstr || *p != '.' || val > 0xFF)
            {
                free(addrstr);
                ftp_send_response(session, 501, "%s\r\n", strerror(EINVAL));
                return;
            }
            port <<= 8;
            port += val;
            val = 0;
        }
        else
        {
            val *= 10;
            val += *p - '0';
        }
    }

    /* validate the port */
    if (val > 0xFF || port > 0xFF)
    {
        free(addrstr);
        ftp_send_response(session, 501, "%s\r\n", strerror(EINVAL));
        return;
    }
    port <<= 8;
    port += val;

    /* fill in the address port and family */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    free(addrstr);

    memcpy(&session->peer_addr, &addr, sizeof(addr));

    /* we are ready to connect to the client */
    session->flags |= SESSION_PORT;
    ftp_send_response(session, 200, "OK\r\n");
}

/*! @fn static void PWD(ftp_session_t *session, const char *args)
 *
 *  @brief print working directory
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(PWD)
{
    size_t len = sizeof(tmp_buf), i;
    char* path;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* encode the cwd */
    len = strlen(session->cwd);
    path = encode_path(session->cwd, &len, true);
    if (path != NULL)
    {
        // { borrow tmp_buf
        i = sprintf(tmp_buf, "257 \"");
        if (i + len + 3 > sizeof(tmp_buf))
        {
            /* buffer will overflow */
            // } tmp_buf
            free(path);
            ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
            // ftp_send_response borrows tmp_buf
            ftp_send_response(session, 550, "%s\r\n", strerror(EOVERFLOW));
            return;
        }
        memcpy(tmp_buf + i, path, len);
        free(path);
        len += i;
        tmp_buf[len++] = '"';
        tmp_buf[len++] = '\r';
        tmp_buf[len++] = '\n';

        ftp_send_response_buffer(session, tmp_buf, len);
        // } tmp_buf
        return;
    }

    // ftp_send_response borrows tmp_buf
    ftp_send_response(session, 425, "%s\r\n", strerror(ENOMEM));
}

/*! @fn static void QUIT(ftp_session_t *session, const char *args)
 *
 *  @brief terminate ftp session
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(QUIT)
{
    TRACE_ARGS();

    /* disconnect from the client */
    ftp_send_response(session, 221, "disconnecting\r\n");
    ftp_session_close_cmd(session);
}

/*! @fn static void REST(ftp_session_t *session, const char *args)
 *
 *  @brief restart a transfer
 *
 *  @note sets file position for a subsequent STOR operation
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(REST)
{
    const char* p;
    uint64_t pos = 0;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* make sure an argument is provided */
    if (args == NULL)
    {
        ftp_send_response(session, 504, "invalid argument\r\n");
        return;
    }

    /* parse the offset */
    for (p = args; *p; ++p)
    {
        if (!isdigit((int)*p))
        {
            ftp_send_response(session, 504, "invalid argument\r\n");
            return;
        }

        if (UINT64_MAX / 10 < pos)
        {
            ftp_send_response(session, 504, "invalid argument\r\n");
            return;
        }

        pos *= 10;

        if (UINT64_MAX - (*p - '0') < pos)
        {
            ftp_send_response(session, 504, "invalid argument\r\n");
            return;
        }

        pos += (*p - '0');
    }

    /* set the restart offset */
    session->filepos = pos;
    ftp_send_response(session, 200, "OK\r\n");
}

/*! @fn static void RETR(ftp_session_t *session, const char *args)
 *
 *  @brief retrieve a file
 *
 *  @note Requires a PASV or PORT connection
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(RETR)
{
    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* open the file to retrieve */
    return ftp_xfer_file(session, args, XFER_FILE_RETR);
}

/*! @fn static void RMD(ftp_session_t *session, const char *args)
 *
 *  @brief remove a directory
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(RMD)
{
    int rc;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the path to remove */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }

    /* remove the directory */
    rc = rmdir(session->buffer);
    if (rc != 0)
    {
        /* rmdir error */
        console_print(RED "rmdir: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 550, "failed to delete directory\r\n");
        return;
    }

    update_free_space();
    ftp_send_response(session, 250, "OK\r\n");
}

/*! @fn static void RNFR(ftp_session_t *session, const char *args)
 *
 *  @brief rename from
 *
 *  @note Must be followed by RNTO
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(RNFR)
{
    int rc;
    struct stat st;
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the path to rename from */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }

    /* make sure the path exists */
    rc = lstat(session->buffer, &st);
    if (rc != 0)
    {
        /* error getting path status */
        console_print(RED "lstat: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 450, "no such file or directory\r\n");
        return;
    }

    /* we are ready for RNTO */
    session->flags |= SESSION_RENAME;
    ftp_send_response(session, 350, "OK\r\n");
}

/*! @fn static void RNTO(ftp_session_t *session, const char *args)
 *
 *  @brief rename to
 *
 *  @note Must be preceded by RNFR
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(RNTO)
{
    char* rnfr = tmp_buf; // rename-from buffer
    int rc;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* make sure the previous command was RNFR */
    if (!(session->flags & SESSION_RENAME))
    {
        ftp_send_response(session, 503, "Bad sequence of commands\r\n");
        return;
    }

    /* clear the rename state */
    session->flags &= ~SESSION_RENAME;

    /* copy the RNFR path */
    // { borrow rnfr=tmp_buf
    // newlib has memccpy.
    char* rnfr_end = memccpy(rnfr, session->buffer, '\0', sizeof tmp_buf);
    _Static_assert(sizeof tmp_buf == CMD_BUFFERSIZE, "buffer size mismatch");
    if (!rnfr_end)
    {
        // should not be possible, since ftp_session_read_command() -> RNFR() copies
        // (session->cmd_buffer ⇒ arg) to session->buffer, and arg is shorter than
        // CMD_BUFFERSIZE.
        // } rnfr=tmp_buf
        // ftp_send_response borrows tmp_buf
        return ftp_send_response(session, 553, "source too long (unreachable?)\r\n");
    }

    /* build the path to rename to */
    if (build_path(session, session->cwd, args) != 0)
    {
        // } rnfr=tmp_buf
        // ftp_send_response borrows tmp_buf
        return ftp_send_response(session, 554, "%s\r\n", strerror(errno));
    }

    /* rename the file */
    rc = rename(rnfr, session->buffer);
    // } rnfr=tmp_buf
    if (rc != 0)
    {
        /* rename failure */
        console_print(RED "rename: %d %s\n" RESET, errno, strerror(errno));
        ftp_send_response(session, 550, "failed to rename file/directory\r\n");
        return;
    }

    update_free_space();
    ftp_send_response(session, 250, "OK\r\n");
}

/*! @fn static void SIZE(ftp_session_t *session, const char *args)
 *
 *  @brief get file size
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(SIZE)
{
    int rc;
    struct stat st;

    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    if (!is_session_authenticated(session))
        return;

    /* build the path to stat */
    if (build_path(session, session->cwd, args) != 0)
    {
        ftp_send_response(session, 553, "%s\r\n", strerror(errno));
        return;
    }

    rc = stat(session->buffer, &st);
    if (rc != 0 || !S_ISREG(st.st_mode))
    {
        ftp_send_response(session, 550, "Could not get file size.\r\n");
        return;
    }

    ftp_send_response(session, 213, "%" PRIu64 "\r\n",
                      (uint64_t)st.st_size);
}

/*! @fn static void STAT(ftp_session_t *session, const char *args)
 *
 *  @brief get status
 *
 *  @note If no argument is supplied, and a transfer is occurring, get the
 *        current transfer status. If no argument is supplied, and no transfer
 *        is occurring, get the server status. If an argument is supplied, this
 *        is equivalent to LIST, except the data is sent over the command
 *        socket.
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(STAT)
{
    time_t uptime = time(NULL) - start_time;
    int hours = uptime / 3600;
    int minutes = (uptime / 60) % 60;
    int seconds = uptime % 60;

    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    if (session->state == DATA_CONNECT_STATE)
    {
        /* we are waiting to connect to the client */
        ftp_send_response(session, -211, "FTP server status\r\n"
                                         " Waiting for data connection\r\n"
                                         "211 End\r\n");
        return;
    }
    else if (session->state == DATA_TRANSFER_STATE)
    {
        /* we are in the middle of a transfer */
        ftp_send_response(session, -211, "FTP server status\r\n"
                                         " Transferred %" PRIu64 " bytes\r\n"
                                         "211 End\r\n",
                          session->filepos);
        return;
    }

    if (strlen(args) == 0)
    {
        /* no argument provided, send the server status */
        ftp_send_response(session, -211, "FTP server status\r\n"
                                         " Uptime: %02d:%02d:%02d\r\n"
                                         "211 End\r\n",
                          hours, minutes, seconds);
        return;
    }

    /* argument provided, open the path in STAT mode */
    ftp_xfer_dir(session, args, XFER_DIR_STAT, false);
}

/*! @fn static void STOR(ftp_session_t *session, const char *args)
 *
 *  @brief store a file
 *
 *  @note Requires a PASV or PORT connection
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(STOR)
{
    TRACE_ARGS();

    if (!is_session_authenticated(session))
        return;

    /* open the file to store */
    return ftp_xfer_file(session, args, XFER_FILE_STOR);
}

/*! @fn static void STOU(ftp_session_t *session, const char *args)
 *
 *  @brief store a unique file
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(STOU)
{
    TRACE_ARGS();

    /* we do not support this yet */
    ftp_session_set_state(session, COMMAND_STATE, 0);
    ftp_send_response(session, 502, "unavailable\r\n");
}

/*! @fn static void STRU(ftp_session_t *session, const char *args)
 *
 *  @brief set file structure
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(STRU)
{
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* we only support F (no structure) mode */
    if (strcasecmp(args, "F") == 0)
    {
        ftp_send_response(session, 200, "OK\r\n");
        return;
    }

    ftp_send_response(session, 504, "unavailable\r\n");
}

/*! @fn static void SYST(ftp_session_t *session, const char *args)
 *
 *  @brief identify system
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(SYST)
{
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* we are UNIX compliant with 8-bit characters */
    ftp_send_response(session, 215, "UNIX Type: L8\r\n");
}

/*! @fn static void TYPE(ftp_session_t *session, const char *args)
 *
 *  @brief set transfer mode
 *
 *  @note transfer mode is always binary
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(TYPE)
{
    TRACE_ARGS();
    ftp_session_set_state(session, COMMAND_STATE, 0);

    /* we always transfer in binary mode */
    ftp_send_response(session, 200, "OK\r\n");
}

/*! @fn static void USER(ftp_session_t *session, const char *args)
 *
 *  @brief provide user name
 *
 *  @param[in] session ftp session
 *  @param[in] args    username
 */
FTP_DECLARE(USER)
{
    TRACE_ARGS();
    char str_anony[2];
    ini_gets("Anonymous", "anonymous:", "0", str_anony, sizearray(str_anony), CONFIGPATH);
    if (*str_anony == '1')
    {
        session->user_ok = true;
        session->pass_ok = true;
        ftp_send_response(session, 230, "OK\r\n");
        if (session->led)
            flash_led_connect();
        return;
    }

    // reset authentication state
    session->user_ok = false;
    session->pass_ok = false;
    char str_user[64];
    ini_gets("User", "user:", "dummy", str_user, sizearray(str_user), CONFIGPATH);
    if (*str_user == '\0')
    {
        user_pass_not_set(session);
        return;
    }
    if (strcmp(str_user, args) == 0)
    {
        // username is ok, wait for the password
        session->user_ok = true;
    }
    ftp_send_response(session, 331, "Password required\r\n");
}

/*! @fn static void PASS(ftp_session_t *session, const char *args)
 *
 *  @brief provide password
 *
 *  @param[in] session ftp session
 *  @param[in] args    arguments
 */
FTP_DECLARE(PASS)
{
    TRACE_ARGS();
    char str_anony[2];
    ini_gets("Anonymous", "anonymous:", "0", str_anony, sizearray(str_anony), CONFIGPATH);
    if (*str_anony == '1')
    {
        session->user_ok = true;
        session->pass_ok = true;
        ftp_send_response(session, 230, "OK\r\n");
        if (session->led)
            flash_led_connect();
        return;
    }

    // reset authentication state
    session->pass_ok = false;
    char str_pass[64];
    ini_gets("Password", "password:", "dummy", str_pass, sizearray(str_pass), CONFIGPATH);
    if (*str_pass == '\0')
    {
        user_pass_not_set(session);
        return;
    }
    if (strcmp(str_pass, args) == 0)
    {
        // password is ok
        session->pass_ok = true;
    }

    // check username and password state
    if (is_session_authenticated(session))
    {
        ftp_session_set_state(session, COMMAND_STATE, 0);
        ftp_send_response(session, 230, "OK\r\n");
        if (session->led)
            flash_led_connect();
    }
}

/*! get the LED setting for connections from the ini file
 *
 *  @returns true if LED should light up on connection, false if not
 */
bool get_session_led_setting()
{
    char str_led[2];
    ini_gets("LED", "led:", "1", str_led, sizearray(str_led), CONFIGPATH);
    return *str_led == '1';
}

/*! check the session authentication and send out an error if not completely authenticated.
 *
 *  @returns true if authentication is ok, false if not
 */
bool is_session_authenticated(ftp_session_t* session)
{
    if (session->user_ok && session->pass_ok)
        return true;

    TRACE();
    console_print(RED "command denied, not authenticated\n" RESET);
    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
    ftp_send_response(session, 430, "Unknown user or password, please check /config/sys-ftpd/config.ini\r\n");
    ftp_session_close_cmd(session);
    return false;
}

void user_pass_not_set(ftp_session_t* session)
{
    ftp_session_set_state(session, COMMAND_STATE, CLOSE_PASV | CLOSE_DATA);
    ftp_send_response(session, 430, "User or password are not set. They must be set in /config/sys-ftpd/config.ini\r\n");
    ftp_session_close_cmd(session);
}
