#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#define VERSION_STR "2.0"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>
#include <errno.h>
#include <sys/ioctl.h>

// See 'man clock_gettime'
#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)   ((~(clockid_t) (fd) << 3) | CLOCKFD)
#define CLOCKID_TO_FD(clk)  ((unsigned int) ~((clk) >> 3))

#define RTP_BUF_SIZE 64 // 64 bytes is enough to get timestamp

// Print every PRINT_FREQ packet
#define PRINT_FREQ 100

struct Settings {
    char* ifname;
    char* stream_address;
    int stream_port;
    int sample_rate;
    int max_latency;
} settings;

#define HISTOGRAM_BOXES 11
#define HISTOGRAM_WIDTH 40
unsigned long histogram[HISTOGRAM_BOXES];
unsigned long histogram_scale = 0;

uint32_t recvr_timestamp = 0;
uint32_t sender_timestamp = 0;

double latency = 0; // in usec
double peak_latency = 0; // in usec

long packet_count = 0;
long late_packets = 0;
long early_packets = 0;

void print_help_and_exit() {
    printf(
        "AES67 Latency Analyzer v" VERSION_STR "\n\n"
        "Measures the difference between the RTP timestamps and the packet arrival times.\n"
        "The computer running this software and the AES67 sender must be synchronized\n"
        "to the same PTP grandmaster clock.\n\n"
        "Note that SO_TIMESTAMPING requires root privileges.\n\n"
        "Options:\n"
        "  -i [Network interface]         (e.g., enp86s0)\n"
        "  -a [Multicast stream address]  (e.g., 239.69.1.2)\n"
        "  -p [Stream port]               (default 5004)\n"
        "  -r [Sample rate]               (default 48000)\n"
        "  -s [Max acceptable latency]    (default 2 ms)\n"
    );
    exit(0);
}

void parse_args(int argc, char* argv[]) {
    settings.ifname = NULL;
    settings.stream_address = NULL;
    settings.stream_port = 5004;
    settings.sample_rate = 48000;
    settings.max_latency = 2000;

    char c;
    while ((c = getopt(argc, argv, ":i:a:p:r:s:h")) != -1) {
        switch (c) {
            case 'i':
                settings.ifname = optarg;
                break;
            case 'a':
                settings.stream_address = optarg;
                break;
            case 'p':
                settings.stream_port = atoi(optarg);
                break;
            case 'r':
                settings.sample_rate = atoi(optarg);
                break;
            case 's':
                settings.max_latency = atoi(optarg);
                break;
            // TODO: Add optional time offset setting.
            case 'h':
                print_help_and_exit();
                break;
            case ':':
                printf("Missing option: -%c\n", optopt);
                exit(1);
                break;
            case '?':
                fprintf(stderr, "Unknown option: -%c\n", optopt);
                exit(1);
                break;
        }
    }
    if (settings.ifname == NULL) {
        fprintf(stderr, "No interface name (-i) specified\n");
        exit(1);
    }
    if (settings.stream_address == NULL) {
        fprintf(stderr, "No stream address (-a) specified\n");
        exit(1);
    }
    if (settings.sample_rate <= 0) {
        fprintf(stderr, "Invalid sample rate\n");
        exit(1);
    }
    if (settings.max_latency <= 0) {
        fprintf(stderr, "Invalid max latency\n");
        exit(1);
    }
}

void print_headers() {
    printf("\033[H\033[J");
    printf("AES67 Latency Analyzer v" VERSION_STR "\n\n");
    printf("Stream: %s:%d\n", settings.stream_address, settings.stream_port);
    printf("Sample rate: %d Hz\n", settings.sample_rate);
    printf("Interface: %s\n", settings.ifname);
    printf("Setting: %d usec\n\n", settings.max_latency);
}

void update_histogram() {
    if (latency < 0) {
        return;
    }
    if (latency >= settings.max_latency) {
        if (++histogram[HISTOGRAM_BOXES - 1] > histogram_scale) {
            histogram_scale++;
        }
    } else {
        int box = (latency / settings.max_latency) * (HISTOGRAM_BOXES - 1);

        if (++histogram[box] > histogram_scale) {
            histogram_scale++;
        }
    }
}

void print_histogram() {
    int size;
    double step_size = settings.max_latency / (HISTOGRAM_BOXES - 1);

    for (int i = 0; i < HISTOGRAM_BOXES; ++i) {
        size = ((double)histogram[i] / (double)histogram_scale) * HISTOGRAM_WIDTH;
        if (i == HISTOGRAM_BOXES - 1) {
            printf("      > %5d usec: ", settings.max_latency);
        } else {
            printf("%5d - %5d usec: ", (int)(step_size * i), (int)(step_size * (i + 1) - 1));
        }
        while (size-- > 0) {
            putchar('=');
        }
        printf(" %lu", histogram[i]);
        putchar('\n');
    }
}

void print_vars() {
    printf("\nReceiver timestamp: %u\n", recvr_timestamp);
    printf("Sender timestamp: %u\n", sender_timestamp);
    printf("Peak latency: %f usec\n", peak_latency);
    printf("Packets: %ld\n", packet_count);
    printf("Late packets: %ld\n", late_packets);
    printf("Early packets: %ld\n", early_packets);
}

int open_socket() {
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Could not create socket");
        return -1;
    }

    // Enable SO_REUSEADDR on the socket
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("Could not set SO_REUSEADDR");
        close(fd);
        return -1;
    }

    // Enable RX hardware timestamping
    struct ifreq ifr;
    struct hwtstamp_config hwts_config;
    memset(&hwts_config, 0, sizeof(hwts_config));
    hwts_config.tx_type = HWTSTAMP_TX_OFF;
    hwts_config.rx_filter = HWTSTAMP_FILTER_ALL;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", settings.ifname);
    ifr.ifr_data = (void *)&hwts_config;
    if (ioctl(fd, SIOCSHWTSTAMP, &ifr) == -1) {
        perror("Could not enable hardware timestamping");
        close(fd);
        return -1;
    }

    // Bind socket to configured 
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(settings.stream_port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Socket bind failed");
        close(fd);
        return -1;
    }

    // Enable timestamp reporting
    int reporting = SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &reporting, sizeof(reporting)) == -1) {
        perror("Could not enable timestamp reporting");
        close(fd);
        return -1;
    }

    // Join multicast
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(settings.stream_address);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
        perror("Could not join multicast");
        close(fd);
        return -1;
    }
    return fd;
}

void update_latency() {
    latency = (double)((int32_t)recvr_timestamp - (int32_t)sender_timestamp) / (double)settings.sample_rate * 1e6;
    if (latency > settings.max_latency) {
        late_packets++;
    } else if (latency < 0) {
        early_packets++;
    }
    if (latency > peak_latency) {
        peak_latency = latency;
    }
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL); // Disable buffering to avoid flickering
    parse_args(argc, argv);

    int sock_fd = open_socket();

    if (sock_fd < 0) {
        return 1;
    }

    char data[RTP_BUF_SIZE], ctrl[4096];
    struct msghdr hdr;
    struct iovec iov;
    struct cmsghdr *cmsg;

    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl;
    hdr.msg_controllen = sizeof(ctrl);
    iov.iov_base = data;
    iov.iov_len = sizeof(data);

    int print_timer = 0;

    printf("Waiting for first packet(s)...\n");

    for (;;) {
        int recvd = recvmsg(sock_fd, &hdr, 0);

        if (recvd < RTP_BUF_SIZE) // Not enough data to get RTP timestamp
            continue;

        // Timestamp is found in control message
        for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) {
                struct timespec *ts = (struct timespec *)CMSG_DATA(cmsg);
                // RTP timestamp "unit" is 1/sample_rate seconds
                recvr_timestamp = (ts[2].tv_sec + ts[2].tv_nsec / 1e9) * settings.sample_rate;
            }
        }

        // Get timestamp from RTP header
        sender_timestamp = ntohl(*(uint32_t*)(data + 4));

        packet_count++;
        update_latency();
        update_histogram();

        if (++print_timer == PRINT_FREQ) {
            print_headers();
            print_histogram();
            print_vars();
            print_timer = 0;
        }
    }
    return 0;
}
