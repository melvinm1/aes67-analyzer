#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#define VERSION_STR "2.2"

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

#define HISTOGRAM_BOXES 11
#define HISTOGRAM_WIDTH 40

#define DEFAULT_PORT 5004
#define DEFAULT_SAMPLE_RATE 48000
#define DEFAULT_LATENCY 2000
#define DEFAULT_PTIME 1000
#define DEFAULT_BUFFER_SIZE 144

struct state {
    uint32_t prev_recvr_ts; // in 1/sample_rate sec
    uint32_t recvr_ts; // in 1/sample_rate sec
    uint32_t sender_ts; // in 1/sample_rate sec

    double latency; // in usec
    double peak_latency; // in usec

    long packet_count;
    long late_packets;
    long early_packets;

    unsigned long histogram[HISTOGRAM_BOXES];
    unsigned long histogram_scale;
    
    struct playback {
        bool started;
        bool has_start_ts;

        // Timestamp when playback should be started
        uint32_t start_ts;

        // Number of buffered samples
        int buffer;

        // Number of underflows/overflows
        long underflows;
        long overflows;
    } playback;

    struct settings {
        char* ifname;
        char* stream_address;
        int stream_port;
        int sample_rate;
        int ptime;
        int max_latency;
        int buffer_size;
    } settings;
};

void init_state(struct state* state) {
    state->prev_recvr_ts = 0;
    state->recvr_ts = 0;
    state->sender_ts = 0;
    
    state->latency = 0;
    state->peak_latency = 0;

    state->packet_count = 0;
    state->late_packets = 0;
    state->early_packets = 0;

    memset(&state->histogram, 0, sizeof(state->histogram));
    state->histogram_scale = 1;

    state->playback.started = false;
    state->playback.has_start_ts = false;
    state->playback.start_ts = 0;
    state->playback.buffer = 0;
    state->playback.underflows = 0;
    state->playback.overflows = 0;

    state->settings.ifname = NULL;
    state->settings.stream_address = NULL;
    state->settings.stream_port = DEFAULT_PORT;
    state->settings.sample_rate = DEFAULT_SAMPLE_RATE;
    state->settings.ptime = DEFAULT_PTIME;
    state->settings.max_latency = DEFAULT_LATENCY;
    state->settings.buffer_size = DEFAULT_BUFFER_SIZE;
};

void print_help_and_exit() {
    printf(
        "AES67 Latency Analyzer v" VERSION_STR "\n\n"
        "Measures the difference between the RTP timestamps and the packet arrival times.\n"
        "Also simulates playback to detect buffer underflows/overflows.\n\n"
        "Note: The computer running this software and the AES67 sender must be synchronized\n"
        "to the same PTP grandmaster clock.\n\n"
        "Note: SO_TIMESTAMPING requires root privileges.\n\n"
        "Options:\n"
        "  -i [Network interface]         (e.g., enp86s0)\n"
        "  -a [Multicast stream address]  (e.g., 239.69.1.2)\n"
        "  -p [Stream port]               (default 5004)\n"
        "  -r [Sample rate (Hz)]          (default 48000 Hz)\n"
        "  -t [Packet time (usec)]        (default 1000 usec)\n"
        "  -s [Latency (usec)]            (default 2000 usec)\n"
        "  -b [Buffer size (samples)]     (default 144 samples)\n"
    );
    exit(0);
}

void parse_args(int argc, char* argv[], struct settings* settings) {
    char c;
    while ((c = getopt(argc, argv, ":i:a:p:r:t:s:b:h")) != -1) {
        switch (c) {
            case 'i':
                settings->ifname = optarg;
                break;
            case 'a':
                settings->stream_address = optarg;
                break;
            case 'p':
                settings->stream_port = atoi(optarg);
                break;
            case 'r':
                settings->sample_rate = atoi(optarg);
                break;
            case 't':
                settings->ptime = atoi(optarg);
                break;
            case 's':
                settings->max_latency = atoi(optarg);
                break;
            // TODO: Add optional time offset setting.
            case 'h':
                print_help_and_exit();
                break;
            case 'b':
                settings->buffer_size = atoi(optarg);
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
    if (settings->ifname == NULL) {
        fprintf(stderr, "No interface name (-i) specified\n");
        exit(1);
    }
    if (settings->stream_address == NULL) {
        fprintf(stderr, "No stream address (-a) specified\n");
        exit(1);
    }
    if (settings->sample_rate <= 0) {
        fprintf(stderr, "Invalid sample rate\n");
        exit(1);
    }
    if (settings->max_latency <= 0) {
        fprintf(stderr, "Invalid max latency\n");
        exit(1);
    }
    if (settings->buffer_size <= 0) {
        fprintf(stderr, "Invalid buffer size\n");
        exit(1);
    }
    if (settings->ptime <= 0) {
        fprintf(stderr, "Invalid packet time\n");
        exit(1);
    }
}

int open_socket(struct settings* settings) {
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

    // Bind to selected interface
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, settings->ifname, strlen(settings->ifname)) < 0) {
        perror("Could not bind socket to interface");
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
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", settings->ifname);
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
    addr.sin_port = htons(settings->stream_port);
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

    // Enable multicast address reporting
    int addr_report = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &addr_report, sizeof(addr_report)) == -1) {
        perror("Could not enable multicast address reporting");
        close(fd);
        return -1;
    }

    // Join multicast
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(settings->stream_address);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
        perror("Could not join multicast");
        close(fd);
        return -1;
    }
    return fd;
}

void update_latency(struct state* state) {
    state->latency = ((int64_t)state->recvr_ts - (int64_t)state->sender_ts) / (double)state->settings.sample_rate * 1e6;
    if (state->latency > state->settings.max_latency) {
        state->late_packets++;
    } else if (state->latency < 0) {
        state->early_packets++;
    }
    if (state->latency > state->peak_latency) {
        state->peak_latency = state->latency;
    }
}

void update_histogram(struct state* state) {
    if (state->latency < 0) {
        return;
    }
    if (state->latency >= state->settings.max_latency) {
        if (++state->histogram[HISTOGRAM_BOXES - 1] > state->histogram_scale) {
            state->histogram_scale++;
        }
    } else {
        int box = (state->latency / state->settings.max_latency) * (HISTOGRAM_BOXES - 1);

        if (++state->histogram[box] > state->histogram_scale) {
            state->histogram_scale++;
        }
    }
}

void update_playback(struct state* state) {
    int samples_to_add = state->settings.sample_rate * (state->settings.ptime / 1e6); // = psamples
    int samples_to_remove = 0;

    if (!state->playback.started) {
        if (!state->playback.has_start_ts) {
            state->playback.start_ts = state->sender_ts + state->settings.sample_rate * (state->settings.max_latency / 1e6);
            state->playback.has_start_ts = true;
        }
        if ((int32_t)(state->recvr_ts - state->playback.start_ts) >= 0) { // recvr_ts > start_ts ?
            samples_to_remove = state->recvr_ts - state->playback.start_ts;
            state->playback.started = true;
        }
    } else {
        samples_to_remove = state->recvr_ts - state->prev_recvr_ts;
    }

    state->playback.buffer -= samples_to_remove;
    if (state->playback.buffer < 0) {
        state->playback.underflows++; // We got an underflow 
        state->playback.buffer = 0;

        state->playback.started = false; // Resync playback
        state->playback.start_ts = state->sender_ts + state->settings.sample_rate * (state->settings.max_latency / 1e6);
    }

   state->playback.buffer += samples_to_add;
    if (state->playback.buffer > state->settings.buffer_size) {
        state->playback.overflows++; // We got an overflow
        state->playback.buffer = state->settings.buffer_size;
        // Resync?
    }
}

void print_headers(struct state* state) {
    printf("\033[H\033[J");
    printf("AES67 Latency Analyzer v" VERSION_STR "\n\n");
    printf("Stream: %s:%d\n", state->settings.stream_address, state->settings.stream_port);
    printf("Sample rate: %d Hz Packet time: %d usec\n", state->settings.sample_rate, state->settings.ptime);
    printf("Latency setting: %d usec Buffer size: %d samples\n", state->settings.max_latency, state->settings.buffer_size);
    printf("Interface: %s\n\n", state->settings.ifname);
}

void print_histogram(struct state* state) {
    double step_size = state->settings.max_latency / (HISTOGRAM_BOXES - 1);

    for (int i = 0; i < HISTOGRAM_BOXES; ++i) {
        int size = ((double)state->histogram[i] / (double)state->histogram_scale) * HISTOGRAM_WIDTH;

        if (i == HISTOGRAM_BOXES - 1) {
            printf("      > %5d usec: ", state->settings.max_latency);
        } else {
            printf("%5d - %5d usec: ", (int)(step_size * i), (int)(step_size * (i + 1) - 1));
        }
        while (size-- > 0) {
            putchar('=');
        }
        printf(" %lu", state->histogram[i]);
        putchar('\n');
    }
}

void print_vars(struct state* state) {
    printf("\nPeak latency: %f usec\n", state->peak_latency);
    printf("Receiver ts: %u Sender ts: %u\n", state->recvr_ts, state->sender_ts);
    printf("Packets: %ld Late packets: %ld Early packets: %ld\n", state->packet_count, state->late_packets, state->early_packets);
    printf("Playback underflows: %ld Playback overflows: %ld\n", state->playback.underflows, state->playback.overflows);
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL); // Disable buffering to avoid flickering

    struct state state;
    init_state(&state);
    parse_args(argc, argv, &state.settings);

    int sock_fd = open_socket(&state.settings);
    if (sock_fd < 0) {
        return 1;
    }

    char data[RTP_BUF_SIZE], ctrl[4096];
    char src_addr[INET_ADDRSTRLEN];
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

    bool first_run = true;
    int print_timer = 0;

    printf("Waiting for first packet(s)...\n");

    for (;;) {
        int recvd = recvmsg(sock_fd, &hdr, 0);

        if (recvd < RTP_BUF_SIZE) // Not enough data to get RTP timestamp
            continue;

        uint32_t new_recvr_ts = 0;

        for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) {
                struct timespec *ts = (struct timespec *)CMSG_DATA(cmsg);

                // Found receiver timestamp
                new_recvr_ts = (ts[2].tv_sec + ts[2].tv_nsec / 1e9) * state.settings.sample_rate;

            } else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

                // Found multicast address
                inet_ntop(AF_INET, &pktinfo->ipi_addr, src_addr, sizeof(src_addr));
            }
        }

        // Ignore packets not going to settings.stream_address
        if (strcmp(src_addr, state.settings.stream_address))
            continue;

        if (first_run) {
            state.prev_recvr_ts = new_recvr_ts;
            first_run = false;
        } else {
            state.prev_recvr_ts = state.recvr_ts;
        }
        state.recvr_ts = new_recvr_ts;

        // Get timestamp from RTP header
        state.sender_ts = ntohl(*(uint32_t*)(data + 4));

        state.packet_count++;
        update_latency(&state);
        update_histogram(&state);
        update_playback(&state);

        if (++print_timer == PRINT_FREQ) {
            print_headers(&state);
            print_histogram(&state);
            print_vars(&state);
            print_timer = 0;
        }
    }
    return 0;
}
