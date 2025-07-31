#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#define VERSION_STR "1.0"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>

// See 'man clock_gettime'
#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)   ((~(clockid_t) (fd) << 3) | CLOCKFD)
#define CLOCKID_TO_FD(clk)  ((unsigned int) ~((clk) >> 3))

// Print every PRINT_FREQ packet
#define PRINT_FREQ 100

#define BUF_SIZE 64
unsigned char buf[BUF_SIZE];

struct Settings {
    char* ptp_device;
    char* stream_address;
    int stream_port;
    int sample_rate;
    int max_latency;
} settings;

#define HISTOGRAM_BOXES 11
#define HISTOGRAM_WIDTH 40
long histogram[HISTOGRAM_BOXES];
long histogram_scale = 0;

uint32_t recvr_timestamp = 0;
uint32_t sender_timestamp = 0;

double latency = 0; // in usec
double peak_latency = 0; // in usec

long packet_count = 0;
long late_packets = 0;

void print_help_and_exit() {
    printf(
        "AES67 Network Latency Analyzer v" VERSION_STR "\n\n"
        "Measures the difference between the RTP timestamps and the current PTP time.\n"
        "The computer running this software and the AES67 sender must be synchronized\n"
        "to the same PTP grandmaster clock.\n\n"
        "If no PTP device is specified, the latency is instead calculated as the\n"
        "time between packets. No PTP synchronization is required in this case.\n\n"
        "Options:\n"
        "  -d [PTP device]                (e.g., /dev/ptp0)\n"
        "  -a [Multicast stream address]  (e.g., 239.69.1.2)\n"
        "  -p [Stream port]               (default 5004)\n"
        "  -r [Sample rate]               (default 48000)\n"
        "  -s [Max acceptable latency]    (default 2 ms)\n"
    );
    exit(0);
}

void parse_args(int argc, char* argv[]) {
    settings.ptp_device = NULL;
    settings.stream_address = NULL;
    settings.stream_port = 5004;
    settings.sample_rate = 48000;
    settings.max_latency = 2000;

    char c;
    while ((c = getopt(argc, argv, ":d:a:p:r:s:h")) != -1) {
        switch (c) {
            case 'd':
                settings.ptp_device = optarg;
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
    printf("AES67 Network Latency Analyzer v" VERSION_STR "\n\n");
    printf("Stream: %s:%d\n", settings.stream_address, settings.stream_port);
    printf("Sample rate: %d Hz\n", settings.sample_rate);
    printf("PTP device: %s\n", settings.ptp_device != NULL ? settings.ptp_device : "None");
    printf("Setting: %d usec\n\n", settings.max_latency);
}

void update_histogram() {
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
        putchar('\n');
    }
}

void print_vars() {
    printf("\nReceiver timestamp: %u\n", recvr_timestamp);
    printf("Sender timestamp: %u\n", sender_timestamp);
    printf("Peak latency: %f usec\n", peak_latency);
    printf("Packets: %ld\n", packet_count);
    printf("Late packets: %ld\n", late_packets);
}

int open_socket(struct sockaddr_in* addr) {
    struct ip_mreq mreq;
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Could not create socket");
        return -1;
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(fd);
        return -1;
    }

    memset((char *)addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
    addr->sin_port = htons(settings.stream_port);

    if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
        perror("Socket bind failed");
        close(fd);
        return -1;
    }

    mreq.imr_multiaddr.s_addr = inet_addr(settings.stream_address);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP");
        close(fd);
        return -1;
    }
    return fd;
}

void update_latency() {
    latency = (double)(recvr_timestamp - sender_timestamp) / (double)settings.sample_rate * 1e6;
    if (latency > settings.max_latency) {
        late_packets++;
    }
    if (latency > peak_latency) {
        peak_latency = latency;
    }
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL); // Disable buffering to avoid flickering
    parse_args(argc, argv);

    int clk_fd = -1;
    clockid_t clk_id = CLOCK_MONOTONIC;
    
    if (settings.ptp_device != NULL) {
        clk_fd = open(settings.ptp_device, O_RDONLY);

        if (clk_fd < 0) {
            perror("Could not open PTP device");
            return 1;
        }
        clk_id = FD_TO_CLOCKID(clk_fd);
    }

    struct sockaddr_in addr;
    unsigned int addrlen = sizeof(addr);
    int sock_fd = open_socket(&addr);

    if (sock_fd < 0) {
        return 1;
    }

    int print_timer = 0;
    bool first_run = true;

    printf("Waiting for first packet(s)...\n");

    for (;;) {
        int recvd = recvfrom(sock_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&addr, &addrlen);

        if (recvd < BUF_SIZE)
            continue;

        struct timespec ts;

        if (clock_gettime(clk_id, &ts) == -1) {
            perror("clock_gettime");
            return 1;
        }
        uint32_t prev_recvr_timestamp = recvr_timestamp;

        // RTP timestamp "unit" is 1/sample_rate seconds
        recvr_timestamp = (ts.tv_sec + ts.tv_nsec / 1e9) * settings.sample_rate;
        
        if (settings.ptp_device != NULL) {
            sender_timestamp = ntohl(*(uint32_t*)(buf + 4)); // Get timestamp from RTP header
        } else {
            sender_timestamp = first_run ? recvr_timestamp : prev_recvr_timestamp;
        }

        packet_count++;
        update_latency();
        update_histogram();

        if (++print_timer == PRINT_FREQ) {
            print_headers();
            print_histogram();
            print_vars();
            print_timer = 0;
        }
        first_run = false;
    }
    return 0;
}
