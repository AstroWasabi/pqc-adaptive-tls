/* c_dispatch/src/telemetry.c
 * Phase 1: Boot-Time Hardware Profiler
 *
 * Runs exactly once at application startup.
 * Detects hypervisor via /sys/class/dmi/id/sys_vendor (DMI) with fallback
 * to /proc/cpuinfo 'hypervisor' flag.  Counts logical cores via sysconf.
 * Exports state to host_profile.json using plain fprintf (no cJSON).
 */

#include "../include/telemetry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * Singleton storage
 * ----------------------------------------------------------------------- */

static HostProfile g_host_profile;
static int         g_initialized = 0;

/* -----------------------------------------------------------------------
 * Known hypervisor vendor strings
 * Matched case-insensitively against /sys/class/dmi/id/sys_vendor
 * ----------------------------------------------------------------------- */

static const char *VM_VENDORS[] = {
    "QEMU",
    "Amazon EC2",
    "Microsoft Corporation",
    "VMware",
    "Xen",
    "Google",
    "KVM",
    "innotek GmbH",          /* VirtualBox */
    "Parallels",
    "DigitalOcean",
    "Alibaba Cloud",
    "Hetzner",
    NULL
};

/* -----------------------------------------------------------------------
 * Hypervisor detection
 * ----------------------------------------------------------------------- */

static int detect_hypervisor(char *vendor_buf, size_t buf_len)
{
    /*
     * Primary: read the DMI sys_vendor string.
     * This is the canonical way to detect virtualisation on Linux
     * without requiring root-only CPUID leaf 0x40000000 decoding.
     */
    FILE *fp = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (fp) {
        if (fgets(vendor_buf, (int)buf_len, fp)) {
            /* Strip trailing newline */
            size_t len = strlen(vendor_buf);
            if (len > 0 && vendor_buf[len - 1] == '\n')
                vendor_buf[len - 1] = '\0';
        } else {
            snprintf(vendor_buf, buf_len, "Unknown");
        }
        fclose(fp);

        /* Match against known hypervisor vendors */
        for (int i = 0; VM_VENDORS[i] != NULL; i++) {
            if (strcasestr(vendor_buf, VM_VENDORS[i]))
                return 1;
        }
        return 0;
    }

    /*
     * Fallback: scan /proc/cpuinfo for the 'hypervisor' CPU flag.
     * This flag is set by the hypervisor itself via CPUID and is
     * readable without elevated privileges.
     */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "flags") && strstr(line, "hypervisor")) {
                fclose(fp);
                snprintf(vendor_buf, buf_len,
                         "Unknown Hypervisor (cpuinfo flag)");
                return 1;
            }
        }
        fclose(fp);
    }

    snprintf(vendor_buf, buf_len, "Bare Metal (DMI unavailable)");
    return 0;
}

#include <pthread.h>
#include <sched.h>
#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

/* -----------------------------------------------------------------------
 * CPU Feature Probing (CPUID)
 * ----------------------------------------------------------------------- */

static void detect_cpu_features(int *has_avx2, int *has_avx512)
{
    *has_avx2 = 0;
    *has_avx512 = 0;
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if ((ecx & (1 << 27)) && (ecx & (1 << 28))) { /* OSXSAVE and AVX */
            if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                if (ebx & (1 << 5))  *has_avx2 = 1;
                if (ebx & (1 << 16)) *has_avx512 = 1;
            }
        }
    }
#endif
}

/* -----------------------------------------------------------------------
 * Physical core count detection via /proc/cpuinfo
 * ----------------------------------------------------------------------- */

static int detect_physical_cores(int logical_cores)
{
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return logical_cores;

    char line[256];
    int cores_per_socket = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "cpu cores", 9) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                cores_per_socket = atoi(colon + 1);
                break;
            }
        }
    }
    fclose(fp);

    if (cores_per_socket > 0 && cores_per_socket <= logical_cores)
        return cores_per_socket;
    return logical_cores;
}

/* -----------------------------------------------------------------------
 * Boot-Time Inter-Thread Condvar Wake-Up Latency Calibration
 * ----------------------------------------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond_to_worker;
    pthread_cond_t  cond_to_main;
    int             step;
    int             stop;
} CalibPingPong;

static void *calib_worker(void *arg)
{
    CalibPingPong *p = (CalibPingPong *)arg;
    int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus >= 2) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    while (1) {
        pthread_mutex_lock(&p->mutex);
        while (p->step == 0 && !p->stop) {
            pthread_cond_wait(&p->cond_to_worker, &p->mutex);
        }
        if (p->stop) {
            pthread_mutex_unlock(&p->mutex);
            break;
        }
        p->step = 0;
        pthread_cond_signal(&p->cond_to_main);
        pthread_mutex_unlock(&p->mutex);
    }
    return NULL;
}

static uint64_t calibrate_inter_thread_sync(void)
{
    int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus < 2) return 50000; /* Nominal 50 us on single core */

    CalibPingPong p;
    memset(&p, 0, sizeof(p));
    pthread_mutex_init(&p.mutex, NULL);
    pthread_cond_init(&p.cond_to_worker, NULL);
    pthread_cond_init(&p.cond_to_main, NULL);
    p.step = 0;
    p.stop = 0;

    pthread_t th;
    if (pthread_create(&th, NULL, calib_worker, &p) != 0) {
        pthread_mutex_destroy(&p.mutex);
        pthread_cond_destroy(&p.cond_to_worker);
        pthread_cond_destroy(&p.cond_to_main);
        return 35000;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    /* Brief warmup */
    usleep(2000);

    const int ROUNDS = 25;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&p.mutex);
        p.step = 1;
        pthread_cond_signal(&p.cond_to_worker);
        while (p.step == 1) {
            pthread_cond_wait(&p.cond_to_main, &p.mutex);
        }
        pthread_mutex_unlock(&p.mutex);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);

    pthread_mutex_lock(&p.mutex);
    p.stop = 1;
    pthread_cond_signal(&p.cond_to_worker);
    pthread_mutex_unlock(&p.mutex);
    pthread_join(th, NULL);

    pthread_mutex_destroy(&p.mutex);
    pthread_cond_destroy(&p.cond_to_worker);
    pthread_cond_destroy(&p.cond_to_main);

    uint64_t diff_ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL +
                       (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    return diff_ns / (uint64_t)ROUNDS;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

void telemetry_refresh_dynamic(void)
{
    if (!g_initialized) return;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    /* Rate-limit sampling to once every 100 ms (100,000,000 ns) */
    if (g_host_profile.last_sample_time_ns != 0 &&
        (now_ns - g_host_profile.last_sample_time_ns) < 100000000ULL) {
        return;
    }

    double load[3];
    if (getloadavg(load, 3) > 0) {
        g_host_profile.load_1min = load[0];
        g_host_profile.load_per_core = load[0] / (double)g_host_profile.logical_cores;
        /* Congested if system run-queue load exceeds 80% capacity per core */
        g_host_profile.is_congested = (g_host_profile.load_per_core >= 0.80);
    } else {
        g_host_profile.load_1min = 0.0;
        g_host_profile.load_per_core = 0.0;
        g_host_profile.is_congested = 0;
    }

    g_host_profile.last_sample_time_ns = now_ns;
}

int host_profile_init(void)
{
    if (g_initialized)
        return 0;   /* Idempotent — run exactly once */

    memset(&g_host_profile, 0, sizeof(g_host_profile));

    /* ── Hostname ── */
    if (gethostname(g_host_profile.hostname,
                    sizeof(g_host_profile.hostname)) != 0)
        snprintf(g_host_profile.hostname,
                 sizeof(g_host_profile.hostname), "unknown");

    /* ── Hypervisor Detection ── */
    g_host_profile.is_virtualized = detect_hypervisor(
        g_host_profile.sys_vendor, sizeof(g_host_profile.sys_vendor));

    /* ── Logical & Physical Core Count ── */
    g_host_profile.logical_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (g_host_profile.logical_cores < 1)
        g_host_profile.logical_cores = 1;
    g_host_profile.physical_cores = detect_physical_cores(g_host_profile.logical_cores);

    /* ── CPU Features ── */
    detect_cpu_features(&g_host_profile.has_avx2, &g_host_profile.has_avx512);

    /* ── Inter-Thread Sync Overhead Calibration ── */
    g_host_profile.sync_overhead_ns = calibrate_inter_thread_sync();

    /* ── Initial Dynamic Sample ── */
    g_initialized = 1;
    telemetry_refresh_dynamic();

    /* ── Boot Timestamp (ISO 8601) ── */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(g_host_profile.boot_timestamp,
             sizeof(g_host_profile.boot_timestamp),
             "%Y-%m-%dT%H:%M:%S%z", tm_info);

    return 0;
}

const HostProfile *get_host_profile(void)
{
    return &g_host_profile;
}

int host_profile_export_json(const char *filepath)
{
    if (!g_initialized)
        return -1;

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("host_profile_export_json: fopen");
        return -1;
    }

    /* Refresh before export */
    telemetry_refresh_dynamic();

    /*
     * Hand-formatted JSON via fprintf — no external JSON library.
     * All string values are assumed safe (no user-controlled escaping needed).
     */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"hostname\": \"%s\",\n",
            g_host_profile.hostname);
    fprintf(fp, "  \"sys_vendor\": \"%s\",\n",
            g_host_profile.sys_vendor);
    fprintf(fp, "  \"is_virtualized\": %s,\n",
            g_host_profile.is_virtualized ? "true" : "false");
    fprintf(fp, "  \"logical_cores\": %d,\n",
            g_host_profile.logical_cores);
    fprintf(fp, "  \"physical_cores\": %d,\n",
            g_host_profile.physical_cores);
    fprintf(fp, "  \"has_avx2\": %s,\n",
            g_host_profile.has_avx2 ? "true" : "false");
    fprintf(fp, "  \"has_avx512\": %s,\n",
            g_host_profile.has_avx512 ? "true" : "false");
    fprintf(fp, "  \"sync_overhead_ns\": %llu,\n",
            (unsigned long long)g_host_profile.sync_overhead_ns);
    fprintf(fp, "  \"load_1min\": %.2f,\n",
            g_host_profile.load_1min);
    fprintf(fp, "  \"load_per_core\": %.2f,\n",
            g_host_profile.load_per_core);
    fprintf(fp, "  \"is_congested\": %s,\n",
            g_host_profile.is_congested ? "true" : "false");
    fprintf(fp, "  \"boot_timestamp\": \"%s\"\n",
            g_host_profile.boot_timestamp);
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}
