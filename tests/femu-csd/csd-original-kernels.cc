#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>

#include "femu-csd-kernel.h"

struct KnnNode {
    char tag[64];
    char vector[4096];
};

static int knn_distance(const int *query, const char *vector)
{
    int distance = 0;

    for (size_t i = 0; i < 4096; ++i) {
        int diff = query[i] - (vector[i] - '0');

        distance += diff * diff;
    }

    return distance;
}

static void knn_chunk(const KnnNode *nodes, const int *query,
                      size_t start, size_t end, int *distances)
{
    for (size_t i = start; i < end; ++i) {
        distances[i] = knn_distance(query, nodes[i].vector);
    }
}

extern "C" long long csd_knn(struct femu_csd_args *args)
{
    if (args->numr < 2) {
        return -1;
    }

    const KnnNode *nodes = static_cast<const KnnNode *>(args->mr_addr[0]);
    int *output = static_cast<int *>(args->mr_addr[1]);
    size_t nr_vector = args->mr_len[0] / static_cast<long long>(sizeof(KnnNode));
    int query[4096] = { 0 };
    size_t nr_threads = std::min<size_t>(2, std::max<size_t>(1, nr_vector));
    size_t chunk = (nr_vector + nr_threads - 1) / nr_threads;
    std::vector<std::thread> threads;

    for (size_t t = 0; t < nr_threads; ++t) {
        size_t start = t * chunk;
        size_t end = std::min(start + chunk, nr_vector);

        if (start < end) {
            threads.emplace_back(knn_chunk, nodes, query, start, end, output);
        }
    }

    for (auto &thread : threads) {
        thread.join();
    }

    return nr_vector;
}

static long long sql_query_records(const char *data, size_t start, size_t end,
                                   int year_lower, int year_upper, char *output)
{
    static constexpr int record_length = 32;
    long long output_size = 0;

    for (size_t i = start; i + record_length <= end; i += record_length) {
        const char *record = data + i;
        int year = ((record[30] - '0') << 8) | static_cast<unsigned char>(record[31] - '0');

        if (year >= year_lower && year <= year_upper) {
            memcpy(output + output_size, record, record_length);
            output_size += record_length;
        }
    }

    return output_size;
}

extern "C" long long csd_sql(struct femu_csd_args *args)
{
    if (args->numr < 2) {
        return -1;
    }

    const char *data = static_cast<const char *>(args->mr_addr[0]);
    char *output = static_cast<char *>(args->mr_addr[1]);
    int year_lower = args->cparam1 ? args->cparam1 : 50;
    int year_upper = args->cparam2 ? args->cparam2 : 60;

    return sql_query_records(data, 0, args->mr_len[0], year_lower, year_upper, output);
}

static long long grep_rows(const char *data, int rows, int cols, const char *pattern)
{
    int pattern_length = strlen(pattern);
    long long matches = 0;

    for (int r = 0; r < rows; ++r) {
        const char *line = data + r * cols;

        for (int c = 0; c <= cols - pattern_length; ++c) {
            if (!strncmp(line + c, pattern, pattern_length)) {
                matches++;
            }
        }
    }

    return matches * 8;
}

extern "C" long long csd_grep(struct femu_csd_args *args)
{
    if (args->numr < 2) {
        return -1;
    }

    const char *data = static_cast<const char *>(args->mr_addr[0]);
    const char *pattern = static_cast<const char *>(args->mr_addr[1]);
    int cols = args->cparam2 ? args->cparam2 : 1024;
    int rows = args->cparam1 ? args->cparam1 : args->mr_len[0] / cols;

    return grep_rows(data, rows, cols, pattern);
}
