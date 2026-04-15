// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTATION ─────────────────────────────────────────────────────────

// WRITE OBJECT
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str;

    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // Create header
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // Combine header + data
    size_t total_len = header_len + len;
    void *full = malloc(total_len);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy((char*)full + header_len, data, len);

    // Compute hash
    compute_hash(full, total_len, id_out);

    // Deduplication
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Get path
    char path[512];
    object_path(id_out, path, sizeof(path));

    // Extract directory path
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        free(full);
        return -1;
    }
    *slash = '\0';

    // Create directory (ignore if exists)
    mkdir(dir, 0755);

    // Temp file
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmpXXXXXX", dir);

    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // Write data
    if (write(fd, full, total_len) != (ssize_t)total_len) {
        close(fd);
        unlink(temp_path);
        free(full);
        return -1;
    }

    // Ensure disk write
    if (fsync(fd) != 0) {
        close(fd);
        unlink(temp_path);
        free(full);
        return -1;
    }

    close(fd);

    // Atomic rename
    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        free(full);
        return -1;
    }

    // fsync directory
    int dir_fd = open(dir, O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full);
    return 0;
}

// READ OBJECT
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    void *buffer = malloc(file_size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    if (fread(buffer, 1, file_size, f) != (size_t)file_size) {
        fclose(f);
        free(buffer);
        return -1;
    }
    fclose(f);

    // Verify hash
    ObjectID check;
    compute_hash(buffer, file_size, &check);

    if (memcmp(check.hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1;
    }

    // Find header end
    char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    size_t header_len = (char*)null_pos - (char*)buffer;

    // Parse header
    char type_str[16];
    size_t data_size;

    if (sscanf(buffer, "%15s %zu", type_str, &data_size) != 2) {
        free(buffer);
        return -1;
    }

    // Determine type
    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    // Extract data
    *data_out = malloc(data_size);
    if (!*data_out) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, (char*)buffer + header_len + 1, data_size);
    *len_out = data_size;

    free(buffer);
    return 0;
}
