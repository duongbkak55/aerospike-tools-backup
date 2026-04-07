/*
 * Aerospike Backup Filter
 *
 * Copyright (c) 2024 Aerospike, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <getopt.h>
#include <inttypes.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_record.h>
#include <aerospike/as_val.h>
#include <aerospike/as_integer.h>
#include <aerospike/as_string.h>
#include <aerospike/as_bytes.h>
#include <citrusleaf/cf_b64.h>
#include <aerospike/as_vector.h>
#include <aerospike/as_udf.h>

#pragma GCC diagnostic pop

#include <dec_text.h>
#include <enc_text.h>
#include <io_proxy.h>
#include <encode.h>
#include <utils.h>
#include <filter.h>


//==========================================================
// Typedefs & constants.
//

#define ASB_SUFFIX     ".asb"
#define ASB_SUFFIX_LEN 4

// Long-only option IDs (beyond ASCII range).
#define OPT_KEY_TYPE      1001
#define OPT_VERSION       1002
#define OPT_SPLIT_RECORDS 1003
#define OPT_SPLIT_SIZE    1004

#define MB (1024ULL * 1024ULL)

typedef enum {
	FILTER_KEY_TYPE_STRING = 0,
	FILTER_KEY_TYPE_INTEGER,
	FILTER_KEY_TYPE_DIGEST
} filter_key_type_t;

/*
 * Holds the set of keys loaded from the external key file.
 * Only one of the three vectors is populated, based on key_type.
 */
typedef struct filter_keys {
	filter_key_type_t type;
	as_vector string_keys;   // vector of char *
	as_vector int_keys;      // vector of int64_t
	as_vector digest_keys;   // vector of char * (base64)
	bool active;             // true when any keys are loaded
} filter_keys_t;


//==========================================================
// Forward Declarations.
//

static void print_usage(const char *prog);
static bool keys_init(filter_keys_t *keys, const char *key_file,
		filter_key_type_t key_type);
static void keys_destroy(filter_keys_t *keys);
static bool record_matches(const as_record *rec, const char *ns_filter,
		const as_vector *set_list, const filter_keys_t *keys);
static bool write_udf_param(io_write_proxy_t *out_fd, const udf_param *udf);
static bool process_file(const char *in_path, const char *out_path,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written);
static bool process_directory(const char *in_dir, const char *out_dir,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written);
static bool split_file(const char *in_path, const char *out_dir,
		uint64_t split_records, uint64_t split_size_bytes,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written);
static bool split_directory(const char *in_dir, const char *out_dir,
		uint64_t split_records, uint64_t split_size_bytes,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written);
static bool open_split_output(io_write_proxy_t *fd,
		const char *out_dir, const char *base_name,
		uint64_t file_index, const char *ns,
		bool first_file,
		const as_vector *g_indexes, const as_vector *g_udfs);
static int compare_str_ptr(const void *a, const void *b);
static bool ensure_directory(const char *path);


//==========================================================
// Public API.
//

int32_t
filter_main(int32_t argc, char **argv)
{
	int32_t res = EXIT_FAILURE;

	// Initialize logging globals used by utils.c inf()/err()/ver().
	atomic_init(&g_verbose, false);
	atomic_init(&g_silent, false);

	// ---- option state ----
	char *input_file = NULL;
	char *input_dir  = NULL;
	char *output_file = NULL;
	char *output_dir  = NULL;
	char *ns_filter   = NULL;
	char *set_list_str = NULL;
	char *key_file    = NULL;
	filter_key_type_t key_type = FILTER_KEY_TYPE_STRING;
	uint64_t split_records   = 0;   // 0 = no split
	uint64_t split_size_mb   = 0;   // 0 = no split
	bool verbose = false;

	static struct option long_opts[] = {
		{ "input",         required_argument, NULL, 'i' },
		{ "directory",     required_argument, NULL, 'd' },
		{ "output",        required_argument, NULL, 'o' },
		{ "output-dir",    required_argument, NULL, 'O' },
		{ "namespace",     required_argument, NULL, 'n' },
		{ "set",           required_argument, NULL, 's' },
		{ "key-file",      required_argument, NULL, 'K' },
		{ "key-type",      required_argument, NULL, OPT_KEY_TYPE },
		{ "split-records", required_argument, NULL, OPT_SPLIT_RECORDS },
		{ "split-size",    required_argument, NULL, OPT_SPLIT_SIZE },
		{ "verbose",       no_argument,       NULL, 'v' },
		{ "version",       no_argument,       NULL, OPT_VERSION },
		{ "help",          no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int32_t opt;
	int32_t opt_idx;

	while ((opt = getopt_long(argc, argv, "i:d:o:O:n:s:K:vh",
					long_opts, &opt_idx)) != -1) {
		switch (opt) {
		case 'i':
			input_file = optarg;
			break;
		case 'd':
			input_dir = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'O':
			output_dir = optarg;
			break;
		case 'n':
			ns_filter = optarg;
			break;
		case 's':
			set_list_str = optarg;
			break;
		case 'K':
			key_file = optarg;
			break;
		case OPT_KEY_TYPE:
			if (strcmp(optarg, "string") == 0) {
				key_type = FILTER_KEY_TYPE_STRING;
			} else if (strcmp(optarg, "integer") == 0) {
				key_type = FILTER_KEY_TYPE_INTEGER;
			} else if (strcmp(optarg, "digest") == 0) {
				key_type = FILTER_KEY_TYPE_DIGEST;
			} else {
				err("Unknown --key-type '%s'. Valid values: string, integer, digest",
						optarg);
				goto cleanup;
			}
			break;
		case 'v':
			verbose = true;
			atomic_store(&g_verbose, true);
			break;
		case OPT_SPLIT_RECORDS: {
			int64_t v;
			if (!better_atoi(optarg, &v) || v <= 0) {
				err("--split-records requires a positive integer, got '%s'", optarg);
				goto cleanup;
			}
			split_records = (uint64_t)v;
			break;
		}
		case OPT_SPLIT_SIZE: {
			int64_t v;
			if (!better_atoi(optarg, &v) || v <= 0) {
				err("--split-size requires a positive integer (MB), got '%s'", optarg);
				goto cleanup;
			}
			split_size_mb = (uint64_t)v;
			break;
		}
		case OPT_VERSION:
			fprintf(stdout, "asfilter %s\n", TOOL_VERSION);
			res = EXIT_SUCCESS;
			goto cleanup;
		case 'h':
			print_usage(argv[0]);
			res = EXIT_SUCCESS;
			goto cleanup;
		default:
			print_usage(argv[0]);
			goto cleanup;
		}
	}

	(void)verbose;

	// ---- validate options ----

	bool split_mode = (split_records > 0 || split_size_mb > 0);

	bool have_input_file  = (input_file  != NULL);
	bool have_input_dir   = (input_dir   != NULL);
	bool have_output_file = (output_file != NULL);
	bool have_output_dir  = (output_dir  != NULL);

	if (!have_input_file && !have_input_dir) {
		err("Specify input with -i FILE or -d DIRECTORY");
		print_usage(argv[0]);
		goto cleanup;
	}

	if (have_input_file && have_input_dir) {
		err("Use either -i FILE or -d DIRECTORY, not both");
		goto cleanup;
	}

	if (!have_output_file && !have_output_dir) {
		err("Specify output with -o FILE or -O DIRECTORY");
		print_usage(argv[0]);
		goto cleanup;
	}

	if (have_output_file && have_output_dir) {
		err("Use either -o FILE or -O DIRECTORY, not both");
		goto cleanup;
	}

	// Split mode always writes to a directory (multiple files).
	if (split_mode && have_output_file) {
		err("--split-records / --split-size produce multiple files; "
				"use -O DIRECTORY for output, not -o FILE");
		goto cleanup;
	}

	// Without split mode, input/output modes must match.
	if (!split_mode) {
		if (have_input_file && have_output_dir) {
			err("When input is a file (-i), output must also be a file (-o), "
					"not a directory (-O)");
			goto cleanup;
		}

		if (have_input_dir && have_output_file) {
			err("When input is a directory (-d), output must also be a "
					"directory (-O), not a file (-o)");
			goto cleanup;
		}
	}

	if (!split_mode && ns_filter == NULL && set_list_str == NULL && key_file == NULL) {
		err("No filter or split specified. "
				"Use -n/-s/-K to filter, or --split-records/--split-size to split");
		print_usage(argv[0]);
		goto cleanup;
	}

	// ---- parse set list ----
	as_vector set_list;
	as_vector_init(&set_list, sizeof(void *), 4);

	if (set_list_str != NULL) {
		// split_string modifies the string in place; work on a copy
		char *set_copy = safe_strdup(set_list_str);
		split_string(set_copy, ',', true, &set_list);
		// The vector now contains pointers into set_copy; keep set_copy alive.
		// We'll free it after we're done using the vector.
		// Note: split_string stores pointers directly into set_copy, so we just
		// need to keep set_copy alive. We'll capture it here.
		// Since set_list contains char* pointers into set_copy, and set_copy is
		// on the heap, this is fine as long as we free it after the run.
		// We store the copy pointer separately to free it later.

		// Re-split with duplicated strings so we can free set_copy safely.
		as_vector_clear(&set_list);
		cf_free(set_copy);

		set_copy = safe_strdup(set_list_str);
		// Tokenize manually
		char *tok = strtok(set_copy, ",");
		while (tok != NULL) {
			// trim whitespace
			while (*tok == ' ') tok++;
			char *end = tok + strlen(tok) - 1;
			while (end > tok && *end == ' ') *end-- = '\0';

			if (*tok != '\0') {
				char *s = safe_strdup(tok);
				as_vector_append(&set_list, &s);
			}
			tok = strtok(NULL, ",");
		}
		cf_free(set_copy);
	}

	// ---- load key file ----
	filter_keys_t keys;
	keys.active = false;
	as_vector_init(&keys.string_keys, sizeof(char *), 128);
	as_vector_init(&keys.int_keys, sizeof(int64_t), 128);
	as_vector_init(&keys.digest_keys, sizeof(char *), 128);

	if (key_file != NULL) {
		if (!keys_init(&keys, key_file, key_type)) {
			goto cleanup_keys;
		}
	}

	// ---- run ----
	uint64_t total_records   = 0;
	uint64_t written_records = 0;
	const filter_keys_t *kp  = (key_file != NULL) ? &keys : NULL;
	uint64_t split_bytes     = split_size_mb * MB;

	if (split_mode) {
		if (have_input_file) {
			if (!split_file(input_file, output_dir, split_records, split_bytes,
						ns_filter, &set_list, kp,
						&total_records, &written_records)) {
				goto cleanup_keys;
			}
		} else {
			if (!split_directory(input_dir, output_dir, split_records, split_bytes,
						ns_filter, &set_list, kp,
						&total_records, &written_records)) {
				goto cleanup_keys;
			}
		}
	} else if (have_input_file) {
		if (!process_file(input_file, output_file, ns_filter, &set_list, kp,
					&total_records, &written_records)) {
			goto cleanup_keys;
		}
	} else {
		if (!process_directory(input_dir, output_dir, ns_filter, &set_list, kp,
					&total_records, &written_records)) {
			goto cleanup_keys;
		}
	}

	inf("Done. Records: total=%" PRIu64 ", written=%" PRIu64 ", skipped=%" PRIu64,
			total_records, written_records, total_records - written_records);

	res = EXIT_SUCCESS;

cleanup_keys:
	keys_destroy(&keys);

cleanup_sets:
	for (uint32_t i = 0; i < set_list.size; i++) {
		char *s = *(char **)as_vector_get(&set_list, i);
		cf_free(s);
	}
	as_vector_destroy(&set_list);

cleanup:
	return res;
}


//==========================================================
// Local helpers.
//

static void
print_usage(const char *prog)
{
	fprintf(stdout,
		"Usage: %s [options]\n"
		"\n"
		"Filters and/or splits Aerospike backup files.\n"
		"Output is in standard asbackup format, compatible with asrestore.\n"
		"\n"
		"Input/Output Options:\n"
		"  -i, --input FILE             Input backup file (.asb)\n"
		"  -d, --directory DIR          Input backup directory\n"
		"  -o, --output FILE            Output backup file (filter mode only)\n"
		"  -O, --output-dir DIR         Output backup directory\n"
		"\n"
		"Filter Options (optional; combinable with split):\n"
		"  -n, --namespace NS           Keep only records in namespace NS\n"
		"  -s, --set SETS               Keep only records in set(s), comma-separated\n"
		"  -K, --key-file FILE          Keep only records whose user key appears in FILE\n"
		"      --key-type TYPE          Type of keys in --key-file:\n"
		"                                 string  (default) - plain string values\n"
		"                                 integer           - 64-bit decimal integers\n"
		"                                 digest            - base64-encoded 20-byte digests\n"
		"\n"
		"Split Options (require -O DIRECTORY; at least one or a filter required):\n"
		"      --split-records N        Start a new output file every N records\n"
		"      --split-size   N         Start a new output file after ~N MB of output\n"
		"                               (Both can be combined; whichever threshold is\n"
		"                                hit first triggers the split.)\n"
		"\n"
		"Other Options:\n"
		"  -v, --verbose                Verbose output\n"
		"      --version                Show version information\n"
		"  -h, --help                   Show this help message\n"
		"\n"
		"Split output file naming:  <input_basename>_<NNNN>.asb\n"
		"  The first file carries '# first-file' and all secondary index / UDF\n"
		"  definitions; subsequent files contain only records. All files are valid\n"
		"  asrestore inputs individually or as a directory.\n"
		"\n"
		"Key File Format:\n"
		"  One key per line. Lines starting with '#' and blank lines are ignored.\n"
		"\n"
		"Examples:\n"
		"  # Filter single file by namespace\n"
		"  %s -i backup.asb -o filtered.asb -n mynamespace\n"
		"\n"
		"  # Split a large file into 500 000-record chunks (enables parallel restore)\n"
		"  %s -i big.asb -O parts/ --split-records 500000\n"
		"\n"
		"  # Split into ~250 MB chunks\n"
		"  %s -i big.asb -O parts/ --split-size 250\n"
		"\n"
		"  # Filter by namespace AND split\n"
		"  %s -i big.asb -O parts/ -n myns --split-records 100000\n"
		"\n"
		"  # Split a directory of backup files\n"
		"  %s -d /backup -O /parts --split-records 500000\n"
		"\n"
		"  # Filter by key list (string keys)\n"
		"  %s -i backup.asb -o filtered.asb -K keys.txt\n"
		"\n",
		prog, prog, prog, prog, prog, prog, prog);
}

/*
 * Loads keys from the given file into the keys struct.
 * Lines starting with '#' and blank lines are skipped.
 */
static bool
keys_init(filter_keys_t *keys, const char *key_file, filter_key_type_t key_type)
{
	keys->type = key_type;

	FILE *f = fopen(key_file, "r");

	if (f == NULL) {
		err("Failed to open key file %s: %s", key_file, strerror(errno));
		return false;
	}

	char line[4096];
	int64_t line_no = 0;
	bool ok = true;

	while (fgets(line, (int)sizeof(line), f) != NULL) {
		line_no++;

		// Remove trailing newline / carriage-return.
		size_t len = strlen(line);

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[--len] = '\0';
		}

		// Skip blank lines and comments.
		if (len == 0 || line[0] == '#') {
			continue;
		}

		switch (key_type) {
		case FILTER_KEY_TYPE_STRING: {
			char *key = safe_strdup(line);
			as_vector_append(&keys->string_keys, &key);
			break;
		}
		case FILTER_KEY_TYPE_INTEGER: {
			int64_t val;

			if (!better_atoi(line, &val)) {
				err("Invalid integer on line %" PRId64 " of key file %s: '%s'",
						line_no, key_file, line);
				ok = false;
				goto done;
			}

			as_vector_append(&keys->int_keys, &val);
			break;
		}
		case FILTER_KEY_TYPE_DIGEST: {
			char *key = safe_strdup(line);
			as_vector_append(&keys->digest_keys, &key);
			break;
		}
		}
	}

done:
	fclose(f);

	if (!ok) {
		return false;
	}

	uint32_t n = keys->string_keys.size + keys->int_keys.size +
			keys->digest_keys.size;
	inf("Loaded %u key(s) from %s", n, key_file);
	keys->active = (n > 0);
	return true;
}

static void
keys_destroy(filter_keys_t *keys)
{
	for (uint32_t i = 0; i < keys->string_keys.size; i++) {
		char *k = *(char **)as_vector_get(&keys->string_keys, i);
		cf_free(k);
	}

	as_vector_destroy(&keys->string_keys);
	as_vector_destroy(&keys->int_keys);

	for (uint32_t i = 0; i < keys->digest_keys.size; i++) {
		char *k = *(char **)as_vector_get(&keys->digest_keys, i);
		cf_free(k);
	}

	as_vector_destroy(&keys->digest_keys);
}

/*
 * Returns true if the record satisfies all active filter conditions.
 *
 *  ns_filter  – namespace string, or NULL to skip namespace check
 *  set_list   – vector of char*; if empty, all sets are accepted
 *  keys       – key filter struct, or NULL to skip key check
 */
static bool
record_matches(const as_record *rec, const char *ns_filter,
		const as_vector *set_list, const filter_keys_t *keys)
{
	// --- namespace ---
	if (ns_filter != NULL) {
		if (strcmp(rec->key.ns, ns_filter) != 0) {
			return false;
		}
	}

	// --- set ---
	if (set_list != NULL && set_list->size > 0) {
		bool found = false;

		for (uint32_t i = 0; i < set_list->size; i++) {
			const char *set = *(const char **)as_vector_get(
					(as_vector *)set_list, i);

			if (strcmp(rec->key.set, set) == 0) {
				found = true;
				break;
			}
		}

		if (!found) {
			return false;
		}
	}

	// --- key file ---
	if (keys == NULL || !keys->active) {
		return true;
	}

	switch (keys->type) {
	case FILTER_KEY_TYPE_STRING: {
		if (keys->string_keys.size == 0) {
			return true;
		}

		// Record must carry a string user key.
		if (rec->key.valuep == NULL ||
				((as_val *)rec->key.valuep)->type != AS_STRING) {
			return false;
		}

		const as_string *s = as_string_fromval((as_val *)rec->key.valuep);

		for (uint32_t i = 0; i < keys->string_keys.size; i++) {
			const char *k = *(const char **)as_vector_get(
					(as_vector *)&keys->string_keys, i);

			if (strcmp(s->value, k) == 0) {
				return true;
			}
		}

		return false;
	}

	case FILTER_KEY_TYPE_INTEGER: {
		if (keys->int_keys.size == 0) {
			return true;
		}

		// Record must carry an integer user key.
		if (rec->key.valuep == NULL ||
				((as_val *)rec->key.valuep)->type != AS_INTEGER) {
			return false;
		}

		const as_integer *ip = as_integer_fromval((as_val *)rec->key.valuep);

		for (uint32_t i = 0; i < keys->int_keys.size; i++) {
			int64_t k = *(int64_t *)as_vector_get(
					(as_vector *)&keys->int_keys, i);

			if (ip->value == k) {
				return true;
			}
		}

		return false;
	}

	case FILTER_KEY_TYPE_DIGEST: {
		if (keys->digest_keys.size == 0) {
			return true;
		}

		// Every record has a digest; compare base64-encoded forms.
		uint32_t b64_len = cf_b64_encoded_len(AS_DIGEST_VALUE_SIZE);
		char *b64 = (char *)alloca(b64_len + 1);
		cf_b64_encode((uint8_t *)rec->key.digest.value,
				AS_DIGEST_VALUE_SIZE, b64);
		b64[b64_len] = '\0';

		for (uint32_t i = 0; i < keys->digest_keys.size; i++) {
			const char *k = *(const char **)as_vector_get(
					(as_vector *)&keys->digest_keys, i);

			if (strcmp(b64, k) == 0) {
				return true;
			}
		}

		return false;
	}
	}

	/* unreachable */
	return false;
}

/*
 * Writes a udf_param to an output backup file using the standard global-data
 * format:  "* u <type_char> <escaped_name> <size> <raw_bytes>\n"
 */
static bool
write_udf_param(io_write_proxy_t *out_fd, const udf_param *udf)
{
	char type_char;

	if (udf->type == AS_UDF_TYPE_LUA) {
		type_char = 'L';
	} else {
		err("Unsupported UDF type %d", (int32_t)udf->type);
		return false;
	}

	if (io_proxy_printf(out_fd, GLOBAL_PREFIX "u %c %s %u ",
				type_char, escape(udf->name), udf->size) < 0) {
		err("Error writing UDF header to output");
		return false;
	}

	if (io_proxy_write(out_fd, udf->data, udf->size) != (int64_t)udf->size) {
		err("Error writing UDF content to output");
		return false;
	}

	if (io_proxy_printf(out_fd, "\n") < 0) {
		err("Error writing UDF trailing newline");
		return false;
	}

	return true;
}

/*
 * Filters a single backup file.
 *
 *  in_path   – path to the source .asb file
 *  out_path  – path of the output .asb file to create
 *  ns_filter – namespace filter, or NULL
 *  set_list  – set filter vector, or empty
 *  keys      – key filter, or NULL
 *
 * The output file preserves the version header, namespace metadata, and
 * (when present) the first-file marker + global data (secondary indexes,
 * UDF files).  Only records matching all supplied filters are copied.
 *
 * The function increments *out_total / *out_written accordingly.
 */
static bool
process_file(const char *in_path, const char *out_path,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written)
{
	bool res = false;
	io_read_proxy_t  in_fd;
	io_write_proxy_t out_fd;
	bool in_opened  = false;
	bool out_opened = false;

	// ---- open input ----
	if (io_read_proxy_init(&in_fd, in_path) != 0) {
		err("Failed to open input file: %s", in_path);
		goto cleanup;
	}

	in_opened = true;

	// ---- read version header ----
	char version[13];
	memset(version, 0, sizeof version);

	if (io_proxy_gets(&in_fd, version, (int)sizeof version) == NULL) {
		err("Error reading version header from %s", in_path);
		goto cleanup;
	}

	if (strncmp("Version ", version, 8) != 0 || version[11] != '\n') {
		err("Invalid version line in backup file %s", in_path);
		goto cleanup;
	}

	bool legacy = strncmp(version + 8, VERSION_3_0, 3) == 0;

	if (!legacy && strncmp(version + 8, VERSION_3_1, 3) != 0) {
		err("Unsupported backup file version %.3s in %s", version + 8, in_path);
		goto cleanup;
	}

	// ---- read metadata section ----
	char file_namespace[256] = { 0 };
	bool file_is_first = false;
	uint32_t line_no = 2;

	{
		char meta[MAX_META_LINE + 4];
		int32_t ch;

		while ((ch = io_proxy_peekc_unlocked(&in_fd)) == (int32_t)META_PREFIX[0]) {
			io_proxy_getc_unlocked(&in_fd);

			if (io_proxy_gets(&in_fd, meta, (int)sizeof meta) == NULL) {
				err("Error reading metadata from %s:%u", in_path, line_no);
				goto cleanup;
			}

			// NUL-terminate at the first newline.
			for (uint32_t i = 0; i < sizeof meta; i++) {
				if (meta[i] == '\n') {
					meta[i] = '\0';
					break;
				}
			}

			if (meta[0] != META_PREFIX[1]) {
				err("Invalid metadata line in %s:%u", in_path, line_no);
				goto cleanup;
			}

			if (strcmp(meta + 1, META_FIRST_FILE) == 0) {
				file_is_first = true;
			} else if (strncmp(meta + 1, META_NAMESPACE,
						sizeof META_NAMESPACE - 1) == 0 &&
					meta[1 + sizeof META_NAMESPACE - 1] == ' ') {
				// "# namespace <name>"
				const char *ns = meta + 1 + sizeof META_NAMESPACE - 1 + 1;
				strncpy(file_namespace, ns, sizeof file_namespace - 1);
				file_namespace[sizeof file_namespace - 1] = '\0';
			}

			line_no++;
		}
	}

	// Decide the namespace string for the output header.
	const char *out_ns = (file_namespace[0] != '\0') ? file_namespace
			: (ns_filter != NULL) ? ns_filter : "unknown";

	// ---- open output ----
	if (io_write_proxy_init(&out_fd, out_path, UINT64_MAX) != 0) {
		err("Failed to open output file: %s", out_path);
		goto cleanup;
	}

	out_opened = true;

	// ---- write output header ----
	if (io_proxy_printf(&out_fd, "Version " VERSION_3_1 "\n") < 0) {
		err("Error writing version to %s", out_path);
		goto cleanup;
	}

	if (io_proxy_printf(&out_fd, META_PREFIX META_NAMESPACE " %s\n",
				escape(out_ns)) < 0) {
		err("Error writing namespace metadata to %s", out_path);
		goto cleanup;
	}

	if (file_is_first) {
		if (io_proxy_printf(&out_fd, META_PREFIX META_FIRST_FILE "\n") < 0) {
			err("Error writing first-file metadata to %s", out_path);
			goto cleanup;
		}
	}

	// ---- process body (global data + records) ----
	as_vector empty_ns_vec;
	as_vector empty_bin_vec;
	as_vector_init(&empty_ns_vec, sizeof(void *), 1);
	as_vector_init(&empty_bin_vec, sizeof(void *), 1);

	uint64_t file_total   = 0;
	uint64_t file_written = 0;
	bool body_ok = true;

	while (true) {
		as_record   rec;
		bool        expired;
		index_param index;
		udf_param   udf;

		decoder_status status = text_parse(&in_fd, legacy,
				&empty_ns_vec, &empty_bin_vec,
				&line_no, &rec, 0, &expired, &index, &udf);

		if (status == DECODER_EOF) {
			break;
		}

		if (status == DECODER_ERROR) {
			err("Error parsing %s at line %u", in_path, line_no);
			body_ok = false;
			break;
		}

		if (status == DECODER_RECORD) {
			file_total++;

			if (record_matches(&rec, ns_filter, set_list, keys)) {
				file_written++;

				if (!text_put_record(&out_fd, false, &rec)) {
					err("Error writing record to %s", out_path);
					as_record_destroy(&rec);
					body_ok = false;
					break;
				}
			}

			as_record_destroy(&rec);

		} else if (status == DECODER_INDEX) {
			// Pass through secondary index definitions (first-file only).
			if (file_is_first) {
				if (!text_put_secondary_index(&out_fd, &index)) {
					err("Error writing secondary index to %s", out_path);
					free_index(&index);
					body_ok = false;
					break;
				}
			}

			free_index(&index);

		} else if (status == DECODER_UDF) {
			// Pass through UDF files (first-file only).
			if (file_is_first) {
				if (!write_udf_param(&out_fd, &udf)) {
					err("Error writing UDF to %s", out_path);
					free_udf(&udf);
					body_ok = false;
					break;
				}
			}

			free_udf(&udf);
		}
	}

	as_vector_destroy(&empty_ns_vec);
	as_vector_destroy(&empty_bin_vec);

	if (!body_ok) {
		goto cleanup;
	}

	*out_total   += file_total;
	*out_written += file_written;

	inf("%s: total=%" PRIu64 ", written=%" PRIu64 ", skipped=%" PRIu64,
			in_path, file_total, file_written, file_total - file_written);

	res = true;

cleanup:
	if (in_opened) {
		io_proxy_close(&in_fd);
	}

	if (out_opened) {
		if (io_proxy_flush(&out_fd) != 0) {
			err("Error flushing output file %s", out_path);
			res = false;
		}

		io_proxy_close(&out_fd);
	}

	return res;
}

/*
 * qsort comparator for char * pointers (compares the pointed-to strings).
 */
static int
compare_str_ptr(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

/*
 * Creates directory at path if it does not already exist.
 * Returns true on success (including when the directory already exists).
 */
static bool
ensure_directory(const char *path)
{
	struct stat st;

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return true;
		}

		err("Output path exists but is not a directory: %s", path);
		return false;
	}

	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
		err("Failed to create output directory %s: %s", path, strerror(errno));
		return false;
	}

	return true;
}

/*
 * Filters all .asb files found in in_dir, writing results to out_dir.
 *
 * Files are processed in sorted order so that the file carrying the
 * "# first-file" marker (which contains global data) is handled stably.
 */
static bool
process_directory(const char *in_dir, const char *out_dir,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written)
{
	DIR *dir = opendir(in_dir);

	if (dir == NULL) {
		err("Failed to open input directory %s: %s", in_dir, strerror(errno));
		return false;
	}

	// Collect all .asb filenames.
	as_vector file_list;
	as_vector_init(&file_list, sizeof(char *), 64);

	struct dirent *ent;

	while ((ent = readdir(dir)) != NULL) {
		const char *name = ent->d_name;
		size_t nlen = strlen(name);

		if (nlen > ASB_SUFFIX_LEN &&
				strcmp(name + nlen - ASB_SUFFIX_LEN, ASB_SUFFIX) == 0) {
			char *copy = safe_strdup(name);
			as_vector_append(&file_list, &copy);
		}
	}

	closedir(dir);

	if (file_list.size == 0) {
		err("No .asb files found in directory %s", in_dir);
		as_vector_destroy(&file_list);
		return false;
	}

	// Sort filenames for deterministic ordering.
	qsort(file_list.list, file_list.size, sizeof(char *), compare_str_ptr);

	// Ensure output directory exists.
	if (!ensure_directory(out_dir)) {
		for (uint32_t i = 0; i < file_list.size; i++) {
			cf_free(*(char **)as_vector_get(&file_list, i));
		}

		as_vector_destroy(&file_list);
		return false;
	}

	bool all_ok = true;

	for (uint32_t i = 0; i < file_list.size; i++) {
		const char *name = *(const char **)as_vector_get(&file_list, i);

		// Build full paths.
		size_t in_len  = strlen(in_dir)  + 1 + strlen(name) + 1;
		size_t out_len = strlen(out_dir) + 1 + strlen(name) + 1;

		char *in_path  = (char *)safe_malloc(in_len);
		char *out_path = (char *)safe_malloc(out_len);

		snprintf(in_path,  in_len,  "%s/%s", in_dir,  name);
		snprintf(out_path, out_len, "%s/%s", out_dir, name);

		inf("Processing %s -> %s", in_path, out_path);

		if (!process_file(in_path, out_path, ns_filter, set_list, keys,
					out_total, out_written)) {
			err("Failed to process file: %s", in_path);
			all_ok = false;
		}

		cf_free(in_path);
		cf_free(out_path);
	}

	for (uint32_t i = 0; i < file_list.size; i++) {
		cf_free(*(char **)as_vector_get(&file_list, i));
	}

	as_vector_destroy(&file_list);
	return all_ok;
}

/*
 * Opens and initializes one output file for split mode.
 *
 *  out_dir    – directory that will hold all split files
 *  base_name  – filename stem (e.g. "backup"); the path becomes
 *               "<out_dir>/<base_name>_<NNNN>.asb"
 *  file_index – 1-based index (used to build the filename)
 *  ns         – namespace string written to the header
 *  first_file – when true, writes "# first-file" plus all buffered
 *               secondary index and UDF definitions
 *  g_indexes  – as_vector of index_param (by value); written if first_file
 *  g_udfs     – as_vector of udf_param   (by value); written if first_file
 *
 * Returns true and leaves *fd open on success.
 */
static bool
open_split_output(io_write_proxy_t *fd,
		const char *out_dir, const char *base_name,
		uint64_t file_index, const char *ns,
		bool first_file,
		const as_vector *g_indexes, const as_vector *g_udfs)
{
	char path[4096];
	snprintf(path, sizeof path, "%s/%s_%04" PRIu64 ".asb",
			out_dir, base_name, file_index);

	if (io_write_proxy_init(fd, path, UINT64_MAX) != 0) {
		err("Failed to create output file %s", path);
		return false;
	}

	if (io_proxy_printf(fd, "Version " VERSION_3_1 "\n") < 0 ||
			io_proxy_printf(fd, META_PREFIX META_NAMESPACE " %s\n",
					escape(ns)) < 0) {
		err("Error writing header to %s", path);
		io_proxy_close(fd);
		return false;
	}

	if (first_file) {
		if (io_proxy_printf(fd, META_PREFIX META_FIRST_FILE "\n") < 0) {
			err("Error writing first-file marker to %s", path);
			io_proxy_close(fd);
			return false;
		}

		for (uint32_t i = 0; i < g_indexes->size; i++) {
			const index_param *idx =
				(const index_param *)as_vector_get((as_vector *)g_indexes, i);

			if (!text_put_secondary_index(fd, idx)) {
				err("Error writing secondary index to %s", path);
				io_proxy_close(fd);
				return false;
			}
		}

		for (uint32_t i = 0; i < g_udfs->size; i++) {
			const udf_param *u =
				(const udf_param *)as_vector_get((as_vector *)g_udfs, i);

			if (!write_udf_param(fd, u)) {
				err("Error writing UDF to %s", path);
				io_proxy_close(fd);
				return false;
			}
		}
	}

	ver("Opened split output file %s", path);
	return true;
}

/*
 * Splits (and optionally filters) a single backup file into multiple smaller
 * output files stored in out_dir.
 *
 * Split triggers (whichever hits first):
 *   split_records > 0  – roll over after this many records per file
 *   split_size_bytes > 0 – roll over when the file exceeds this many bytes
 *
 * Filter parameters (ns_filter, set_list, keys) are applied the same way as
 * in process_file(); pass NULL / empty vector / NULL to disable.
 *
 * Output file naming:  <out_dir>/<in_basename>_<NNNN>.asb
 * The first output file carries "# first-file" and all global data (secondary
 * indexes, UDF files) found in the input.  Subsequent files have only the
 * version header and namespace metadata.
 */
static bool
split_file(const char *in_path, const char *out_dir,
		uint64_t split_records, uint64_t split_size_bytes,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written)
{
	bool res = false;
	io_read_proxy_t  in_fd;
	io_write_proxy_t out_fd;
	bool in_opened  = false;
	bool out_opened = false;

	// Global data buffered from the input's header section.
	// Stored by value (shallow copy); callers must not free_index/free_udf
	// the originals after appending here.
	as_vector g_indexes;   // as_vector of index_param
	as_vector g_udfs;      // as_vector of udf_param
	as_vector_init(&g_indexes, sizeof(index_param), 8);
	as_vector_init(&g_udfs,    sizeof(udf_param),   8);

	// ---- open input ----
	if (io_read_proxy_init(&in_fd, in_path) != 0) {
		err("Failed to open input file: %s", in_path);
		goto cleanup;
	}

	in_opened = true;

	// ---- read version header ----
	char version[13];
	memset(version, 0, sizeof version);

	if (io_proxy_gets(&in_fd, version, (int)sizeof version) == NULL) {
		err("Error reading version header from %s", in_path);
		goto cleanup;
	}

	if (strncmp("Version ", version, 8) != 0 || version[11] != '\n') {
		err("Invalid version line in %s", in_path);
		goto cleanup;
	}

	bool legacy = strncmp(version + 8, VERSION_3_0, 3) == 0;

	if (!legacy && strncmp(version + 8, VERSION_3_1, 3) != 0) {
		err("Unsupported backup file version %.3s in %s", version + 8, in_path);
		goto cleanup;
	}

	// ---- read metadata section ----
	char file_namespace[256] = { 0 };
	bool input_is_first = false;
	uint32_t line_no = 2;

	{
		char meta[MAX_META_LINE + 4];
		int32_t ch;

		while ((ch = io_proxy_peekc_unlocked(&in_fd)) == (int32_t)META_PREFIX[0]) {
			io_proxy_getc_unlocked(&in_fd);

			if (io_proxy_gets(&in_fd, meta, (int)sizeof meta) == NULL) {
				err("Error reading metadata from %s:%u", in_path, line_no);
				goto cleanup;
			}

			for (uint32_t i = 0; i < sizeof meta; i++) {
				if (meta[i] == '\n') { meta[i] = '\0'; break; }
			}

			if (meta[0] != META_PREFIX[1]) {
				err("Invalid metadata line in %s:%u", in_path, line_no);
				goto cleanup;
			}

			if (strcmp(meta + 1, META_FIRST_FILE) == 0) {
				input_is_first = true;
			} else if (strncmp(meta + 1, META_NAMESPACE,
						sizeof META_NAMESPACE - 1) == 0 &&
					meta[1 + sizeof META_NAMESPACE - 1] == ' ') {
				const char *ns = meta + 1 + sizeof META_NAMESPACE - 1 + 1;
				strncpy(file_namespace, ns, sizeof file_namespace - 1);
				file_namespace[sizeof file_namespace - 1] = '\0';
			}

			line_no++;
		}
	}

	const char *out_ns = (file_namespace[0] != '\0') ? file_namespace
			: (ns_filter != NULL) ? ns_filter : "unknown";

	// ---- derive base name for output files ----
	// From "/path/to/backup.asb" → "backup"
	const char *slash = strrchr(in_path, '/');
	const char *fname = (slash != NULL) ? slash + 1 : in_path;
	char base_name[256];
	strncpy(base_name, fname, sizeof base_name - 1);
	base_name[sizeof base_name - 1] = '\0';
	{
		size_t blen = strlen(base_name);

		if (blen > ASB_SUFFIX_LEN &&
				strcmp(base_name + blen - ASB_SUFFIX_LEN, ASB_SUFFIX) == 0) {
			base_name[blen - ASB_SUFFIX_LEN] = '\0';
		}
	}

	if (!ensure_directory(out_dir)) {
		goto cleanup;
	}

	// ---- process entities ----
	as_vector empty_ns_vec;
	as_vector empty_bin_vec;
	as_vector_init(&empty_ns_vec, sizeof(void *), 1);
	as_vector_init(&empty_bin_vec, sizeof(void *), 1);

	uint64_t file_index       = 1;
	uint64_t records_in_file  = 0;
	uint64_t file_total       = 0;
	uint64_t file_written     = 0;
	bool     body_ok          = true;

	while (true) {
		as_record   rec;
		bool        expired;
		index_param index;
		udf_param   udf;

		decoder_status status = text_parse(&in_fd, legacy,
				&empty_ns_vec, &empty_bin_vec,
				&line_no, &rec, 0, &expired, &index, &udf);

		if (status == DECODER_EOF) {
			break;
		}

		if (status == DECODER_ERROR) {
			err("Error parsing %s at line %u", in_path, line_no);
			body_ok = false;
			break;
		}

		if (status == DECODER_INDEX) {
			// Buffer – do NOT call free_index; vector owns the struct now.
			as_vector_append(&g_indexes, &index);
			continue;
		}

		if (status == DECODER_UDF) {
			// Buffer – do NOT call free_udf; vector owns the struct now.
			as_vector_append(&g_udfs, &udf);
			continue;
		}

		// DECODER_RECORD path.
		file_total++;

		// Open the first output file lazily (after all global data is buffered).
		if (!out_opened) {
			if (!open_split_output(&out_fd, out_dir, base_name, file_index,
						out_ns, input_is_first, &g_indexes, &g_udfs)) {
				body_ok = false;
				as_record_destroy(&rec);
				break;
			}

			out_opened = true;
		}

		// Roll over if we've hit a split threshold.
		bool rollover = false;

		if (records_in_file > 0) {
			if (split_records > 0 && records_in_file >= split_records) {
				rollover = true;
			}

			if (!rollover && split_size_bytes > 0 &&
					(uint64_t)io_write_proxy_absolute_pos(&out_fd) >=
					split_size_bytes) {
				rollover = true;
			}
		}

		if (rollover) {
			if (io_proxy_flush(&out_fd) != 0) {
				err("Error flushing split output file");
			}

			io_proxy_close(&out_fd);
			out_opened = false;

			file_index++;
			records_in_file = 0;

			// Non-first files carry no "# first-file" / global data.
			if (!open_split_output(&out_fd, out_dir, base_name, file_index,
						out_ns, false, &g_indexes, &g_udfs)) {
				body_ok = false;
				as_record_destroy(&rec);
				break;
			}

			out_opened = true;
		}

		// Apply filter and write.
		if (record_matches(&rec, ns_filter, set_list, keys)) {
			file_written++;

			if (!text_put_record(&out_fd, false, &rec)) {
				err("Error writing record to split output %s part %" PRIu64,
						base_name, file_index);
				as_record_destroy(&rec);
				body_ok = false;
				break;
			}

			records_in_file++;
		}

		as_record_destroy(&rec);
	}

	as_vector_destroy(&empty_ns_vec);
	as_vector_destroy(&empty_bin_vec);

	if (!body_ok) {
		goto cleanup;
	}

	// If the input had global data but no records, still create output file #1.
	if (!out_opened && input_is_first) {
		if (!open_split_output(&out_fd, out_dir, base_name, file_index,
					out_ns, true, &g_indexes, &g_udfs)) {
			goto cleanup;
		}

		out_opened = true;
	}

	*out_total   += file_total;
	*out_written += file_written;

	inf("%s: total=%" PRIu64 ", written=%" PRIu64 ", skipped=%" PRIu64
			", split into %" PRIu64 " file(s)",
			in_path, file_total, file_written,
			file_total - file_written, file_index);

	res = true;

cleanup:
	if (in_opened) {
		io_proxy_close(&in_fd);
	}

	if (out_opened) {
		if (io_proxy_flush(&out_fd) != 0) {
			err("Error flushing final split output");
			res = false;
		}

		io_proxy_close(&out_fd);
	}

	// Free buffered global data.
	for (uint32_t i = 0; i < g_indexes.size; i++) {
		free_index((index_param *)as_vector_get(&g_indexes, i));
	}

	as_vector_destroy(&g_indexes);

	for (uint32_t i = 0; i < g_udfs.size; i++) {
		free_udf((udf_param *)as_vector_get(&g_udfs, i));
	}

	as_vector_destroy(&g_udfs);

	return res;
}

/*
 * Splits all .asb files found in in_dir, writing output to out_dir.
 * Each input file is split independently.
 */
static bool
split_directory(const char *in_dir, const char *out_dir,
		uint64_t split_records, uint64_t split_size_bytes,
		const char *ns_filter, const as_vector *set_list,
		const filter_keys_t *keys, uint64_t *out_total, uint64_t *out_written)
{
	DIR *dir = opendir(in_dir);

	if (dir == NULL) {
		err("Failed to open input directory %s: %s", in_dir, strerror(errno));
		return false;
	}

	as_vector file_list;
	as_vector_init(&file_list, sizeof(char *), 64);

	struct dirent *ent;

	while ((ent = readdir(dir)) != NULL) {
		const char *name = ent->d_name;
		size_t nlen = strlen(name);

		if (nlen > ASB_SUFFIX_LEN &&
				strcmp(name + nlen - ASB_SUFFIX_LEN, ASB_SUFFIX) == 0) {
			char *copy = safe_strdup(name);
			as_vector_append(&file_list, &copy);
		}
	}

	closedir(dir);

	if (file_list.size == 0) {
		err("No .asb files found in directory %s", in_dir);
		as_vector_destroy(&file_list);
		return false;
	}

	qsort(file_list.list, file_list.size, sizeof(char *), compare_str_ptr);

	if (!ensure_directory(out_dir)) {
		for (uint32_t i = 0; i < file_list.size; i++) {
			cf_free(*(char **)as_vector_get(&file_list, i));
		}

		as_vector_destroy(&file_list);
		return false;
	}

	bool all_ok = true;

	for (uint32_t i = 0; i < file_list.size; i++) {
		const char *name = *(const char **)as_vector_get(&file_list, i);

		size_t in_len = strlen(in_dir) + 1 + strlen(name) + 1;
		char *in_path = (char *)safe_malloc(in_len);
		snprintf(in_path, in_len, "%s/%s", in_dir, name);

		inf("Splitting %s -> %s/", in_path, out_dir);

		if (!split_file(in_path, out_dir, split_records, split_size_bytes,
					ns_filter, set_list, keys, out_total, out_written)) {
			err("Failed to split file: %s", in_path);
			all_ok = false;
		}

		cf_free(in_path);
	}

	for (uint32_t i = 0; i < file_list.size; i++) {
		cf_free(*(char **)as_vector_get(&file_list, i));
	}

	as_vector_destroy(&file_list);
	return all_ok;
}
