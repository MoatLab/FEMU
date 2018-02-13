

DEF("bench", img_bench,
"bench [-c count] [-d depth] [-f fmt] [--flush-interval=flush_interval] [-n] [--no-drain] [-o offset] [--pattern=pattern] [-q] [-s buffer_size] [-S step_size] [-t cache] [-w] filename")

DEF("check", img_check,
"check [-q] [--object objectdef] [--image-opts] [-f fmt] [--output=ofmt] [-r [leaks | all]] [-T src_cache] filename")

DEF("create", img_create,
"create [-q] [--object objectdef] [-f fmt] [-o options] filename [size]")

DEF("commit", img_commit,
"commit [-q] [--object objectdef] [--image-opts] [-f fmt] [-t cache] [-b base] [-d] [-p] filename")

DEF("compare", img_compare,
"compare [--object objectdef] [--image-opts] [-f fmt] [-F fmt] [-T src_cache] [-p] [-q] [-s] filename1 filename2")

DEF("convert", img_convert,
"convert [--object objectdef] [--image-opts] [-c] [-p] [-q] [-n] [-f fmt] [-t cache] [-T src_cache] [-O output_fmt] [-o options] [-s snapshot_id_or_name] [-l snapshot_param] [-S sparse_size] [-m num_coroutines] [-W] filename [filename2 [...]] output_filename")

DEF("dd", img_dd,
"dd [--image-opts] [-f fmt] [-O output_fmt] [bs=block_size] [count=blocks] [skip=blocks] if=input of=output")

DEF("info", img_info,
"info [--object objectdef] [--image-opts] [-f fmt] [--output=ofmt] [--backing-chain] filename")

DEF("map", img_map,
"map [--object objectdef] [--image-opts] [-f fmt] [--output=ofmt] filename")

DEF("snapshot", img_snapshot,
"snapshot [--object objectdef] [--image-opts] [-q] [-l | -a snapshot | -c snapshot | -d snapshot] filename")

DEF("rebase", img_rebase,
"rebase [--object objectdef] [--image-opts] [-q] [-f fmt] [-t cache] [-T src_cache] [-p] [-u] -b backing_file [-F backing_fmt] filename")

DEF("resize", img_resize,
"resize [--object objectdef] [--image-opts] [-q] filename [+ | -]size")

DEF("amend", img_amend,
"amend [--object objectdef] [--image-opts] [-p] [-q] [-f fmt] [-t cache] -o options filename")
