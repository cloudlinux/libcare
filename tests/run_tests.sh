#!/bin/sh

set -e

wait_file() {
	local file="$1"
	local pause="${2-1}"
	local i=0
	local timeout=60

	while test $i -lt $timeout; do
		if test -s $file; then
			break
		fi
		sleep $pause
		i=$((i + 1))
	done

	if test $i -eq $timeout; then
		return 1
	fi

	return 0
}

xsudo() {
	if [ "$(id -u)" = "0" ]; then
		"$@"
	else
		sudo "$@"
	fi
}

xrealpath() {
	if command -v realpath >/dev/null; then
		realpath $1;
	else
		readlink -f -- "$1"
	fi
}

run() {
	local cmd="$1"
	local outfile="$2"
	local pidfile=$(mktemp --tmpdir)

	$LIBCARE_CLIENT $SOCKPATH run "exec env $RUN_ARGS LD_PRELOAD=$LD_PRELOAD $cmd >$outfile 2>&1" >$pidfile
	read pid <$pidfile
	wait_file $outfile
	echo "pid=$pid"
}

kill_reap() {
	local pid=$1
	$LIBCARE_CLIENT $SOCKPATH kill $pid

	return 0

	if ! kill -0 $pid 2>/dev/null; then
		wait $pid 2>/dev/null
		return $?
	fi
	kill $pid
	local result=0
	if wait $pid 2>/dev/null; then
		result=$?
		if test $result -eq 143; then
			result=0
		fi
	fi
	return $result
}

libcare_ctl() {
	$TIME $LIBCARE_CLIENT $SOCKPATH "$@"
}

grep_tail() {
	tail -n2 $outfile | grep -qi "$@"
}


libcare_server_init() {
	SOCKPATH=$(mktemp --tmpdir -d)/test.sock
	SERVER_LOG=$(mktemp --tmpdir)
	stdbuf -o 0 $LIBCARE_CTL -v server $SOCKPATH \
		>$SERVER_LOG 2>&1 </dev/null & :
	SERVER_PID=$!
	sleep 1
	cat $SERVER_LOG
	kill -0 $SERVER_PID
	echo "SERVER_PID=$SERVER_PID"
}

libcare_server_fini() {
	kill $SERVER_PID
}

CHECK_RESULT=check_result
check_result() {
	local testname=$1
	outfile=$2
	case $testname in
		simplest)
			! grep_tail 'UNPATCHED'
			return $?
			;;
		fail_unpatch)
			grep_tail '\<PATCHED'
			return $?
			;;
		fail_*)
			grep_tail 'UNPATCHED'
			return $?
			;;
		ref_orig_threads)
			tail -n3 $outfile | grep -qi "thread2 (PATCHED)" && \
				tail -n3 $outfile | grep -qi "thread1 (UNPATCHED)"
			return $?
			;;
		both)
			grep_tail '\<PATCHED shared library' && \
				grep_tail '\<PATCHED binary'
			return $?
			;;
		*)
			grep_tail '\<PATCHED'
			return $?
			;;
	esac
}

test_patch_files_init() {
	export LD_PRELOAD=$PWD/fastsleep.so
}

test_patch_files() {
	local testname=$1
	local outfile=$2
	local logfile=$3

	local kpatch_file=$testname/$DESTDIR/${testname}.kpatch
	local kpatch_so_file=$testname/$DESTDIR/lib${testname}.so.kpatch

	run "LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$PWD/$testname/$DESTDIR/$testname" $outfile

	if test -f $kpatch_file; then
		libcare_ctl patch-user -p $pid $kpatch_file \
			>$logfile 2>&1 || :
	fi

	if test -f $kpatch_so_file; then
		libcare_ctl patch-user -p $pid $kpatch_so_file \
			>>$logfile 2>&1 || :
	fi

	sleep 3

	kill_reap $pid
}

test_patch_files_fini() {
	:
}


check_result_unpatch() {
	local testname="$1"
	local outfile="$2"

	check_result "$@"
	test $? -eq 0
	local is_unpatched=$?

	test "$(cat ${outfile}_patched)" -eq 1
	local was_patched=$?

	case $testname in
		fail_unpatch)
			test $is_unpatched -eq 0 && test $was_patched -eq 1
			;;
		*)
			test $is_unpatched -eq 1 && test $was_patched -eq 1
			;;
	esac
}

test_unpatch_files_init() {
	export LD_PRELOAD=$PWD/fastsleep.so
	CHECK_RESULT=check_result_unpatch
}

test_unpatch_files() {
	local testname=$1
	local outfile=$2
	local logfile=$3

	local kpatch_file=$testname/$DESTDIR/${testname}.kpatch
	local kpatch_so_file=$testname/$DESTDIR/lib${testname}.so.kpatch

	run "LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$testname/$DESTDIR/$testname" $outfile


	if test -f $kpatch_file; then
		libcare_ctl patch-user -p $pid $kpatch_file \
			>$logfile 2>&1 || :
	fi

	if test -f $kpatch_so_file; then
		libcare_ctl patch-user -p $pid $kpatch_so_file \
			>>$logfile 2>&1 || :
	fi

	sleep 3

	check_result $testname $outfile
	echo $? >${outfile}_patched
	cat ${outfile}_patched

	echo "============unpatching===============" >>$logfile
	libcare_ctl unpatch-user -p $pid \
		>>$logfile 2>&1 || :

	sleep 2

	kill_reap $pid
}

test_unpatch_files_fini() {
	:
}


test_patch_dir_init() {
	export LD_PRELOAD=$PWD/fastsleep.so
}

test_patch_dir() {
	local testname=$1
	local outfile=$2
	local logfile=$3

	local kpatch_dir=$testname/$DESTDIR

	run "LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$testname/$DESTDIR/$testname" $outfile

	libcare_ctl patch-user -p $pid $kpatch_dir >$logfile || :

	sleep 3

	kill_reap $pid
}

test_patch_dir_fini() {
	:
}


check_result_startup() {
	case "$1" in
		fail_coro|fail_busy_single*|fail_threading)
			grep -q '\<PATCHED' $2
			return $?
			;;
		fail_busy_threads)
			grep -q 'thread1 (UNPATCHED' $2 &&
				grep -q 'thread2 (PATCHED' $2
			return $?
			;;
	esac
	check_result "$@"
}

test_patch_startup_init_binfmt() {
	for tst in $tests; do
		echo "$PWD/$tst/$DESTDIR/$tst" | sed 's,/./,/,g; s,//,/,g' > \
			 /proc/ucare/applist
	done
	kcare_genl_sink_log=$(mktemp --tmpdir)
	xsudo ../binfmt/kcare_genl_sink "stdbuf -o 0 time \\
		$LIBCARE_CTL -v \\
		patch-user -p %pid -s $PATCHROOT >logfile 2>&1" \
			>$kcare_genl_sink_log 2>&1 & :
	SUDO_GENL_SINK_PID=$!
	sleep 1
	cat $kcare_genl_sink_log
	GENL_SINK_PID=$(awk '/My pid/ { print $NF }' $kcare_genl_sink_log)
	KILL_SUDO=1
}

test_patch_startup_init_execve() {
	make -C execve

	$LIBCARE_CLIENT $SOCKPATH storage "$PWD/$DESTDIR-patchroot"

	RUN_ARGS="KP_EXECVE_PATTERN=\"$PWD/*/$DESTDIR/*\" \
		  KP_EXECVE_PATTERN_PATHNAME=1 \
		  LIBCARE_CTL_UNIX=$SOCKPATH"
	LD_PRELOAD="$PWD/execve/execve.so"
}

GENL_SINK_PID=
test_patch_startup_init() {
	local tests="$1"
	CHECK_RESULT=check_result_startup
	if test -d /proc/ucare; then
		test_patch_startup_init_binfmt "$tests"
	else
		test_patch_startup_init_execve "$tests"
	fi
}

test_patch_startup() {
	local testname=$1
	local outfile=$2
	local logfile=$3

	run "LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$PWD/$testname/$DESTDIR/$testname" $outfile

	# Start up is patched automagically

	kill_reap $pid

	cat $SERVER_LOG > $logfile
	echo > $SERVER_LOG
}

test_patch_startup_fini() {
	if test -n "$GENL_SINK_PID"; then
		if test "$KILL_SUDO" -eq 0; then
			kill $GENL_SINK_PID || :
		else
			xsudo kill $GENL_SINK_PID || :
		fi
	fi
	if test -n "$SUDO_GENL_SINK_PID"; then
		wait $SUDO_GENL_SINK_PID 2>/dev/null || :
	fi
	rm -f logfile
	if test -f /proc/ucare/applist; then
		echo '-*' > /proc/ucare/applist
	fi
}

test_patch_startup_ld_linux_init() {
	if ! test -f /proc/ucare/applist; then
		echo "STARTUP LD REQUIRES UCARE MODULE"
		exit 0
	fi

	test_patch_startup_init
	local ld_path="$(xrealpath /lib64/ld-linux-x86-64.so.2)"
	echo "$ld_path" > /proc/ucare/applist
}

test_patch_startup_ld_linux() {
	local testname=$1
	local outfile=$2
	local logfile=$3

	# link logfile to the appropriate file
	ln -fs $logfile logfile

	run "LD_LIBRARY_PATH=$testname/$DESTDIR \
		$(command -v stdbuf) -o 0 \
		/lib64/ld-linux-x86-64.so.2 \
		$PWD/$testname/$DESTDIR/$testname" $outfile

	# Start up is patched automagically

	kill_reap $pid
}

test_patch_startup_ld_linux_fini() {
	test_patch_startup_fini
}


test_patch_patchlevel_init() {
	export LD_PRELOAD=$PWD/fastsleep.so
	CHECK_RESULT=check_result_patchlevel
}

_set_latest() {
	local storage=$1
	local patchlevel=$2
	for dir in $storage/*; do
		rm -f $dir/latest
		ln -fs $patchlevel $dir/latest
	done
}

test_patch_patchlevel() {
	local testname=$1
	local outfile=$2
	local logfile=$3

	run "LD_LIBRARY_PATH=$testname/build	\
		stdbuf -o 0 \
		$PWD/$testname/$DESTDIR/$testname" $outfile

	local kpatch_storage=$PWD/$testname/patchlevel-root

	_set_latest $kpatch_storage 1
	libcare_ctl patch-user -p $pid $kpatch_storage \
		>$logfile 2>&1 || :

	sleep 2

	_set_latest $kpatch_storage 2
	libcare_ctl patch-user -p $pid $kpatch_storage \
		>>$logfile 2>&1 || :

	sleep 2

	kill_reap $pid
}

check_result_patchlevel() {
	local testname=$1
	local outfile=$2

	if test $testname != "patchlevel"; then
		echo "UNKNOWN test for patchlevel flavor: $testname"
		return 1
	fi

	if ! grep -q "Hello from SEMIPATCHED shared library" $outfile; then
		return 1
	fi
	if ! grep -q "Welcome from SEMIPATCHED binary" $outfile; then
		return 1
	fi

	if ! grep -q "Hello from PATCHED shared library" $outfile; then
		return 1
	fi
	if ! grep -q "Welcome from PATCHED binary" $outfile; then
		return 1
	fi

	return 0
}

test_patch_patchlevel_fini() {
	:
}


show_log() {
	if test -n "$verbose"; then
		cat $1
	else
		tail -n2 $1
	fi
}

test_one() {
	local testname=$1
	local flavor=$2
	local outfile=$(mktemp --tmpdir)
	local logfile=$(mktemp --tmpdir)

	$flavor $testname $outfile $logfile

	local result=

	{
		set +e
		$CHECK_RESULT $testname $outfile
		result=$?
		set -e
	}

	if test $result -eq 0; then
		echo "TEST $testname IS OK"
		echo "binary output"
		show_log "$outfile"

		echo "libcare-ctl output"
		show_log "$logfile"

		rm -f "$outfile" "$logfile"
	else
		echo "TEST $testname FAILED"
		echo cat $logfile $outfile
		cat $logfile $outfile
	fi

	return $result
}


should_skip() {
	if test "$FLAVOR" = "test_patch_patchlevel"; then
		if test "$1" != "patchlevel"; then
			return 0;
		fi
	else
		if test "$1" = "patchlevel"; then
			return 0
		fi
	fi

	case "$1" in
	ifunc)
		if grep -q 'release 6' /etc/redhat-release 2>/dev/null; then
			return 0
		fi
		;;
	fail_busy_threads|fail_busy_single|fail_busy_single_top|fail_coro|\
	fail_threading|fail_coro_listed)
		if test "$FLAVOR" = "test_unpatch_files"; then
			return 0
		fi
		;;
	esac
	return 1
}

env_init() {
	TESTDIR=$(xrealpath $(dirname $0))
	KPTOOLS=${KPTOOLS-$TESTDIR/../src}
	LIBCARE_CTL=$KPTOOLS/libcare-ctl
	LIBCARE_CLIENT=$KPTOOLS/libcare-client
	STAGE=${STAGE-$TESTDIR/stage/tmp}

	TIME=$(which time)
}

main() {
	export SLEEP_MULT=100000000

	env_init

	DESTDIR=build
	FLAVOR=test_patch_files
	while getopts ":f:vqd:p:" opt "$@"; do
		case $opt in
			f)
				FLAVOR=$OPTARG
				;;
			d)
				DESTDIR="$OPTARG"
				;;
			p)
				PATCHROOT="$OPTARG"
				;;
			q)
				quiet=yes
				verbose=
				;;
			v)
				verbose=yes
				quiet=
				;;
			?)
				echo "Unknown option $opt"
				exit 1
				;;
			:)
				echo "Option -$opt requires an argument"
				exit 1
				;;
		esac
	done

	case $FLAVOR in
		test_patch_files|\
		test_patch_dir|\
		test_patch_startup|\
		test_patch_startup_ld_linux|\
		test_unpatch_files|\
		test_patch_patchlevel)
			;;
		*)
			echo "Unknown flavor $FLAVOR"
			exit 1
	esac

	PATCHROOT="${PATCHROOT-$PWD/$DESTDIR-patchroot}"

	shift $(($OPTIND - 1))

	ALL_TESTS="$(find -iname desc -o -iname desc_ |	\
			sed -e 's,/desc_\?$,,; s,^./,,')"
	TESTS="$@"
	if test -z "${TESTS}"; then
		TESTS="${ALL_TESTS}"
	fi

	# kill runaway test executables at exit
	trap 'tmpfile=$(mktemp);
	      jobs -p > $tmpfile;
	      while IFS= read -r pid; do kill $pid 2>/dev/null || :; done < $tmpfile;
	      rm -f $tmpfile;
	      exit' EXIT TERM INT

	nskipped=0
	nfailed=0
	nok=0
	ntotal=0

	FAILED=""

	libcare_server_init
	${FLAVOR}_init "$TESTS"
	for tst in $TESTS; do
		ntotal=$(($ntotal + 1))
		if should_skip $tst; then
			echo "SKIP: $tst"
			nskipped=$(($nskipped + 1))
			continue
		fi
		if ! test_one $tst $FLAVOR; then
			FAILED="${FAILED:+$FAILED }$tst"
			nfailed=$(($nfailed + 1))
		else
			nok=$(($nok + 1))
		fi
	done
	${FLAVOR}_fini
	libcare_server_fini

	echo "OK $nok FAIL $nfailed SKIP $nskipped TOTAL $ntotal"
	if test -n "$FAILED"; then
		echo "FAILED TESTS: $FAILED"
		exit 1
	fi
	exit 0
}

main "$@"
