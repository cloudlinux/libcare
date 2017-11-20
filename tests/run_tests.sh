#!/bin/sh

set -e

TESTDIR=$(realpath $(dirname $0))
KPTOOLS=${KPTOOLS-$TESTDIR/../src}
LIBCARE_DOCTOR=$KPTOOLS/libcare-ctl
STAGE=${STAGE-$TESTDIR/stage/tmp}

TIME=$(which time)

wait_file() {
	while ! test -s $1; do sleep ${2-1}; done
	return 0
}

xsudo() {
	if [ "$(id -u)" = "0" ]; then
		"$@"
	else
		sudo "$@"
	fi
}

have_ptrace_permissions() {
	local PTRACE_SCOPE=/proc/sys/kernel/yama/ptrace_scope
	test $(id -u) -eq 0 && return 0
	test -n "$(find $LIBCARE_DOCTOR -perm /6000 -uid 0)" && return 0
	test -f $PTRACE_SCOPE && grep -q 1 $PTRACE_SCOPE && \
		test -z "$(getcap $LIBCARE_DOCTOR | grep cap_sys_ptrace)" &&
		return 1
	return 0
}

assert_ptrace_permissions() {

	if have_ptrace_permissions; then
		return
	fi

	cat <<EOF
Not enough permissions for kpatch.

Either run as root, or enable ptrace either globally or by
\`sudo setcap cap_sys_ptrace+ep $LIBCARE_DOCTOR\`.
EOF
	exit 1
}

kill_reap() {
	local pid=$1
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

grep_tail() {
	tail -n2 $outfile | grep -qi "$@"
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

	LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$PWD/$testname/$DESTDIR/$testname >$outfile 2>&1 & :
	local pid=$!
	wait_file $outfile

	if test -f $kpatch_file; then
		$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_file \
			>$logfile 2>&1 || :
	fi

	if test -f $kpatch_so_file; then
		$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_so_file \
			>>$logfile 2>&1 || :
	fi

	sleep 3

	kill_reap $pid
}

test_patch_files_fini() {
	:
}


check_result_unpatch() {
	local outfile="$2"
	check_result "$@"
	test $? -ne "$(cat ${outfile}_patched)"
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

	LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$testname/$DESTDIR/$testname >$outfile 2>&1 & :
	local pid=$!
	wait_file $outfile


	if test -f $kpatch_file; then
		$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_file \
			>$logfile 2>&1 || :
	fi

	if test -f $kpatch_so_file; then
		$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_so_file \
			>>$logfile 2>&1 || :
	fi

	sleep 1

	check_result $testname $outfile
	echo $? >${outfile}_patched

	$TIME $LIBCARE_DOCTOR -v unpatch-user -p $pid \
		>$logfile 2>&1 || :

	sleep 1

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

	LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$testname/$DESTDIR/$testname >$outfile 2>&1 & :
	local pid=$!
	wait_file $outfile

	$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_dir \
	>$logfile 2>&1 || :

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
		$LIBCARE_DOCTOR -v \\
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

	export KP_EXECVE_PATTERN="$PWD/*/$DESTDIR/*"
	export KP_EXECVE_PATTERN_PATHNAME=1
	export LD_PRELOAD="$PWD/execve/execve.so"
	export PATCH_ROOT="$PWD/$DESTDIR-patchroot"

	kcare_genl_sink_log=$(mktemp --tmpdir)
	./execve/listener >$kcare_genl_sink_log 2>&1 & :
	GENL_SINK_PID=$!
	KILL_SUDO=0
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

	# link logfile to the appropriate file
	ln -fs $logfile logfile

	LD_LIBRARY_PATH=$testname/$DESTDIR \
		stdbuf -o 0 \
		$PWD/$testname/$DESTDIR/$testname >$outfile 2>&1 & :
	local pid=$!
	wait_file $outfile

	# Start up is patched automagically

	kill_reap $pid
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

xrealpath() {
	if command -v realpath >/dev/null; then
		realpath $1;
	else
		local p=$1
		local n=
		while test -L $p; do
			n="$(ls -l $p | sed 's/.*-> //g')"
			if test -n "${n##/*}"; then # relative path
				n="$(dirname $p)/$n"
			fi
			p=$n
		done
		n="$(dirname $p)"
		p="$(basename $p)"
		if test "$n" != "/"; then
			n="$(xrealpath $n)"
		else
			n=""
		fi
		echo $n/$p
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

	LD_LIBRARY_PATH=$testname/$DESTDIR \
		$(command -v stdbuf) -o 0 \
		/lib64/ld-linux-x86-64.so.2 \
		$PWD/$testname/$DESTDIR/$testname >$outfile 2>&1 & :

	local pid=$!
	wait_file $outfile

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

	LD_LIBRARY_PATH=$testname/build	\
		stdbuf -o 0 \
		$PWD/$testname/$DESTDIR/$testname >$outfile 2>&1 & :

	local pid=$!
	wait_file $outfile

	local kpatch_storage=$PWD/$testname/patchlevel-root

	_set_latest $kpatch_storage 1
	$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_storage \
		>$logfile 2>&1 || :

	sleep 2

	_set_latest $kpatch_storage 2
	$TIME $LIBCARE_DOCTOR -v patch-user -p $pid $kpatch_storage \
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


main() {
	assert_ptrace_permissions

	export SLEEP_MULT=100000000

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
	      rm -f $tmpfile' 0

	nskipped=0
	nfailed=0
	nok=0
	ntotal=0

	FAILED=""

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

	echo "OK $nok FAIL $nfailed SKIP $nskipped TOTAL $ntotal"
	if test -n "$FAILED"; then
		echo "FAILED TESTS: $FAILED"
		exit 1
	fi
	exit 0
}

main "$@"
