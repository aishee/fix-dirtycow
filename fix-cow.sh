#!/bin/bash
set -e -u

_atexit=("true")

function push_atexit {
    _atexit=($# "$@" "${_atexit[@]}")
}

function pop_atexit {
    local nargs=${_atexit[0]}
    "${_atexit[@]:1:$nargs}"
    _atexit=("${_atexit[@]:$((1+$nargs))}")
}

function prepend_trap {
    local new_cmd="$1" event="$2"
    local cmd="$(trap -p $event)"
    if [ "$cmd" ]; then
        cmd="${cmd:0:8}$(printf %q "${new_cmd}")';'${cmd:8}"
    else
        cmd="trap -- $(printf %q "${new_cmd}") $event"
    fi
    eval "$cmd"
}

function atexit {
    push_atexit "$@"
    prepend_trap pop_atexit EXIT
}

check_vmlinux()
{
        # Use readelf to check if it's a valid ELF
        # TODO: find a better to way to check that it's really vmlinux
        #       and not just an elf
        readelf -h $1 > /dev/null 2>&1 || return 1

        cat $1 > $VMLINUX
        exit 0
}

try_decompress()
{
        # The obscure use of the "tr" filter is to work around older versions of
        # "grep" that report the byte offset of the line instead of the pattern.

        # Try to find the header ($1) and decompress from here
        for     pos in `tr "$1\n$2" "\n$2=" < "$KRNL" | grep -abo "^$2"`
        do
                pos=${pos%%:*}
                tail -c+$pos "$KRNL" | $3 > $TMP 2> /dev/null
                check_vmlinux $TMP && break
        done
}

KRNL=${1:-/boot/vmlinuz-$(uname -r)}
KV=${2:-${KRNL##*/}}
KV=${KV##vmlinuz-}

[ "$(uname -sm)" = "Linux x86_64" ] || { echo "$0: this patch requires Linux x86_64." >&2; exit 1; }

if [[ $KV < 3.16 ]]; then
	echo "$0: this patch requires kernel 3.16+." >&2
	exit 1
fi

if test -d /sys/module/cowcleaner; then
	echo "$0: cowcleaner kernel module is already active." >&2
	exit 1
fi

test -f "$KRNL" || { echo "Usage: $0 /path/to/vmlinuz [version]" >&2; exit 1; }

if ! test -f cowcleaner.ko; then
        echo "$0: building cowcleaner.ko"
        make
fi

TMP=$(mktemp decompress.XXXXXX.img)
atexit rm -f $TMP

VMLINUX=$(mktemp vmlinux.XXXXXX.o)
atexit rm -f $VMLINUX

echo "Analyzing $KRNL, KV=$KV…"

(
set +e
# Initial attempt for uncompressed images or objects:
check_vmlinux $KRNL || true

# That didnt work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
)

SMAP=$(mktemp smap.XXXXXX.sym)
atexit rm -f $SMAP

if test -r /boot/System.map-$KV; then
	cat /boot/System.map-$KV | sort > $SMAP
else
	if test -e /proc/sys/kernel/kptr_restrict; then
		kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict)
		echo 0 > /proc/sys/kernel/kptr_restrict
	fi
	cat /proc/kallsyms | sort > $SMAP
	if test -e /proc/sys/kernel/kptr_restrict; then
		echo "$kptr_restrict" > /proc/sys/kernel/kptr_restrict
	fi
fi

[ "$(grep -vc '^0000000000000000' $SMAP)" = 0 ] && { echo "$0: cannot get symbols for $KV, exiting.">&2; exit 1; }

lookup() {
	grep -A1 " [tT] $1\$" $SMAP | awk '{print $1}' | xargs
}

ptr=
for sym in follow_page_pte follow_page_mask __get_user_pages; do
	ptr=$(lookup $sym)
	if [ -n "$ptr" ]; then
		echo "Found $sym at 0x${ptr% *}!"
		break
	else
		echo "No $sym found, possibliy inlined by the compiler."
	fi
done
[ -z "$ptr" ] && { echo "$0: cannot resolve all needed symbols." >&2; exit 1; }

vm_normal_page=$(lookup vm_normal_page | cut -d' ' -f1)
[ -z "$vm_normal_page" ] && { echo "$0: cannot resolve vm_normal_page." >&2; exit 1; }

FUNCS=$(mktemp func.XXXXXX.S)
atexit rm -f $FUNCS

__get_user_pages=$(lookup __get_user_pages)
[ -z "$__get_user_pages" ] && { echo "$0: cannot resolve __get_user_pages." >&2; exit 1; }

GUPS=$(mktemp gups.XXXXXX.S)
atexit rm -f $GUPS

objdump -d --start-address=0x${ptr% *} --stop-address=0x${ptr#* } $VMLINUX | sed -e "s/0x$vm_normal_page/vm_normal_page/g" > $FUNCS
if grep -q 0x4010 $FUNCS; then
	echo "Congratulations, your kernel seems to be already patched against dirty cow." >&2
	exit 0
fi

objdump -d --start-address=0x${__get_user_pages% *} --stop-address=0x${__get_user_pages#* } $VMLINUX | sed -e "s/0x$vm_normal_page/vm_normal_page/g" > $GUPS

OPS=$(grep -m1 'test\s*\$0x8,%al' $GUPS -A6 | cut -d $'\t' -f3 | cut -d' ' -f1 | xargs)

if [ "$OPS" = "test je mov and testb cmove jmpq" ]; then
	t=$(grep -m1 'test\s*\$0x8,%al' $GUPS | cut -d: -f1)
	echo "Found faultin_page last conditional branch at 0x$t."
elif [ "$OPS" = "test je mov or testb cmove jmpq" ]; then
	echo "Congratulations, your kernel seems to be already patched against dirty cow." >&2
	exit 0
else
	echo "Cannot find a specific sequence inside __get_user_pages." >&2
	exit 1
fi

e=$(grep '\scallq\s*vm_normal_page' -B10 $FUNCS | tac | sed -e 1d -e 's/:/ /' | awk '/\smov/ { entry=$1; next } { print entry; exit }')

if [ -n "$e" ]; then
	echo "L64: page = vm_normal_page(vma, address, pte); is at 0x$e."
else
	echo "Cannot find page = vm_normal_page(vma, address, pte);" >&2
	exit 1
fi

echo "Calculating L64 xrefs…"
x=$(sed "1,/^$e:/p" -n $FUNCS | grep "0x$e\$" | tail -n1)

if [ -n "$x" ]; then
	echo "XREF $x"
else
	echo "Cannot locate xrefs to L64." >&2
	exit 1
fi

x=$(echo "$x" | cut -d: -f1)
echo "Scanning $x..$e for conditional branches"
JE=$(sed "/^$x:/,/^$e:/p" -n $FUNCS | sed -e 1d | grep '\sje ') ||:
inline=$(grep "^$x:" -A1 $FUNCS | tail -n 1 | cut -d: -f1)

if [ -z "$JE" ]; then
	echo "0x$x seems to be an inlined form of pte_unmap_unlock(ptep, ptl);"
	echo "Testing for XREFs to 0x$x, just to be sure no-one gets hurt…"
	if grep 0x$x $FUNCS; then
		echo "Sorry, there was a reference. Stopping just to be safe." >&2
		exit 1
	fi
	insmod cowcleaner.ko ptr_inline=$((0x$inline)) ptr_marker=$((0x$t)) ptr_l64=$((0x$e))
else
	echo "0x$x calls L149 with a weak condition. Redirecting…"
        insmod cowcleaner.ko ptr_redirect=$((0x${JE%:*})) ptr_marker=$((0x$t)) ptr_l64=$((0x$e))
fi
