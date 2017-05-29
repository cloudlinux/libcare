#!/usr/bin/awk -f

/Section Headers/,/Key to Flags/ {
	gsub("\\[|\\]", "");
	shnum = strtonum($1)
	if (shnum != 0) {
		name = $2;
		sectionsname[shnum] = name;
		if (name ~ /kpatch/) {
			sections[shnum] = -1;
		} else {
			addr = $4;
			sections[shnum] = strtonum("0x"addr);
		}
	}
}

function skip_symbol(name)
{
	return (name ~ /^__/) || (name ~ /^[[:alnum:]_]+\.[[:digit:]]+$/) ||
	       (name ~ /^_L_(robust_)?(cond_)?(timed)?(un)?lock/) ||
	       (name ~ /^\.L/);
}

/.symtab/,!/./ {
	value = strtonum("0x"$2);
	size = strtonum($3);
	type = $4;
	shnum = $7;
	name = $8;
	if (value != 0 && (type == "FUNC" || type == "OBJECT") &&
	    !skip_symbol(name) && sections[shnum] != -1) {
		printf "%016x %-16s %016x %s\n", value - sections[shnum], sectionsname[shnum], size, name;
	}
}
