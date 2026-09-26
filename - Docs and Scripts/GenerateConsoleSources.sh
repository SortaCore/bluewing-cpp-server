#!/usr/bin/env bash
set -euo pipefail

# Requires Bash 3.2 or newer. This deliberately avoids Perl, sed-specific
# extensions, associative arrays, mapfile, and other Bash 4+ features.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
input_path=${1:-"$repo_dir/GenericConsole.cpp"}
output_dir=${2:-"$repo_dir"}
debug_output=${DEBUG_OUTPUT:-0}

mkdir -p -- "$output_dir"

fail() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

info() {
	if [[ $debug_output == 1 ]]; then
		printf '%s\n' "$1"
	fi
}

read_file() {
	local path=$1 sentinel
	sentinel=$'\034'
	# The sentinel prevents command substitution from stripping trailing LF.
	REPLY=$(command cat -- "$path"; printf '%s' "$sentinel") ||
		fail "Cannot read \"$path\"."
	REPLY=${REPLY%"$sentinel"}
}

write_read_only() {
	local path=$1 contents=$2 windows_path
	if [[ -e $path ]]; then
		case ${OSTYPE-} in
			msys*|cygwin*)
				windows_path=$(cygpath -aw "$path")
				attrib.exe -R "$windows_path" >/dev/null ||
					fail "Cannot make \"$path\" writable."
				;;
			*) chmod u+w -- "$path" || fail "Cannot make \"$path\" writable." ;;
		esac
		rm -f -- "$path" || fail "Cannot remove \"$path\"."
	fi
	printf '%s' "$contents" > "$path" || fail "Cannot write \"$path\"."
	case ${OSTYPE-} in
		msys*|cygwin*)
			windows_path=$(cygpath -aw "$path")
			attrib.exe +R "$windows_path" >/dev/null ||
				fail "Cannot mark \"$path\" read-only."
			;;
		*) chmod a-w -- "$path" || fail "Cannot mark \"$path\" read-only." ;;
	esac
}

check_output_age() {
	local output_path=$1
	if [[ -e $output_path && $output_path -nt $input_path ]]; then
		fail "Aborting generic to specific script, output file \"${output_path##*/}\" modified later than input \"${input_path##*/}\"."
	fi
}

replace_literal() {
	local contents=$1 needle=$2 replacement=$3
	REPLY=${contents//"$needle"/"$replacement"}
}

prefix_ternary_literals() {
	local value=$1 prefix=$2 output='' before quote_number=0
	[[ $value != *'\"'* ]] || fail 'backslash quote in ternary'
	while [[ $value == *'"'* ]]; do
		before=${value%%'"'*}
		value=${value#*'"'}
		output+=$before
		((quote_number += 1))
		if (( quote_number % 2 == 1 )); then
			output+=$prefix
		fi
		output+='"'
	done
	REPLY=$output$value
}

transform_streams() {
	local contents=$1 prefix=$2 output='' scan before name rest
	local operator value transformed statement=0 operand_count=0
	local stream_regex='(std::w?cout|lastTimeAndStatsSS)'
	local operand_regex='^([[:space:]]*<<[[:space:]]*)([^;<]+)'

	scan=$contents
	while [[ $scan =~ $stream_regex ]]; do
		name=${BASH_REMATCH[1]}
		before=${scan%%"$name"*}
		rest=${scan#*"$name"}
		output+=$before
		transformed=$name
		operand_count=0

		while [[ $rest =~ $operand_regex ]]; do
			operator=${BASH_REMATCH[1]}
			value=${BASH_REMATCH[2]}
			rest=${rest:${#BASH_REMATCH[0]}}

			if [[ $value == '"'* || $value == "'"* ]]; then
				value=$prefix$value
			fi
			if [[ $value == '('* && $value == *'?'* ]]; then
				prefix_ternary_literals "$value" "$prefix"
				value=$REPLY
			fi
			transformed+=$operator$value
			((operand_count += 1))
		done

		if (( operand_count > 0 )) && [[ $rest == ';'* ]]; then
			output+=$transformed';'
			scan=${rest:1}
			((statement += 1))
		else
			# This occurrence was not a complete stream insertion expression.
			output+=$name
			scan=$rest
		fi
	done
	REPLY=$output$scan
	STREAM_STATEMENTS=$statement
}

replace_macro() {
	local contents=$1 macro=$2 prefix=$3 wide=$4
	local output='' scan before whole argument replacement
	local regex="${macro}\\(([^)]*)\\)"

	scan=$contents
	while [[ $scan =~ $regex ]]; do
		whole=${BASH_REMATCH[0]}
		argument=${BASH_REMATCH[1]}
		before=${scan%%"$whole"*}
		case $macro in
			TXT) replacement=$prefix$argument ;;
			u8_lw)
				if (( wide )); then replacement="UTF8ToWide($argument)"; else replacement=$argument; fi
				;;
			lw_u8)
				if (( wide )); then replacement="WideToUTF8($argument)"; else replacement=$argument; fi
				;;
		esac
		output+=$before$replacement
		scan=${scan#*"$whole"}
	done
	REPLY=$output$scan
}

replace_preproc() {
	local contents=$1 symbol=$2 symbol_true=$3 output='' line clean
	local depth=0 active=1 parent_active=1 condition=0 found_else=0
	local if_count=0 endif_count=0 selected_any=0 local_index=0 post_endif=0
	local if_regex="^[[:space:]]*#[[:space:]]*if(n?)(def)?[[:space:]]+(!?)${symbol}[[:space:]]*$"
	local else_regex="^[[:space:]]*#[[:space:]]*else[[:space:]]*//[[:space:]]*!${symbol}[[:space:]]*$"
	local endif_regex="^[[:space:]]*#[[:space:]]*endif[[:space:]]*//[[:space:]]*!?${symbol}[[:space:]]*$"
	local -a active_stack parent_stack condition_stack else_stack selected_stack

	while IFS= read -r line; do
		clean=${line%$'\r'}
		if (( post_endif )); then
			if [[ $clean =~ ^[[:space:]]*$ ]]; then
				# The C# regex consumes a whitespace-only line immediately
				# following the target #endif and recreates it without tabs.
				if (( post_endif == 2 )); then output+=$'\n'; fi
				post_endif=0
				continue
			fi
			post_endif=0
		fi
		if [[ $clean =~ $if_regex ]]; then
			((if_count += 1))
			active_stack[$depth]=$active
			parent_stack[$depth]=$active
			condition=$symbol_true
			if [[ ${BASH_REMATCH[1]} == n || ${BASH_REMATCH[3]} == '!' ]]; then
				if (( condition )); then condition=0; else condition=1; fi
			fi
			condition_stack[$depth]=$condition
			else_stack[$depth]=0
			selected_stack[$depth]=0
			parent_active=$active
			active=$(( parent_active && condition ))
			((depth += 1))
			continue
		fi

		if (( depth > 0 )) && [[ $clean =~ $else_regex ]]; then
			local_index=$((depth - 1))
			found_else=${else_stack[$local_index]}
			(( found_else == 0 )) || fail "Duplicate #else for $symbol."
			else_stack[$local_index]=1
			parent_active=${parent_stack[$local_index]}
			condition=${condition_stack[$local_index]}
			active=$(( parent_active && ! condition ))
			continue
		fi

		if [[ $clean =~ $endif_regex ]]; then
			((endif_count += 1))
			(( depth > 0 )) || fail "Too many #endif $symbol ($endif_count) without enough #if(def) $symbol ($if_count)."
			local_index=$((depth - 1))
			found_else=${else_stack[$local_index]}
			selected_any=${selected_stack[$local_index]}
			active=${active_stack[$local_index]}
			depth=$((depth - 1))
			# Match the C# task's deliberate blank result for a false block
			# that has no #else section.
			if (( active && ! found_else && ! selected_any )); then
				output+=$'\n'
				post_endif=1
			elif (( active )); then
				post_endif=2
			fi
			continue
		fi

		if (( active )); then
			output+=$line$'\n'
			if (( depth > 0 )); then
				local_index=$((depth - 1))
				selected_stack[$local_index]=1
			fi
		fi
	done < <(printf '%s' "$contents")

	(( depth == 0 )) || fail "Too many #if(def) $symbol ($if_count) without enough #endif $symbol ($endif_count)."
	(( if_count > 0 )) || fail "regex broken for detecting #ifdef $symbol (none found)."
	(( endif_count <= if_count )) || fail "Too many #endif $symbol ($endif_count) without enough #if(def) $symbol ($if_count)."
	REPLY=$output
}

generate_variant() {
	local output_name=$1 windows=$2 utf8=$3 wide=$4
	local output_path=$output_dir/$output_name prefix contents
	check_output_age "$output_path"
	(( ! (utf8 && wide) )) || fail 'Both UTF-8 and Wide specified; only one must be.'

	read_file "$input_path"
	contents=$REPLY
	if (( ! utf8 && ! wide )); then
		write_read_only "$output_path" "$contents"
		return
	fi

	if (( utf8 )); then prefix=u8; else prefix=L; fi
	transform_streams "$contents" "$prefix"
	contents=$REPLY
	(( STREAM_STATEMENTS > 0 )) || fail 'No string literal matches found.'

	if (( wide )); then
		replace_literal "$contents" 'std::cout' 'std::wcout'; contents=$REPLY
		replace_literal "$contents" 'std::cin' 'std::wcin'; contents=$REPLY
	fi

	replace_literal "$contents" 'GetPortFromInput("' "GetPortFromInput(${prefix}\""; contents=$REPLY
	if (( wide )); then
		replace_literal "$contents" '!strcasecmp(argv[i], "' "!_wcsicmp(argv[i], ${prefix}\""; contents=$REPLY
		replace_literal "$contents" 'int main(' 'int wmain('; contents=$REPLY
		replace_literal "$contents" 'std::strtoul(' 'std::wcstoul('; contents=$REPLY
		replace_literal "$contents" 'std::to_string(' 'std::to_wstring('; contents=$REPLY
		replace_literal "$contents" 'sprintf(' '_stprintf_s('; contents=$REPLY
	elif (( windows )); then
		replace_literal "$contents" '!strcasecmp(argv[i], "' "!_stricmp(argv[i], ${prefix}\""; contents=$REPLY
	fi

	replace_preproc "$contents" '_WIN32' "$windows"; contents=$REPLY
	replace_preproc "$contents" 'lw_utf8_console' "$utf8"; contents=$REPLY
	replace_macro "$contents" 'TXT' "$prefix" "$wide"; contents=$REPLY
	replace_macro "$contents" 'u8_lw' "$prefix" "$wide"; contents=$REPLY
	replace_macro "$contents" 'lw_u8' "$prefix" "$wide"; contents=$REPLY

	write_read_only "$output_path" "$contents"
	info "Wrote to \"$output_path\" successfully."
}

generate_variant 'WindowsUTF8Console.cpp' 1 1 0
generate_variant 'LinuxConsole.cpp'       0 1 0
generate_variant 'WindowsWideConsole.cpp' 1 0 1
