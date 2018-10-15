#!/bin/sh

PYTHON="/opt/python"
MAL_DNS="./dns/run_mal_dns.py"
MAL_IP="./ip/"

ARG_ACTION=${1}

declare -A run_dict
run_dict=(["mal_dns"]=${MAL_DNS} ["mal_ip"]=${MAL_IP})

function get_pid() {
	echo `ps -ef|grep ${run_dict[${1}]}|grep -v grep|awk '{print $2}'`
}

function check_status() {
	pid=`get_pid ${1}`
	if [ "x${pid}" = "x" ];then
		echo "$1 is already stopped."
	else
		echo "$1 [PID:${pid}] is running."
	fi
}

function start_module() {
	pid=`get_pid ${1}`
	
	if [ "x${pid}" != "x" ];then
		echo "$1 [PID:${pid}] is already running."
		return
	fi

	if [ ! -f "${PYTHON}" ];then
		echo "ERROR: Python '${PYTHON}' not found."
		return
	fi

	cmd="${PYTHON} ${run_dict[${1}]}"

	printf "Start ${1} ...\r"
	${cmd} 1>/dev/null 2>&1 &
	sleep 1

	pid=`get_pid ${1}`
	if [ "x${pid}" = "x" ];then
		echo "Start ${1} ... failed."
	else
		echo "Start ${1} ... done. [PID: ${pid}]"
	fi
}

function stop_module() {
	oldpid=`get_pid ${1}`
	
	if [ "x${oldpid}" = "x" ]; then
		echo "${1} is already stopped."
	fi

	cmd="kill ${oldpid}"
	
	printf "Stop ${1} ...\r"
	${cmd}
	sleep 1
	
	newpid=`get_pid ${1}`
	if [ "x${newpid}" = "x" ]; then
		echo "Stop ${1} [PID: ${oldpid}] ... done."
	else
		echo "Stop ${1} [PID: ${oldpid}] ... failed. "
	fi
}

function main() {
	case "x${ARG_ACTION}" in 
		"xstart")
			for key in $(echo ${!run_dict[*]});do
				start_module ${key}
			done
		;;

		"xstop")
			for key in $(echo ${!run_dict[*]});do
				stop_module ${key}
			done
		;;

		"xrestart")
			for key in $(echo ${!run_dict[*]});do
				stop_module ${key}
			done

			sleep 1
			printf "\r"			

			for key in $(echo ${!run_dict[*]});do
				start_module ${key}
			done
		;;
		
		"xstatus")
			for key in $(echo ${!run_dict[*]});do
				check_status ${key}
			done
		;;

		"x")
			echo "ERROR: Missing action."
		;;
		
		*)
			echo "ERROR: Unknown action '${ARG_ACTION}'."
		;;
	esac
}

main
