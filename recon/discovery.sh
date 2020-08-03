SUBNET=$(echo $1 | grep -Eo "^[0-9]+.[0-9]+.[0-9]+")
CHECK_MARK="\033[0;32m\xE2\x9C\x94\033[0m"

if [[ -z $SUBNET ]]
then
	echo "Usage: ./discovery.sh <ip range>"
	exit 1
fi

if [[ $EUID -ne 0 ]]
then
	echo "Checking root permissions..."
	sudo ls > /dev/null
fi

echo -e "\n\e[4mChecking Hosts...\e[0m"
for i in {1..254}
do
	IP="$SUBNET.$i"
	echo -ne "Trying IP $IP ... \r"
	host $IP > /dev/null
	if [[ $? -eq 0 ]]
	then
		echo -ne "${CHECK_MARK} $IP "
		HOSTNAME=$(host $IP | awk '{print $NF}')
		echo -ne "$HOSTNAME "
		sudo ping -c 1 $IP > /dev/null
		if [[ $? -eq 0 ]]
		then
			echo -e "Ping: \e[32mUP\e[39m"
		else
			echo -e "Ping: \e[31mDOWN\e[39m"
		fi
	fi
done
echo -e "\033[2K"
