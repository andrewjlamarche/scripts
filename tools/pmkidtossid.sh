if [[ -z $1 ]]
then
        echo "Usage: ./pmkidtossid.sh <pmkid file>"
        exit 1
fi

if ! [[ -f $1 ]]
then
        echo "PMKID file does not exist"
        exit 1
fi

if ! [[ -s $1 ]]
then
        echo "PMKID file empty"
        exit 1
fi

PMKIDS=$(cat $1 2>/dev/null)
CHECK_MARK="\033[0;32m\xE2\x9C\x94\033[0m"
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "\n\e[4mConverting...\e[0m"
for pmkid in $PMKIDS
do
        conv=$(echo $pmkid | rev | cut -d "*" -f 4 | rev | xxd -r -p)
        echo -e "${CHECK_MARK} $pmkid:${GREEN}"$conv${NC}
done
