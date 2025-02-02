!#/bin/bash

echo "what os is this?"
echo "1. linux-gnu"
echo "2. linux-musl"

read -p "enter: " response

case "$response" in
    [1]* ) echo "linux-gnu selected";;
    [2]* ) echo "linux-musl selected";;
    * ) echo "Invalid input. Please enter 1 or 2"; exit 1;;
esac

if [ "$response" == "1" ]; then
    echo "Moving binaries from linux-gnu"
    mv -f linux-gnu/all-distros/* /usr/bin
elif [ "$response" == "2" ]; then
    echo "Moving binaries from linux-musl"
    mv -f linux-musl/all-distros/* /usr/bin
else
    echo "Invalid input. Please enter 1 or 2."
    exit 1
fi

echo "Binaires have been moved successfully!"
