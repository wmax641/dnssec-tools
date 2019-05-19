#!/usr/bin/bash
# Full creds to the below for ridiculous idea:
#   https://shaunc.com/blog/article/generating-vanity-dnssec-key-tags~NvTJKAhLogni

ZONE="domain.name"
DESIRED_KEYTAG="1337"
ALGO=ECDSAP384SHA384
#ALGO=ECDSAP256SHA256
#ALGO=RSASHA256
STORE_DIR=`pwd`/store
FOUND_DIR=`pwd`/found
LOGFILE=`pwd`/"mine.log"

mkdir -p ${STORE_DIR}
mkdir -p ${FOUND_DIR}

date > ${LOGFILE}

while true; do
    # Try...
    for i in {1..50}; do
        FILE=$(dnssec-keygen -K ${STORE_DIR} -a ${ALGO} -f KSK ${ZONE})
        KEYTAG=$(echo "$FILE" | cut -f3 -d'+')

        # Found a substring
        if [[ $KEYTAG == *${DESIRED_KEYTAG}* ]]; then
            echo "Found - #${KEYTAG}"
            mv ${STORE_DIR}/${FILE}.key ${FOUND_DIR}
            mv ${STORE_DIR}/${FILE}.private ${FOUND_DIR}
        fi
        echo ${KEYTAG} >> ${LOGFILE}
    done

    # Clean up and relax
    echo "Cleaning up and relaxing a bit"
    rm -f ${STORE_DIR}/*.key ${STORE_DIR}/*.private
    sleep 2
done

