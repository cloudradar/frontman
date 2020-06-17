#!/bin/sh

APIKEY=$1
FILE=$2

if [ ! -e $FILE ]; then
    echo $FILE dont exist
    exit 1
fi

# Post file to virustotal and wait for result
curl -fSs --request POST \
  --url 'https://www.virustotal.com/vtapi/v2/file/scan' \
  --form "apikey=$APIKEY" \
  --form "file=@$FILE" > job.json

jq < job.json
SCANID=$(jq -r .scan_id < job.json)
echo "Upload finished. Got SCAN ID $SCANID. Waiting for results .... "
sleep 10
for LOOP in {1..20}; do
    curl -fSs --request GET \
    --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=$APIKEY&resource=$SCANID" > result.json
    RESPONSECODE=$(jq -r .response_code < result.json)
    if [ $RESPONSECODE -eq 1 ]; then
        AV_POSITIVES=$(jq .positives < result.json)
        echo "virustotal reported $AV_POSITIVES positive matches"

        if [ "$AV_POSITIVES" -gt "1" ];then
            jq . < result.json
            echo "ERROR: vistutoal found too many positives"
            exit 1
        fi

        exit 0
    else
        echo "Try $LOOP: Scan not finished. Waiting."
        cat result.json
        sleep 10
    fi
done

echo "Giving up. No result could be fetched."
exit 1
