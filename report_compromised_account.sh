#!/bin/bash

# The following shell variables are set by the Policy server when
# this script is called and can be used in the message being sent.
#
#	"request": "smtpd_access_policy",
#	"protocol_state": "RCPT",
#	"protocol_name": "ESMTP",
#	"client_address": "<remote IP address>",
#	"client_name": "<reverse DNS name>",
#	"client_port": "<client TCP port>",
#	"reverse_client_name": "<reverse DNS name>",
#	"server_address": "<local IP address>",
#	"server_port": "<local TCP port e.g. 25>",
#	"helo_name": "<helo name>",
#	"sender": "<envelope sender>",
#	"recipient": "<envelope recipient>",
#	"recipient_count": "0",
#	"queue_id": "",
#	"instance": "<instance ID from Postfix>",
#	"size": "0",
#   "etrn_domain": "",
#	"stress": "",
#	"sasl_method": "<authentication method used>",
#	"sasl_username": "<authenticated username>",
#	"sasl_sender": "",
#	"ccert_subject": "",
#	"ccert_issuer": "",
#	"ccert_fingerprint": "",
#	"ccert_pubkey_fingerprint": "",
#	"encryption_protocol": "<encrypton protocol used>",
#	"encryption_cipher": "<encryption cipher used>",
#	"encryption_keysize": "<encrypton keysize used>",
#	"policy_context": ""

SUBJECT="New compromised account: ${sasl_username}"
TO=""

if [ -z "$TO" ]; then
    echo "You need to set TO=\"your@email.address\" to use this script"
    exit 1
fi

mail -s "$SUBJECT" "$TO" <<EOF
New compromised account detected!

${sasl_username} 

Remote IP: ${client_address} (${client_name}) (${reverse_client_name})
HELO: ${helo_name}
Authentication Method: ${sasl_method}
Sender: ${sender}
Recipient: ${recipient}

EOF
