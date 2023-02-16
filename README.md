Abusix AUTH Policy Daemon
-------------------------------------

This is a Postfix Policy daemon designed to use Abusix Mail Intelligence to catch, report and prevent compromised accounts after authenticating successfully to Postfix.

## Requirements
NodeJS (>=14 should work)
Redis Server (this can be installed on the same host or remote)

## Installation from source
`````
cd /opt
git clone https://gitlab.com/abusix-public/abusix_auth_ppd.git
cd abusix_auth_ppd
npm install
# Install the systemd service files
sudo cp abusix_auth_ppd.service /etc/systemd/system
sudo systemctl daemon-reload
`````

## Configuration
The `abusix_auth_ppd.ini` file is used to configure the daemon.

At minimum you need to set `apikey` to your Abusix Mail Intelligence API key.  If you don't set an `action`, then the default is just to write to the log, so you'll probably want to set this to either `reject` or `hold`.

If you are using a non-local Redis server, then you will need to uncomment the `[redis]` section and set-up the connection parameters accordingly.

Run `./abusix_auth_ppd.js` to ensure that the daemon starts and there are no errors, press Ctrl+C to terminate it, then run:

`sudo systemctl start abusix_auth_ppd`

To start the daemon via systemd.

Run `sudo systemctl status abusix_auth_ppd` to ensure that it is running correctly.

### Postfix Configuration

Edit the Postfix `main.cf` file and add the following to the start of `smtpd_sender_restrictions =` (or add this section if it does not already exist):
`````
check_policy_service { inet:127.0.0.1:9998 }
`````

If you are running the policy daemon on a separate server to Postfix, then will need to modify the IP address accordingly.

Postfix needs to be restarted once `main.cf` has been edited.

## Operation

NOTE: If the daemon fails or is not started, then Postfix will defer all messages until it can reconnect to the daemon.

By default the systemd service file runs the daemon as user `nobody`.  Once started, it will fork a worker process per-CPU for maximum performance.

The daemon will handle messages based on the action you have configured will either reject any attempted messages, accept the messages but put the messages in the Postfix 'hold' queue, or just allow the messages and write the detections to the log.

When a compromised account is detected, it will be cached in Redis so that any future connections from the compromised account are handled, regardless as to what IP they are connecting from, or, what addresses they are trying to send to.  Additionally, if configured, the `command` option can be set to a shell-script which will be called for each *new* detection, this script will receive all of the connection/message attributes sent by Postfix as enviornment variables and can be used to generate alerts, create tickets, call APIs or webhooks etc.  There is an example script provided, see `report_compromised_account.sh`.

You can run the following command to list the detected compromised accounts (you will need to modify the redis-cli command if you are running Redis on a differet host or with authentication etc.):

`echo "SMEMBERS compromised_accts" | redis-cli --raw`

And to delete an entry from the cache once the compromised account has been secured (replace add@ress.com with the compromised account address):

`echo "SREM compromised_accts add@ress.com" | redis-cli --raw`

Redis should return "1" to say that it removed one item from the set and messages will be allowed through from this account again.

## License
This software is licensed under the GPLv3, please see the `COPYING` file in the same directory.   Please send any modifications or improvements as a Pull Request.
