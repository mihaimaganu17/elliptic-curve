# All the commands below are used for the testnet chain
## Create a new wallet
```
./src/bitcoint-cli -testnet createwallet "testwallet"
```
## Load the wallet
```
./src/bitcoint-cli -testnet loadwallet "testwallet"
```
## Encrypt the wallet
```
./src/bitcoint-cli -testnet encyptwallet
```
## Backup the wallet
```
./src/bitcoint-cli -testnet backupwallet ~/walletbackup.dat
```
## Get a new address
```
./src/bitcoint-cli -testnet -named getnewaddress address_type=legacy
```


# Bitcoin system commands
## Restart the Bitcoin chain
```
sudo systemctl restart bitcoind
```
