```bash
cargo run --package zero --bin rpc fetch --rpc-url $rpc_url --start-block $number --end-block $number > ./b$number_$network.json
header_name=b$number_$network_header.json
echo "[" > $file_name
cast rpc eth_getBlockByNumber 0x$number false --rpc-url $rpc_url >> $file_name
echo "]" >> $file_name
```
