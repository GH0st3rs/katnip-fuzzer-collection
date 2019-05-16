## BurpSuite fuzzer

Generate mutation data based on BurpSuite requests

## How generate inputs?

* Collect some requests with BurpSuite
* Export collected data to XML: Target -> Site Map -> Select item and Right click -> Save selected items

## Usage fuzz_http
```bash
usage: fuzz_http.py [-h] [-s SKIP] [-i INPUT_FILE] -t HOST -p PORT [-r REPLAY]
                    [-v] [-r1] [-f FILTERED]

optional arguments:
  -h, --help     show this help message and exit
  -s SKIP        Skip count
  -i INPUT_FILE  Set burp input xml file
  -t HOST        Target IP
  -p PORT        Target Port
  -r REPLAY      Path to parsed requests for replay
  -v             Verbose
  -r1            Replay one package
  -f FILTERED    Filter message
```

Example:
```bash
$./fuzz_http.py -i /tmp/burp_target.xml -t 192.168.178.1 -p 80
```

## Usage fuzz_http
```bash
usage: kitty_fuzzer_burp.py [-h] [-s SKIP] [-i INPUT_FILE] -t HOST -p PORT

optional arguments:
  -h, --help     show this help message and exit
  -s SKIP        Skip count
  -i INPUT_FILE  Set burp input xml file
  -t HOST        Target IP
  -p PORT        Target Port

```

Example:
```bash
$./kitty_fuzzer_burp.py -i /tmp/burp_target.xml -t 192.168.178.1 -p 80
```