# dissect-getting-started

## Dissect CLI usage

Install and use dissect:

```shell
python3 -m venv .venv
source .venv/bin/activate
pip3 install dissect
```

```shell
target-query --list | less
target-query --list --json  | jq .loaders
```

Useful commands:

```shell
target-info -q image.qcow2 --json
target-query -q image.qcow2 -f hostname,domain,os,version,ips
target-query -q image.qcow2 -f users | rdump -F hostname,name -C
target-shell -q image.qcow2
```
