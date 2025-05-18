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
target-info -q targets/image.qcow2 --json
target-query -q targets/image.qcow2 -f hostname,domain,os,version,ips
target-query -q targets/image.qcow2 -f users | rdump -F hostname,name -C
target-query -q targets/image.qcow2 -f walkfs --limit 50 | rdump -F path,mode,size,mtime -m csv
target-shell -q targets/image.qcow2
```

## Analyzing a qcow2 image from honeypot

Investigate the following aspects of the image:
- ssh configs
- users, logins, passwords
- cron jobs


```shell
target-info -q targets/image.qcow2 --json
target-query -q targets/image.qcow2 -f ssh | rdump -J | jq
target-query -q targets/image.qcow2 -f users | rdump -J | jq
target-query -q targets/image.qcow2 -f cronjobs | rdump -J | jq
```
