# dissect-getting-started

## Dissect CLI usage

Install and use dissect:

```shell
python3 -m venv .venv
source .venv/bin/activate
pip3 install dissect
```

Dissect is a collection of tools. The tools are prefixed with `target-`

```shell
target-query -q targets/ -f hostname,version
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
- services, cronjobs
- users, logins, passwords
- ssh configs
- recent files, executable recent files
- network access


### target-query

```shell
target-info -q targets/image.qcow2 --json
target-query -q targets/image.qcow2 -f hostname,version,os
target-query -q targets/image.qcow2 -f cronjobs
target-query -q targets/image.qcow2 -f services
target-query -q targets/image.qcow2 -f users | rdump -J | jq
target-query -q targets/image.qcow2 -f lastlog
target-query -q targets/image.qcow2 -f activity --limit 10

target-query -q targets/image.qcow2 -f bashhistory
target-query -q targets/image.qcow2 -f commandhistory

target-query -q targets/image.qcow2 -f ssh | rdump -J | jq

target-query -q -f files targets/image.qcow2 --limit 10 | rdump -J | jq
target-query -q -f files targets/image.qcow2 --limit 10 | rdump -l
target-query -q -f files targets/image.qcow2 --limit 10 | rdump -s "'.exe' in str(r.path)"
```

### target-shell

```shell
target-shell
```

### target-fs

```shell
target-fs targets/image.qcow2 walk /tmp
```

## Useful investigation commands

```shell
target-info
target-query -q -f os,hostname,activity,install_date

target-fs image.qcow2 walk /usr/local/bin
target-fs image.qcow2 walk /root
target-fs image.qcow2 walk /tmp

target-fs image.qcow2 cat /tmp/file.txt | shasum56
target-fs image.qcow2 cat /tmp/file.txt | md5sum

target-shell
```
