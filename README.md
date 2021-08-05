# Basic SSH Honeypot - with Downloader
Following on from [Part 1](https://github.com/sjbell/basic_ssh_honeypot), this repo extends the basic SSH honeypot with a downloaderer -- for getting malware samples. Part of my blog post: [How to build an SSH honeypot in Python and Docker - Part 2](https://securehoney.net/blog/how-to-build-an-ssh-honeypot-in-python-and-docker-part-2.html). Made with Python, containserised in Docker, managed with Docker Compose.

Uses the [Paramiko](https://github.com/paramiko/paramiko) Python SSH protocol library.

# Installation

## Port forwarding
Setup port forwarding (e.g. from 22 to 2222)

```
iptables -A PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-port 2222
```

## Generate server key
```
ssh-keygen -t rsa -f server.key
```
## Build
```
docker-compose build
```
## Run
```
docker-compose up
```
Logs are recorded in the auto-generated ```ssh_honeypot.log``` file
