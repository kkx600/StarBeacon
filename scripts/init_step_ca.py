#!/usr/bin/env python3
"""在专属目录和短期 Docker 容器内初始化探针 CA；不安装宿主软件、不覆盖现有身份。"""
import argparse
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = "cr.smallstep.com/smallstep/step-ca:0.30.2@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270"

def initialize(directory, dns, image=IMAGE, uid=None, gid=None, platform_uid=None, platform_gid=None):
    base = pathlib.Path(directory)
    if not base.is_absolute() or base.exists() or base.is_symlink() or not base.parent.is_dir():
        raise ValueError("CA 初始化要求父目录已存在的全新绝对目录")
    names = dns.split(",")
    if not names or len(names) > 16 or len(set(names)) != len(names):
        raise ValueError("CA DNS/IP 名称须为 1–16 个不重复的值")
    for name in names:
        try:
            ipaddress.ip_address(name)
        except ValueError:
            if len(name)>253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?",name) or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",part) for part in name.split(".")):
                raise ValueError("CA 名称必须为明确的 DNS 名称或 IP 地址")
    uid = (os.getuid() or 1000) if uid is None else uid
    gid = (os.getgid() or 1000) if gid is None else gid
    platform_uid = uid if platform_uid is None else platform_uid
    platform_gid = gid if platform_gid is None else platform_gid
    if any(type(value) is not int or value < 1 for value in (uid,gid,platform_uid,platform_gid)):
        raise ValueError("CA 和平台密钥文件要求非 root 属主")
    base.mkdir(mode=0o700)
    live, offline, platform = (base / part for part in ("ca", "offline", "platform"))
    for path in (live,offline,platform):
        path.mkdir(mode=0o700)
    os.chown(live,uid,gid)
    for name in ("secrets","templates","db"):
        path=live/name;path.mkdir(mode=0o700);os.chown(path,uid,gid)
    password=live/"secrets/password"
    password.write_text(secrets.token_urlsafe(48)+"\n");password.chmod(0o600);os.chown(password,uid,gid)
    template=live/"templates/probe.tpl"
    shutil.copyfile(ROOT/"deploy/step-ca/probe.tpl",template);template.chmod(0o600);os.chown(template,uid,gid)
    def step(*arguments):
        # 密码只经私有只读文件传入，参数和日志不携带密码或私钥内容。
        subprocess.run(["docker","run","--rm","--network","none","--user",f"{uid}:{gid}","--cap-drop","ALL","--security-opt","no-new-privileges:true","--pids-limit","128","--memory","512m","--cpus","1","--volume",str(live)+":/home/step","--entrypoint","step",image,*arguments],check=True,timeout=90,stdout=subprocess.DEVNULL)
    step("ca","init","--deployment-type","standalone","--name","StarBeacon Probe CA","--dns",dns,"--address",":9000","--provisioner","bootstrap","--password-file","/home/step/secrets/password","--provisioner-password-file","/home/step/secrets/password")
    step("crypto","jwk","create","/home/step/provisioner.pub.json","/home/step/platform-signing.jwk","--kty","OKP","--crv","Ed25519","--no-password","--insecure")
    config_path=live/"config/ca.json"
    config=json.loads(config_path.read_text())
    config["authority"]={"provisioners":[{"type":"JWK","name":"starbeacon-probes","key":json.loads((live/"provisioner.pub.json").read_text()),"claims":{"minTLSCertDuration":"5m","maxTLSCertDuration":"168h","defaultTLSCertDuration":"24h","disableRenewal":True},"options":{"x509":{"templateFile":"/home/step/templates/probe.tpl"}}}]}
    config["tls"]={"minVersion":1.3,"maxVersion":1.3}
    config_path.write_text(json.dumps(config,indent=2)+"\n");config_path.chmod(0o600);os.chown(config_path,uid,gid)
    # 离线根私钥不在运行 CA 的挂载范围，平台仅取得受限 provisioner 授权密钥。
    shutil.move(str(live/"secrets/root_ca_key"),offline/"root_ca_key")
    shutil.move(str(live/"platform-signing.jwk"),platform/"provisioner.jwk")
    (platform/"provisioner.jwk").chmod(0o600);os.chown(platform/"provisioner.jwk",platform_uid,platform_gid)
    shutil.copyfile(live/"certs/root_ca.crt",platform/"root_ca.crt")
    (platform/"root_ca.crt").chmod(0o644)
    (live/"provisioner.pub.json").unlink()
    manifest={"schema":"probe.ca.v1","image":image,"ca_directory":str(live),"offline_directory":str(offline),"platform_directory":str(platform),"ca_uid":uid,"ca_gid":gid,"platform_uid":platform_uid,"platform_gid":platform_gid,"dns_names":names,"provisioner":"starbeacon-probes","certificate_seconds":86400}
    (base/"deployment.json").write_text(json.dumps(manifest,indent=2)+"\n");(base/"deployment.json").chmod(0o600)
    return manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory",required=True)
    parser.add_argument("--dns",default="step-ca,localhost,127.0.0.1")
    parser.add_argument("--image",default=IMAGE)
    for name in ("uid","gid","platform-uid","platform-gid"):
        parser.add_argument("--"+name,type=int)
    args=parser.parse_args()
    result=initialize(args.directory,args.dns,args.image,args.uid,args.gid,args.platform_uid,args.platform_gid)
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()
