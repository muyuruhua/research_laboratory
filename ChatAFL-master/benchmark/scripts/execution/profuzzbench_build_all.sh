#!/bin/bash

#export NO_CACHE="--no-cache"
#export MAKE_OPT="-j4"

cd $PFBENCH
cd subjects/FTP/LightFTP
docker build . -t lightftp --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/FTP/BFTPD
docker build . -t bftpd --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/FTP/ProFTPD
docker build . -t proftpd --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/FTP/PureFTPD
docker build . -t pure-ftpd --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/SMTP/Exim
docker build . -t exim --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/RTSP/Live555
docker build . -t live555 --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/SIP/Kamailio
docker build . -t kamailio --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/DAAP/forked-daapd
docker build . -t forked-daapd --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/HTTP/Lighttpd1
docker build . -t lighttpd1 --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/MQTT/Mosquitto
docker build . -t mosquitto --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/MQTT/Mosquitto-v2.0.18
docker build . -t mosquitto-v2.0.18 --build-arg MAKE_OPT $NO_CACHE

cd $PFBENCH
cd subjects/MQTT/Mosquitto-v2.1.2
docker build . -t mosquitto-v2.1.2 --build-arg MAKE_OPT $NO_CACHE

# ── StateAFL 扩展（开闭：仅追加一次调用，不改上方任何既有构建段）──
# 自动发现 subjects/*/*/Dockerfile-stateafl 并构建 <target>-stateafl 镜像；
# 语义与上方一致（无条件重建）。幂等快速路径请直接调用：
#   FORCE=0 PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_stateafl.sh
cd $PFBENCH
PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_stateafl.sh
