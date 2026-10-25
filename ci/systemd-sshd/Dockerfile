# A disposable "server" for the onboarding tests: systemd as PID 1, sshd on
# port 2222 (a non-standard port, so the firewall test means something),
# root and a passwordless-sudo `deploy` user. Authorized keys are added after
# the container starts (see the onboarding-matrix job in .github/workflows/ci.yml).
#
#   docker build --build-arg IMAGE=debian:12 -t keel-test/debian-12 ci/systemd-sshd
#   docker run -d --name srv --privileged --cgroupns=host \
#     -v /sys/fs/cgroup:/sys/fs/cgroup:rw -p 2222:2222 -p 7443:7443 keel-test/debian-12
ARG IMAGE=ubuntu:24.04
FROM ${IMAGE}

ENV container=docker
RUN export DEBIAN_FRONTEND=noninteractive \
 && apt-get update -q \
 && apt-get install -y -q --no-install-recommends \
      systemd systemd-sysv dbus openssh-server sudo iproute2 procps \
      ca-certificates curl netcat-openbsd \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Things a container can't or shouldn't run. The openssh-server package
# enables sshd itself (ssh.socket on Ubuntu 24.04, ssh.service elsewhere).
RUN systemctl mask systemd-firstboot.service getty.target \
      systemd-logind.service console-getty.service \
 && printf 'Port 2222\nPasswordAuthentication no\n' > /etc/ssh/sshd_config.d/10-test.conf \
 && useradd -m -s /bin/bash deploy \
 && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy \
 && chmod 0440 /etc/sudoers.d/deploy \
 && install -d -m 0700 /root/.ssh \
 && install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh \
 && rm -f /etc/machine-id /var/lib/dbus/machine-id \
 && systemd-machine-id-setup

STOPSIGNAL SIGRTMIN+3
EXPOSE 2222 7443
CMD ["/sbin/init"]
