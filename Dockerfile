FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssh-server sudo curl unzip && \
    mkdir /var/run/sshd

RUN curl -L https://github.com/kelseyhightower/confd/releases/download/v0.16.0/confd-0.16.0-linux-amd64 -o /usr/local/bin/confd && \
    chmod +x /usr/local/bin/confd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    echo "export VISIBLE=now" >> /etc/profile

RUN useradd -m -s /bin/bash devops && \
    useradd -m -s /bin/bash backend && \
    useradd -m -s /bin/bash frontend && \
    mkdir -p /home/devops/.ssh /home/backend/.ssh /home/frontend/.ssh && \
    chmod 700 /home/*/.ssh && \
    touch /home/devops/.ssh/authorized_keys /home/backend/.ssh/authorized_keys /home/frontend/.ssh/authorized_keys && \
    chmod 600 /home/*/.ssh/authorized_keys && \
    chown -R devops:devops /home/devops/.ssh && \
    chown -R backend:backend /home/backend/.ssh && \
    chown -R frontend:frontend /home/frontend/.ssh

COPY confd/conf.d /etc/confd/conf.d
COPY confd/templates /etc/confd/templates

COPY run_confd.sh /usr/local/bin/run_confd.sh
RUN chmod +x /usr/local/bin/run_confd.sh

EXPOSE 22
WORKDIR /usr/local/bin

# ✅ Start confd at container runtime
CMD ["/usr/local/bin/run_confd.sh"]

