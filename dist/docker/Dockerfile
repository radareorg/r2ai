FROM ubuntu:24.04
WORKDIR /root/
RUN apt update && apt install -y build-essential
RUN apt install -y git curl pkg-config
RUN apt install -y python3.12
RUN apt install -y python3.12-venv
RUN apt install -y zlib1g zlib1g-dev
RUN apt install -y unzip neovim
RUN apt install -y ninja-build meson 

# install radare
RUN git clone https://github.com/radareorg/radare2.git
WORKDIR radare2/
RUN sys/install.sh

# install plugins
WORKDIR /root/
RUN r2pm -U
#RUN r2pm -ci r2ghidra r2ghidra-sleigh   # slow and optional
RUN r2pm -ci r2ai-server r2ai-plugin   # r2ai-py is deprecated
RUN r2pm -ci decai r2dec

# r2 tunning
RUN echo 'e io.unalloc=true' >> /root/.radare2rc
RUN echo 'e cfg.fortunes=false' >> /root/.radare2rc
RUN echo 'e emu.str=true' >> /root/.radare2rc
RUN echo 'e bin.relocs.apply=true' >> /root/.radare2rc
RUN echo 'e dir.tmp=/tmp/' >> /root/.radare2rc
RUN echo 'e scr.prompt.flag=1' >> /root/.radare2rc
RUN echo 'e cfg.editor=nvim' >> /root/.radare2rc
RUN echo 'decai -e deterministic=true' >> /root/.radare2rc
RUN echo 'decai -e lang=Python' >> /root/.radare2rc
RUN echo 'decai -e cmds=pdd,pdg' >> /root/.radare2rc
RUN echo 'decai -e prompt=..' >> /root/.radare2rc
RUN echo 'decai -e api=ollama' >> /root/.radare2rc
RUN echo 'decai -e model=qwen2.5-coder:latest' >> /root/.radare2rc


# Uncomment to have ollama inside the docker (will not use gpu)
#RUN curl -fsSL https://ollama.com/install.sh | sh
#RUN \
#  echo '#!/bin/bash'; \
#  echo 'ollama serve &'; \
#  echo 'sleep 5'; \
#  echo 'ollama pull qwen2.5-coder:latest'; >> /root/ollama.run
#
#RUN chmod +x /root/ollama.run
#RUN /root/ollama.run


