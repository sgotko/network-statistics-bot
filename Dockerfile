FROM node:16-slim

ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y fontconfig

WORKDIR /app

COPY ./package*.json ./

RUN while ! npm install ; do npm install ; done ; echo -e '\e[1;32m Packages successfullly installed! \e[0m'

COPY ./ .

CMD ["node", "index.js"]