# syntax=docker/dockerfile:experimental

FROM node:18 AS BUILD

WORKDIR /ui

COPY package.json .
RUN npm install

COPY . .
RUN npm run build

FROM nginx AS RUN

COPY --from=BUILD /ui/dist /usr/share/nginx/html
