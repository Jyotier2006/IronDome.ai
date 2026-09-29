# IronDome.ai dashboard. Build from frontend/:
#   docker build -t irondome-dashboard .
#   docker build --build-arg VITE_SENSOR_URL=http://irondome.local -t irondome-dashboard .   # behind an ingress
# Without VITE_SENSOR_URL the dashboard talks to the sensor on <page host>:3001.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG VITE_SENSOR_URL=""
ENV VITE_SENSOR_URL=${VITE_SENSOR_URL}
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
