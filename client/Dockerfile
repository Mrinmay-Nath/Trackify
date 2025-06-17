# Frontend Dockerfile (for static HTML/JS/CSS)
FROM nginx:alpine

COPY client /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
