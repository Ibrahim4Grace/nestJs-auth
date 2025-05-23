# Use the official Node.js image as the base image
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the rest of the application code to the working directory
COPY . .

# Install the dependencies
RUN npm install

RUN npm run build

EXPOSE 8000

# Command to run the application
CMD ["npm", "run", "start:prod"]