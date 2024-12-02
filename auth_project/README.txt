Authentication services Setup Guide
-------------------------

This document describes how to run the authentication services in Docker. Please follow the instructions carefully to get the services running successfully.


Requirements
------------
Docker Desktop should be installed and started on your computer.


Instructions
------------
1. Open Docker Desktop
Make sure that Docker Desktop is running before proceeding.

2. Open a terminal in Docker

3. Change to the "auth_project" directory
cd path/to/auth_project

4. Start the microservices
Execute the following command to create and start the microservices:

docker-compose up --build

This command creates and starts the Docker images, containers and volumes for the two authentication services.


After executing the command
---------------------------
After executing the docker-compose up --build command, the following Docker images, containers and volumes should be created and started:

Images:
username_password_service
token_auth_service

Containers:
token_auth_service
username_password_service

Volumes:
auth_project_token_auth_volume
auth_project_username_password_volume


These services are now ready to perform authentications. The individual functions can be found in the documentation.


