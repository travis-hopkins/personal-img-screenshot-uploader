#!/bin/bash

# Define the port and app directory
PORT=5003
APP_DIR="/opt/screenshot-app/app"
GUNICORN_BIN="/home/ubuntu/miniforge3/envs/screenshot-app/bin/gunicorn"
APP_MODULE="main:app"

# Function to check if the process is running
is_running() {
    lsof -i :$PORT | grep LISTEN > /dev/null
    return $?
}

# Load environment variables from the config.env file
if [ -f "$APP_DIR/config.env" ]; then
    export $(grep -v '^#' "$APP_DIR/config.env" | xargs)
else
    echo "config.env file not found in $APP_DIR"
    exit 1
fi

# Navigate to the application directory
cd $APP_DIR

# Check if the application is already running
if is_running; then
    echo "The application is already running on port $PORT."
else
    echo "Starting the application..."
    # Run Gunicorn with specified parameters
    $GUNICORN_BIN -w 4 -b 127.0.0.1:$PORT $APP_MODULE &
    echo "Application started."
fi
