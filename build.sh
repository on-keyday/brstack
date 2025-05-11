#!/bin/bash


BUILDER_NAME="brstack"

# check if builder already exists
if docker buildx inspect "$BUILDER_NAME" &>/dev/null
then
    BUILDER_HANDLE=brstack
elif ! BUILDER_HANDLE=$(docker buildx create --driver docker-container --name "$BUILDER_NAME" --use) 
then
    echo "Failed to create builder"
    exit 1
fi


if ! docker buildx bake\
        -f ./docker-compose.yml\
        --builder "$BUILDER_HANDLE"\
        --load 
then
    echo "Failed to build images"
    exit 1
fi

docker compose up -d
