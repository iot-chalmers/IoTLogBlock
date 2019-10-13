rm -rf hfc-key-store
docker rm -f $(docker ps -aq)
docker network prune
docker rmi `docker images | grep fabcar | awk '{print $1}'`
./startFabric.sh
node enrollAdmin.js
node registerUser.js
